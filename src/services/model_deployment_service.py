from __future__ import annotations

import filecmp
import json
import logging
import os
import shlex
import shutil
import subprocess
import tempfile

from html import escape
from pathlib import Path

from src.db.model_registry_repository import (
    get_active_model,
    set_active_model,
    sync_model_registry,
)


logger = logging.getLogger(__name__)

MODEL_REGISTRY_DIR = Path(
    os.getenv("MODEL_REGISTRY_DIR", "/app/models")
)
ACTIVE_MODEL_PATH = Path(
    os.getenv("ACTIVE_MODEL_PATH", "/app/model.pkl")
)
MODEL_DEPLOY_RESTART_COMMAND = os.getenv(
    "MODEL_DEPLOY_RESTART_COMMAND",
    "docker compose -f /home/capstone/ojs_git/docker-ojs/docker-compose.yml restart inference",
)

METRIC_KEYS = {
    "accuracy": (
        "accuracy",
        "test_accuracy",
    ),
    "precision_score": (
        "precision",
        "precision_score",
        "test_precision",
    ),
    "recall_score": (
        "recall",
        "recall_score",
        "test_recall",
    ),
    "f1_score": (
        "f1",
        "f1_score",
        "test_f1",
    ),
}


class ModelDeployError(Exception):
    pass


class ModelCopyError(ModelDeployError):
    pass


class ModelRestartError(ModelDeployError):
    pass


def _find_metric(data, keys):
    if isinstance(data, dict):
        for key in keys:
            if key in data:
                return data[key]

        for value in data.values():
            found = _find_metric(
                value,
                keys,
            )
            if found is not None:
                return found

    elif isinstance(data, list):
        for value in data:
            found = _find_metric(
                value,
                keys,
            )
            if found is not None:
                return found

    return None


def _numeric_metric(value):
    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def format_metric(value):
    numeric_value = _numeric_metric(
        value
    )

    if numeric_value is None:
        return "Missing"

    if numeric_value <= 1:
        numeric_value *= 100

    return f"{numeric_value:.2f}%"


def _metrics_path_for_model(model_path: Path):
    companion_path = model_path.with_name(
        f"{model_path.stem}_metrics.json"
    )

    if companion_path.exists():
        return companion_path

    if model_path.name == "modsec_xgb.pkl":
        fallback_path = model_path.with_name(
            "modsec_metrics.json"
        )

        if fallback_path.exists():
            return fallback_path

    return None


def read_metrics_for_model(model_name):
    model_path = MODEL_REGISTRY_DIR / f"{model_name}.pkl"
    metrics_path = _metrics_path_for_model(
        model_path
    )

    metrics = {
        "metrics_path": str(metrics_path) if metrics_path else None,
        "accuracy": None,
        "precision_score": None,
        "recall_score": None,
        "f1_score": None,
    }

    if not metrics_path:
        return metrics

    try:
        with metrics_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

    except Exception:
        logger.exception(
            "Failed reading metrics for model=%s path=%s",
            model_name,
            metrics_path,
        )
        return metrics

    for metric_name, keys in METRIC_KEYS.items():
        metrics[metric_name] = _numeric_metric(
            _find_metric(data, keys)
        )

    return metrics


def scan_models():
    if not MODEL_REGISTRY_DIR.exists():
        logger.warning(
            "Model registry directory does not exist: %s",
            MODEL_REGISTRY_DIR,
        )
        return []

    models = []

    for model_path in sorted(MODEL_REGISTRY_DIR.glob("*.pkl")):
        if not model_path.is_file():
            continue

        model_name = model_path.stem
        metrics = read_metrics_for_model(
            model_name
        )

        models.append({
            "model_name": model_name,
            "model_path": str(model_path),
            "metrics_path": metrics["metrics_path"],
            "accuracy": metrics["accuracy"],
            "precision_score": metrics["precision_score"],
            "recall_score": metrics["recall_score"],
            "f1_score": metrics["f1_score"],
        })

    logger.info(
        "Model registry scan count=%s dir=%s",
        len(models),
        MODEL_REGISTRY_DIR,
    )

    return models


def _active_model_from_file(models):
    if not ACTIVE_MODEL_PATH.exists():
        return None

    for model_info in models:
        try:
            if filecmp.cmp(
                ACTIVE_MODEL_PATH,
                model_info["model_path"],
                shallow=False,
            ):
                return model_info

        except OSError:
            continue

    return None


def _resolve_active_model(models):
    active_record = get_active_model()

    if active_record:
        for model_info in models:
            if model_info["model_name"] == active_record["model_name"]:
                return model_info

        return active_record

    return _active_model_from_file(
        models
    )


def get_model_by_name_from_scan(model_name):
    for model_info in scan_models():
        if model_info["model_name"] == model_name:
            return model_info

    return None


def get_paginated_models(page, per_page=3):
    models = scan_models()
    sync_model_registry(
        models
    )

    total_models = len(models)
    total_pages = max(
        1,
        (total_models + per_page - 1) // per_page,
    )
    page = max(
        0,
        min(page, total_pages - 1),
    )
    start = page * per_page
    end = start + per_page

    return {
        "models": models,
        "page_models": models[start:end],
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "active_model": _resolve_active_model(models),
    }


def get_current_model_info():
    models = scan_models()
    sync_model_registry(
        models
    )

    return _resolve_active_model(
        models
    )


def _metric_lines(model_info, include_all=True):
    if include_all:
        return "\n".join([
            f"{'Accuracy':<9}: {format_metric(model_info.get('accuracy'))}",
            f"{'Precision':<9}: {format_metric(model_info.get('precision_score'))}",
            f"{'Recall':<9}: {format_metric(model_info.get('recall_score'))}",
            f"{'F1 Score':<9}: {format_metric(model_info.get('f1_score'))}",
        ])

    return "\n".join([
        f"Accuracy: {format_metric(model_info.get('accuracy'))}",
        f"F1 Score: {format_metric(model_info.get('f1_score'))}",
    ])


def build_model_registry_message(page):
    view = get_paginated_models(
        page
    )
    active_model = view["active_model"]

    if active_model:
        active_text = "\n".join([
            f"<b>{escape(active_model['model_name'])}</b>",
            "",
            _metric_lines(active_model),
        ])
    else:
        active_text = "No active model recorded"

    available_lines = []

    for index, model_info in enumerate(
        view["page_models"],
        1,
    ):
        available_lines.append(
            "\n".join([
                (
                    f"<b>[{index}] "
                    f"{escape(model_info['model_name'])}</b>"
                ),
                _metric_lines(
                    model_info,
                    include_all=False,
                ),
            ])
        )

    available_text = (
        "\n\n".join(available_lines)
        if available_lines
        else "No trained models found."
    )

    message = (
        "🤖 Model Registry\n\n"
        "━━━━━━━━━━━━━━\n\n"
        "✅ Active Model\n"
        f"{active_text}\n\n"
        "━━━━━━━━━━━━━━\n\n"
        "Available Models\n\n"
        f"{available_text}\n\n"
        f"📄 Page {view['page'] + 1} / {view['total_pages']}"
    )

    view["message"] = message
    return view


def build_confirm_message(model_name):
    model_info = get_model_by_name_from_scan(
        model_name
    )

    if not model_info:
        raise ValueError(
            "Selected model is no longer available."
        )

    return (
        "⚠️ Confirm Model Deployment\n\n"
        "You selected:\n"
        f"<b>{escape(model_info['model_name'])}</b>\n\n"
        f"{_metric_lines(model_info)}\n\n"
        "Are you sure you want to deploy this model?"
    )


def _copy_model(source_path: Path):
    destination_path = ACTIVE_MODEL_PATH
    destination_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    logger.info(
        "Copying model source=%s destination=%s",
        source_path,
        destination_path,
    )

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            dir=str(destination_path.parent),
            prefix=f".{destination_path.name}.",
            suffix=".tmp",
        ) as temp_file:
            temp_path = Path(
                temp_file.name
            )

        shutil.copy2(
            source_path,
            temp_path,
        )
        os.replace(
            temp_path,
            destination_path,
        )

    except Exception as exc:
        if temp_path and temp_path.exists():
            temp_path.unlink()

        logger.exception(
            "Failed copying model source=%s destination=%s",
            source_path,
            destination_path,
        )
        raise ModelCopyError(
            "could not copy selected model"
        ) from exc


def _restart_inference():
    command = shlex.split(
        MODEL_DEPLOY_RESTART_COMMAND
    )

    if not command:
        raise ModelRestartError(
            "restart command is empty"
        )

    logger.info(
        "Restarting inference command=%s",
        command,
    )

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    logger.info(
        "Restart command returncode=%s stdout=%s stderr=%s",
        result.returncode,
        result.stdout,
        result.stderr,
    )

    if result.returncode != 0:
        raise ModelRestartError(
            result.stderr or result.stdout or "restart failed"
        )


def deploy_model(model_name, deployed_by):
    model_info = get_model_by_name_from_scan(
        model_name
    )

    if not model_info:
        raise ModelCopyError(
            "selected model is no longer available"
        )

    source_path = Path(
        model_info["model_path"]
    )

    if source_path.parent != MODEL_REGISTRY_DIR:
        raise ModelCopyError(
            "invalid model path"
        )

    logger.info(
        "Selected model=%s deployed_by=%s",
        model_name,
        deployed_by,
    )

    _copy_model(
        source_path
    )
    _restart_inference()

    set_active_model(
        model_name,
        deployed_by,
    )

    logger.info(
        "DB active model updated model=%s",
        model_name,
    )

    return model_info
