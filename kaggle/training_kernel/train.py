"""Entry point training di Kaggle (End-to-End: Raw Log → CSV → Model)."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def list_dir(path: Path, label: str):
    print(f"[KAGGLE DEBUG] {label}: {path}")
    if path.exists():
        for item in sorted(path.rglob("*")):
            rel = item.relative_to(path)
            print(f"  {rel} {'[DIR]' if item.is_dir() else ''}")
    else:
        print(f"  (path tidak ada)")


def main():
    import subprocess, sys
    sys.stdout.reconfigure(line_buffering=True)

    work = Path("/kaggle/working")
    inp  = Path("/kaggle/input")

    list_dir(inp, "Isi /kaggle/input")

    # ── Install dependencies ─────────────────────────────────────
    print("[KAGGLE] Installing mlflow...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "--quiet", "--no-warn-script-location", "mlflow"
        ])
        print("[KAGGLE] mlflow installed.")
    except subprocess.CalledProcessError as e:
        print(f"[KAGGLE ERROR] Gagal install mlflow: {e}")
        sys.exit(1)

    print("[KAGGLE] Upgrading scikit-learn to 1.8.0...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "--quiet", "--no-warn-script-location", "--upgrade", "scikit-learn==1.8.0"
        ])
        print("[KAGGLE] scikit-learn upgraded.")
    except subprocess.CalledProcessError as e:
        print(f"[KAGGLE ERROR] Gagal upgrade scikit-learn: {e}")
        sys.exit(1)

    # ── Copy code dari dataset ───────────────────────────────────
    code_src = inp / "modsec-code"
    if not code_src.exists():
        print(f"ERROR: Code dataset tidak ditemukan di {code_src}")
        sys.exit(1)

    for folder in ["src", "scripts", "config"]:
        src = code_src / folder
        dst = work / folder
        if src.exists():
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
            print(f"[KAGGLE] Copied {folder}/ dari dataset ke working")
        else:
            print(f"[KAGGLE WARN] {folder}/ tidak ada di code dataset")

    list_dir(work / "scripts", "Isi /kaggle/working/scripts")
    sys.path.insert(0, str(work))

    # ── STEP 1: Prepare dataset dari raw log ─────────────────────
    print("[KAGGLE] ============================================================")
    print("[KAGGLE] STEP 1: Prepare dataset dari raw JSON log")
    print("[KAGGLE] ============================================================")

    raw_src = inp / "modsec-raw-logs"
    raw_logs = list(raw_src.glob("*.log"))
    if not raw_logs:
        print("ERROR: Raw log (*.log) tidak ditemukan di /kaggle/input/modsec-raw-logs/")
        list_dir(raw_src, "DEBUG isi raw folder")
        sys.exit(1)

    raw_log = raw_logs[0]
    dataset_csv = work / "modsec_raw_json_v2.csv"

    prepare_script = work / "scripts" / "prepare_dataset_from_raw_json_v2.py"
    if not prepare_script.exists():
        print(f"ERROR: {prepare_script} tidak ditemukan")
        sys.exit(1)

    print(f"[KAGGLE] Using raw log: {raw_log}")
    res = subprocess.run([
        sys.executable, str(prepare_script),
        "--input", str(raw_log),
        "--output", str(dataset_csv),
    ])
    if res.returncode != 0:
        print("[KAGGLE ERROR] Prepare dataset gagal")
        sys.exit(res.returncode)

    if not dataset_csv.exists():
        print("ERROR: Dataset CSV tidak terbentuk setelah prepare")
        sys.exit(1)
    print(f"[KAGGLE] Dataset ready: {dataset_csv}")

    # ── STEP 2: Training ─────────────────────────────────────────
    print("[KAGGLE] ============================================================")
    print("[KAGGLE] STEP 2: Run training")
    print("[KAGGLE] ============================================================")

    train_script = work / "scripts" / "run_modsec_training.py"
    if not train_script.exists():
        print(f"ERROR: {train_script} tidak ditemukan")
        sys.exit(1)

    cmd = [
        sys.executable, str(train_script),
        "--dataset",        str(dataset_csv),
        "--model-output",   str(work / "modsec_xgb.pkl"),
        "--metrics-output", str(work / "modsec_metrics.json"),
        "--use-optuna",
        "--optuna-trials",  os.getenv("KAGGLE_OPTUNA_TRIALS", "25"),
    ]
    print(f"[KAGGLE] Running: {' '.join(cmd)}")
    res = subprocess.run(cmd)
    sys.exit(res.returncode)


if __name__ == "__main__":
    main()