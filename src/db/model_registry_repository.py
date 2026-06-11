from __future__ import annotations

from src.auth.db import get_connection


def upsert_model_record(model_info):
    conn = get_connection()

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO model_registry (
                    model_name,
                    model_path,
                    metrics_path,
                    accuracy,
                    precision_score,
                    recall_score,
                    f1_score,
                    is_used
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'no')
                ON DUPLICATE KEY UPDATE
                    model_path = VALUES(model_path),
                    metrics_path = VALUES(metrics_path),
                    accuracy = VALUES(accuracy),
                    precision_score = VALUES(precision_score),
                    recall_score = VALUES(recall_score),
                    f1_score = VALUES(f1_score)
                """,
                (
                    model_info.get("model_name"),
                    model_info.get("model_path"),
                    model_info.get("metrics_path"),
                    model_info.get("accuracy"),
                    model_info.get("precision_score"),
                    model_info.get("recall_score"),
                    model_info.get("f1_score"),
                ),
            )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def sync_model_registry(models):
    for model_info in models:
        upsert_model_record(model_info)

    return len(models)


def get_active_model():
    conn = get_connection()

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM model_registry
                WHERE is_used = 'yes'
                LIMIT 1
                """
            )

            return cur.fetchone()

    finally:
        conn.close()


def get_model_by_name(model_name):
    conn = get_connection()

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM model_registry
                WHERE model_name = %s
                LIMIT 1
                """,
                (model_name,),
            )

            return cur.fetchone()

    finally:
        conn.close()


def set_active_model(model_name, deployed_by):
    conn = get_connection()

    try:
        with conn.cursor() as cur:
            cur.execute("START TRANSACTION")

            cur.execute(
                """
                UPDATE model_registry
                SET is_used = 'no'
                """
            )

            cur.execute(
                """
                UPDATE model_registry
                SET
                    is_used = 'yes',
                    deployed_by = %s,
                    deployed_at = NOW()
                WHERE model_name = %s
                """,
                (
                    deployed_by,
                    model_name,
                ),
            )

            if cur.rowcount == 0:
                raise ValueError(
                    f"Model not found in registry: {model_name}"
                )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()
