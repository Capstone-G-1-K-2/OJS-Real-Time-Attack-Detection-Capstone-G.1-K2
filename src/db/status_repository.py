from src.auth.db import get_connection


TRAINING_PAUSE_KEY = "training_pause_notifications"


def ensure_system_state_table(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS system_state (
            state_key VARCHAR(128) NOT NULL,
            state_value VARCHAR(255) NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (state_key)
        ) ENGINE=InnoDB
        """
    )


def get_status_metrics():
    conn = get_connection()

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) AS overall_logs
                FROM modsec_events
                """
            )
            modsec_counts = cur.fetchone() or {}

            cur.execute(
                """
                SELECT
                    COUNT(*) AS attack_logs,
                    COALESCE(
                        SUM(CASE WHEN detected_at >= CURDATE() THEN 1 ELSE 0 END),
                        0
                    ) AS attacks_today,
                    COALESCE(
                        SUM(CASE WHEN detected_at >= NOW() - INTERVAL 7 DAY THEN 1 ELSE 0 END),
                        0
                    ) AS attacks_last_week,
                    COALESCE(
                        SUM(CASE WHEN detected_at >= NOW() - INTERVAL 1 MONTH THEN 1 ELSE 0 END),
                        0
                    ) AS attacks_last_month
                FROM attack_events
                """
            )
            attack_counts = cur.fetchone() or {}

            cur.execute(
                """
                SELECT attack_type, COUNT(*) AS attack_type_count
                FROM attack_events
                WHERE attack_type IS NOT NULL
                    AND attack_type <> ''
                GROUP BY attack_type
                ORDER BY attack_type_count DESC, attack_type ASC
                LIMIT 1
                """
            )
            most_attack = cur.fetchone() or {}

    finally:
        conn.close()

    return {
        "overall_logs": int(modsec_counts.get("overall_logs") or 0),
        "attack_logs": int(attack_counts.get("attack_logs") or 0),
        "most_attack_type": most_attack.get("attack_type") or "N/A",
        "attacks_today": int(attack_counts.get("attacks_today") or 0),
        "attacks_last_week": int(attack_counts.get("attacks_last_week") or 0),
        "attacks_last_month": int(attack_counts.get("attacks_last_month") or 0),
    }


def set_attack_notifications_paused(paused: bool) -> None:
    conn = get_connection()

    try:
        with conn.cursor() as cur:
            ensure_system_state_table(cur)
            cur.execute(
                """
                INSERT INTO system_state (state_key, state_value)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE
                    state_value = VALUES(state_value)
                """,
                (
                    TRAINING_PAUSE_KEY,
                    "1" if paused else "0",
                ),
            )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def are_attack_notifications_paused() -> bool:
    conn = get_connection()

    try:
        with conn.cursor() as cur:
            ensure_system_state_table(cur)
            cur.execute(
                """
                SELECT state_value
                FROM system_state
                WHERE state_key = %s
                """,
                (TRAINING_PAUSE_KEY,),
            )
            result = cur.fetchone()

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    if not result:
        return False

    return result.get("state_value") == "1"
