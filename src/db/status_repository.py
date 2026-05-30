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


def fetch_attack_history_summary(cur):
    cur.execute(
        """
        SELECT
            COUNT(*) AS total_attacks,
            COALESCE(
                SUM(CASE WHEN detected_at >= CURDATE() THEN 1 ELSE 0 END),
                0
            ) AS attacks_today,
            COALESCE(
                SUM(CASE WHEN detected_at >= NOW() - INTERVAL 7 DAY THEN 1 ELSE 0 END),
                0
            ) AS attacks_last_7_days,
            COALESCE(
                SUM(CASE WHEN detected_at >= NOW() - INTERVAL 30 DAY THEN 1 ELSE 0 END),
                0
            ) AS attacks_last_30_days
        FROM attack_events
        """
    )
    counts = cur.fetchone() or {}

    cur.execute(
        """
        SELECT attack_type, COUNT(*) AS total
        FROM attack_events
        WHERE attack_type IS NOT NULL
            AND attack_type <> ''
        GROUP BY attack_type
        ORDER BY total DESC, attack_type ASC
        LIMIT 1
        """
    )
    most_attack_type = cur.fetchone() or {}

    cur.execute(
        """
        SELECT attacker_ip, COUNT(*) AS total
        FROM attack_events
        WHERE attacker_ip IS NOT NULL
            AND attacker_ip <> ''
        GROUP BY attacker_ip
        ORDER BY total DESC, attacker_ip ASC
        LIMIT 1
        """
    )
    most_attacker_ip = cur.fetchone() or {}

    cur.execute(
        """
        SELECT detected_at
        FROM attack_events
        ORDER BY detected_at DESC
        LIMIT 1
        """
    )
    latest_attack = cur.fetchone() or {}

    cur.execute(
        """
        SELECT
            detected_at,
            attack_type,
            probability,
            attack_url,
            attacker_ip
        FROM attack_events
        ORDER BY detected_at DESC
        LIMIT 5
        """
    )
    recent_attacks = cur.fetchall()

    return {
        "total_attacks": int(counts.get("total_attacks") or 0),
        "attacks_today": int(counts.get("attacks_today") or 0),
        "attacks_last_7_days": int(counts.get("attacks_last_7_days") or 0),
        "attacks_last_30_days": int(counts.get("attacks_last_30_days") or 0),
        "most_attack_type": most_attack_type.get("attack_type") or "N/A",
        "most_attacker_ip": most_attacker_ip.get("attacker_ip") or "N/A",
        "latest_attack": latest_attack.get("detected_at"),
        "recent_attacks": recent_attacks,
    }


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

            attack_history = fetch_attack_history_summary(
                cur
            )

    finally:
        conn.close()

    return {
        "overall_logs": int(modsec_counts.get("overall_logs") or 0),
        "attack_logs": attack_history["total_attacks"],
        "most_attack_type": attack_history["most_attack_type"],
        "attacks_today": attack_history["attacks_today"],
        "attacks_last_week": attack_history["attacks_last_7_days"],
        "attacks_last_month": attack_history["attacks_last_30_days"],
    }


def get_attack_history_summary():
    conn = get_connection()

    try:
        with conn.cursor() as cur:
            attack_history = fetch_attack_history_summary(
                cur
            )

    finally:
        conn.close()

    return attack_history


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
