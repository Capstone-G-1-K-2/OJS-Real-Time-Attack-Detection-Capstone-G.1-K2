from src.auth.db import get_connection


def insert_attack_event(
    detected_at,
    attack_type,
    probability,
    attack_url,
    attacker_ip,
):
    conn = get_connection()

    try:
        with conn.cursor() as cur:

            sql = """
            INSERT INTO attack_events (
                detected_at,
                attack_type,
                probability,
                attack_url,
                attacker_ip
            )
            VALUES (%s, %s, %s, %s, %s)
            """

            cur.execute(
                sql,
                (
                    detected_at,
                    attack_type,
                    probability,
                    attack_url,
                    attacker_ip,
                ),
            )

        conn.commit()

        return cur.lastrowid

    except Exception:
        conn.rollback()
        raise
    
    finally:
        conn.close()

def update_attack_assessment(
    event_id,
    assessment,
):

    conn = get_connection()

    try:

        with conn.cursor() as cur:

            sql = """
            UPDATE attack_events
            SET assessment = %s
            WHERE id = %s
            """

            cur.execute(
                sql,
                (
                    assessment,
                    event_id,
                ),
            )

        conn.commit()

    except Exception:

        conn.rollback()

        raise

    finally:

        conn.close()
