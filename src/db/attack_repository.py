import pymysql
import os


def get_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        port=int(
                os.getenv(
                    "DB_PORT",
                    "3306",
                )
            ),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database="ojs_detection",
        cursorclass=pymysql.cursors.DictCursor,
    )


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
