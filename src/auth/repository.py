from src.auth.db import get_connection


def is_allowed_email(email: str) -> bool:
    conn = get_connection()

    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM allowed_emails WHERE email=%s",
            (email,)
        )

        result = cursor.fetchone()

    conn.close()

    return result is not None


def save_verified_user(email: str, chat_id: int):
    conn = get_connection()

    with conn.cursor() as cursor:
        cursor.execute("""
            INSERT INTO telegram_users (
                email,
                telegram_chat_id,
                verified
            )
            VALUES (%s, %s, TRUE)
            ON DUPLICATE KEY UPDATE
                telegram_chat_id=VALUES(telegram_chat_id),
                verified=TRUE
        """, (email, chat_id))

    conn.commit()
    conn.close()

def get_all_verified_users():
    conn = get_connection()

    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT
                telegram_chat_id,
                email
            FROM telegram_users
            WHERE verified=TRUE
        """)

        results = cursor.fetchall()

    conn.close()

    return results


def is_authorized(chat_id: int) -> bool:
    conn = get_connection()

    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT * FROM telegram_users
            WHERE telegram_chat_id=%s
            AND verified=TRUE
        """, (chat_id,))

        result = cursor.fetchone()

    conn.close()

    return result is not None
