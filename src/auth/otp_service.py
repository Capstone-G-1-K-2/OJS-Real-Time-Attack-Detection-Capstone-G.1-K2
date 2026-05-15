import random
from datetime import datetime, timedelta

from src.auth.db import get_connection


def generate_otp():
    return str(random.randint(100000, 999999))


def store_otp(email: str, otp: str):
    expires_at = datetime.now() + timedelta(minutes=5)

    conn = get_connection()

    with conn.cursor() as cursor:
        cursor.execute("""
            INSERT INTO otp_codes (
                email,
                otp_code,
                expires_at
            )
            VALUES (%s, %s, %s)
        """, (email, otp, expires_at))

    conn.commit()
    conn.close()


def verify_otp(email: str, otp_input: str) -> bool:
    conn = get_connection()

    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT *
            FROM otp_codes
            WHERE email=%s
            AND otp_code=%s
            AND used_flag=FALSE
            AND expires_at > NOW()
            ORDER BY id DESC
            LIMIT 1
        """, (email, otp_input))

        result = cursor.fetchone()

        if result:
            cursor.execute("""
                UPDATE otp_codes
                SET used_flag=TRUE
                WHERE id=%s
            """, (result["id"],))

            conn.commit()

    conn.close()

    return result is not None
