import os
import logging

import httpx

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


async def send_otp_email(
    receiver_email: str,
    otp: str,
):
    api_url = os.getenv(
        "SMTP_API_URL"
    )

    payload = {
        "server": os.getenv(
            "SMTP_SERVER"
        ),
        "username": os.getenv(
            "SMTP_USERNAME"
        ),
        "password": os.getenv(
            "SMTP_PASSWORD"
        ),
        "from": os.getenv(
            "SMTP_FROM"
        ),
        "to": receiver_email,
        "subject": "OJS Detection OTP",
        "body": f"""
<h2>Your OTP Code</h2>

<p>{otp}</p>

<p>This code expires in 5 minutes.</p>
""",
    }

    logger.info(
        "MXRoute API URL: %s",
        api_url,
    )

    logger.info(
        "Sending OTP to: %s",
        receiver_email,
    )

    logger.info(
        "MXRoute payload: %s",
        payload,
    )

    async with httpx.AsyncClient(
        timeout=15
    ) as client:

        response = await client.post(
            api_url,
            json=payload,
        )

    logger.info(
        "MXRoute response status: %s",
        response.status_code,
    )

    logger.info(
        "MXRoute response body: %s",
        response.text,
    )

    response.raise_for_status()

    try:
        data = response.json()

        logger.info(
            "MXRoute response JSON: %s",
            data,
        )

        if (
            isinstance(data, dict)
            and data.get("success") is False
        ):
            raise Exception(
                f"MXRoute API failure: {data}"
            )

    except Exception:
        logger.warning(
            "Response is not JSON or JSON validation failed"
        )
