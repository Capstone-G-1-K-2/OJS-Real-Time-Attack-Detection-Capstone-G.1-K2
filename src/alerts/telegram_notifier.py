import logging
import os
import asyncio

from telegram import Bot
from dotenv import load_dotenv

from src.auth.repository import (
    get_all_verified_users,
)

load_dotenv()

logger = logging.getLogger(__name__)


class TelegramNotifier:
    def __init__(self):
        self.token = os.getenv(
            "TELEGRAM_TOKEN"
        )

        self.bot = Bot(
            token=self.token
        )

    async def send_alert(
        self,
        message: str,
    ):
        users = (
            get_all_verified_users()
        )

        logger.info(
            "Sending alert to %s users",
            len(users),
        )

        tasks = []

        for user in users:
            chat_id = user[
                "telegram_chat_id"
            ]

            tasks.append(
                self._send_to_user(
                    chat_id,
                    message,
                )
            )

        await asyncio.gather(*tasks)

    async def _send_to_user(
        self,
        chat_id: int,
        message: str,
    ):
        try:
            await self.bot.send_message(
                chat_id=chat_id,
                text=message,
                parse_mode="Markdown",
            )

            logger.info(
                "Alert sent to chat_id=%s",
                chat_id,
            )

        except Exception:
            logger.exception(
                "Failed sending alert to %s",
                chat_id,
            )
