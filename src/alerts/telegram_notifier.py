import os
import asyncio
import logging

from pathlib import Path

from dotenv import load_dotenv

from telegram import (
    Bot,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)

from src.auth.repository import (
    get_all_verified_users,
)

load_dotenv()

logger = logging.getLogger(__name__)

FAILED_LOG_PATH = Path(
    "logs/failed_notifications.log"
)


class TelegramNotifier:

    def __init__(self):

        self.token = os.getenv(
            "TELEGRAM_TOKEN"
        )

        if not self.token:
            raise ValueError(
                "TELEGRAM_TOKEN missing"
            )

        self.bot = Bot(
            token=self.token
        )

    async def send_alert(
        self,
        message: str,
        event_id: int,
    ) -> bool:

        users = (
            get_all_verified_users()
        )

        logger.info(
            "Sending alert to %s users",
            len(users),
        )

        if not users:

            logger.warning(
                "No verified Telegram users found"
            )

            return False

        tasks = []

        for user in users:

            chat_id = user[
                "telegram_chat_id"
            ]

            tasks.append(
                self._send_to_user(
                    chat_id=chat_id,
                    message=message,
                    event_id=event_id,
                )
            )

        results = await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )

        success_count = sum(
            1
            for result in results
            if result is True
        )

        logger.info(
            "Telegram alerts success=%s/%s",
            success_count,
            len(users),
        )

        return success_count > 0

    async def _send_to_user(
        self,
        chat_id: int,
        message: str,
        event_id: int,
        retries: int = 3,
    ) -> bool:

        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton(
                    "👍 Serangan",
                    callback_data=f"attack_yes:{event_id}",
                ),

                InlineKeyboardButton(
                    "👎 Bukan Serangan",
                    callback_data=f"attack_no:{event_id}",
                ),
            ]
        ])

        delay = 1

        for attempt in range(
            1,
            retries + 1,
        ):

            try:

                sent_message = (
                    await self.bot.send_message(
                        chat_id=chat_id,
                        text=message,
                        parse_mode="Markdown",
                        reply_markup=keyboard,
                    )
                )

                logger.info(
                    (
                        "Alert sent "
                        "chat_id=%s "
                        "message_id=%s "
                        "event_id=%s"
                    ),
                    chat_id,
                    sent_message.message_id,
                    event_id,
                )

                return True

            except Exception as e:

                logger.error(
                    (
                        "Telegram send failed "
                        "attempt=%s "
                        "chat_id=%s "
                        "error=%s"
                    ),
                    attempt,
                    chat_id,
                    e,
                )

                await asyncio.sleep(
                    delay
                )

                delay *= 2

        self._log_failed_notification(
            chat_id=chat_id,
            event_id=event_id,
            message=message,
        )

        return False

    def _log_failed_notification(
        self,
        chat_id: int,
        event_id: int,
        message: str,
    ):

        FAILED_LOG_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with FAILED_LOG_PATH.open(
            "a"
        ) as f:

            f.write(
                (
                    f"chat_id={chat_id} "
                    f"event_id={event_id}\n"
                    f"{message}\n\n"
                )
            )

        logger.error(
            (
                "Notification permanently failed "
                "chat_id=%s "
                "event_id=%s"
            ),
            chat_id,
            event_id,
        )