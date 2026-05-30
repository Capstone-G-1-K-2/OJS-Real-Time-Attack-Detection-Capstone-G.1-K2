import os
import asyncio
import logging

from pathlib import Path

from dotenv import load_dotenv
from telegram.request import HTTPXRequest

from telegram import (
    Bot,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)

from src.auth.repository import (
    get_all_verified_users,
)

from src.db.status_repository import (
    are_attack_notifications_paused,
)

load_dotenv()

logger = logging.getLogger(__name__)

FAILED_LOG_PATH = Path("logs/failed_notifications.log")


class TelegramNotifier:

    def __init__(self):

        self.token = os.getenv("TELEGRAM_TOKEN")

        if not self.token:
            raise ValueError("TELEGRAM_TOKEN missing")

        request = HTTPXRequest(
            connection_pool_size=20,
            pool_timeout=30.0,
            connect_timeout=10.0,
            read_timeout=20.0,
            write_timeout=20.0,
        )

        self.bot = Bot(
            token=self.token,
            request=request,
        )

        self.send_semaphore = asyncio.Semaphore(5)

    async def send_alert(
        self,
        message: str,
        event_id: int,
        probability: float,
    ) -> bool:

        try:
            if are_attack_notifications_paused():
                logger.info(
                    "Telegram alert skipped because training is running"
                )
                return False
        except Exception:
            logger.exception(
                "Failed checking notification pause state"
            )

        users = get_all_verified_users()

        if not users:
            logger.warning("No verified users")
            return False

        targets = []

        for user in users:

            if not user.get("is_subscribed", True):
                continue

            user_threshold = user.get("min_probability", 0.5)

            if probability < user_threshold:
                continue

            targets.append(user["telegram_chat_id"])

        targeted_users = len(targets)

        logger.info("Targeted users=%s", targeted_users)

        if targeted_users == 0:
            logger.info("No users matched criteria")
            return False

        results = []

        for chat_id in targets:
            result = await self._send_to_user(
                chat_id=chat_id,
                message=message,
                event_id=event_id,
            )

            results.append(result)

        success_count = sum(
            1
            for result in results
            if result is True
        )

        logger.info(
            "Telegram alerts success=%s/%s",
            success_count,
            targeted_users,
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
                    "👎 Bukan Serangan",
                    callback_data=f"attack_no:{event_id}",
                ),
            ]
        ])

        delay = 1

        async with self.send_semaphore:

            for attempt in range(1, retries + 1):

                try:
                    sent_message = await self.bot.send_message(
                        chat_id=chat_id,
                        text=message,
                        parse_mode="Markdown",
                        reply_markup=keyboard,
                    )

                    logger.info(
                        "Alert sent chat_id=%s message_id=%s event_id=%s",
                        chat_id,
                        sent_message.message_id,
                        event_id,
                    )

                    return True

                except Exception as e:
                    logger.error(
                        "Telegram send failed attempt=%s chat_id=%s error=%s",
                        attempt,
                        chat_id,
                        e,
                    )

                    await asyncio.sleep(delay)
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

        with FAILED_LOG_PATH.open("a") as f:
            f.write(
                (
                    f"chat_id={chat_id} "
                    f"event_id={event_id}\n"
                    f"{message}\n\n"
                )
            )

        logger.error(
            "Notification permanently failed chat_id=%s event_id=%s",
            chat_id,
            event_id,
        )
