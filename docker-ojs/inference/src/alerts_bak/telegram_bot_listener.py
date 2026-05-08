import logging
import os
import subprocess
from typing import Optional

from dotenv import load_dotenv
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# Load .env
load_dotenv()

# Configure logging (stdout)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger(__name__)


class TelegramBotListener:
    """Telegram bot listener for incoming commands."""

    def __init__(self) -> None:
        self.token: str = os.getenv("TELEGRAM_TOKEN", "")
        self.allowed_chat_id: Optional[str] = os.getenv("TELEGRAM_CHAT_ID")

        if not self.token:
            raise ValueError("TELEGRAM_TOKEN is required")

        self.app = Application.builder().token(self.token).build()
        self._register_handlers()

    def _register_handlers(self) -> None:
        """Register all command and message handlers."""
        self.app.add_handler(CommandHandler("status", self._handle_status))
        self.app.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self._handle_message)
        )

    async def _handle_status(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /status command."""
        chat_id = str(update.effective_chat.id)
        username = update.effective_user.username or "unknown"
        text = update.message.text or ""

        logger.info(
            "[COMMAND] /status | chat_id=%s user=%s text=%s",
            chat_id,
            username,
            text,
        )

        if not self._is_authorized(chat_id):
            logger.warning("[UNAUTHORIZED] chat_id=%s", chat_id)
            await update.message.reply_text("Unauthorized")
            return

        result = self._run_command("date")

        await update.message.reply_text(f"🖥 VPS Time:\n{result}")

    async def _handle_message(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Log all non-command messages."""
        chat_id = str(update.effective_chat.id)
        username = update.effective_user.username or "unknown"
        text = update.message.text or ""

        logger.info(
            "[MESSAGE] chat_id=%s user=%s text=%s",
            chat_id,
            username,
            text,
        )

    def _is_authorized(self, chat_id: str) -> bool:
        """Check if chat_id is allowed."""
        return bool(self.allowed_chat_id and chat_id == self.allowed_chat_id)

    @staticmethod
    def _run_command(cmd: str) -> str:
        """Execute shell command safely."""
        try:
            return subprocess.getoutput(cmd)
        except Exception as e:
            logger.error("Command failed: %s", e)
            return "Error executing command"

    def run(self) -> None:
        """Start bot polling."""
        logger.info("Starting Telegram bot listener...")
        self.app.run_polling()