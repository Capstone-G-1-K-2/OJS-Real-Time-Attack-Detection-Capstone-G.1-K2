import os
import logging

from dotenv import load_dotenv

from telegram import Update

from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ConversationHandler,
    ContextTypes,
    filters,
)

from src.auth.repository import (
    is_allowed_email,
    save_verified_user,
    is_authorized,
)

from src.auth.otp_service import (
    generate_otp,
    store_otp,
    verify_otp,
)

from src.auth.email_service import (
    send_otp_email,
)

load_dotenv()

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

ASK_EMAIL, VERIFY_OTP = range(2)


class TelegramBotListener:
    def __init__(self):
        self.token = os.getenv(
            "TELEGRAM_TOKEN"
        )

        self.app = (
            Application.builder()
            .token(self.token)
            .build()
        )

        conv_handler = ConversationHandler(
            entry_points=[
                CommandHandler(
                    "start",
                    self.start,
                )
            ],
            states={
                ASK_EMAIL: [
                    MessageHandler(
                        filters.TEXT
                        & ~filters.COMMAND,
                        self.handle_email,
                    )
                ],
                VERIFY_OTP: [
                    MessageHandler(
                        filters.TEXT
                        & ~filters.COMMAND,
                        self.handle_otp,
                    )
                ],
            },
            fallbacks=[],
        )

        self.app.add_handler(
            conv_handler
        )

        self.app.add_handler(
            CommandHandler(
                "status",
                self.status,
            )
        )

    async def start(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):
        logger.info(
            "/start command received from chat_id=%s",
            update.effective_chat.id,
        )

        await update.message.reply_text(
            "Enter your authorized email:"
        )

        return ASK_EMAIL

    async def handle_email(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):
        email = (
            update.message.text.strip()
        )

        logger.info(
            "Email entered: %s",
            email,
        )

        if not is_allowed_email(email):
            logger.warning(
                "Unauthorized email attempt: %s",
                email,
            )

            await update.message.reply_text(
                "Email not authorized."
            )

            return ConversationHandler.END

        otp = generate_otp()

        logger.info(
            "Generated OTP for %s",
            email,
        )

        try:
            await send_otp_email(
                email,
                otp,
            )

        except Exception:
            logger.exception(
                "Failed to send OTP email"
            )

            await update.message.reply_text(
                "Failed to send OTP email."
            )

            return ConversationHandler.END

        # IMPORTANT:
        # store only AFTER successful send
        store_otp(email, otp)

        logger.info(
            "OTP stored successfully for %s",
            email,
        )

        context.user_data["email"] = (
            email
        )

        await update.message.reply_text(
            "OTP sent to your email."
        )

        return VERIFY_OTP

    async def handle_otp(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):
        otp_input = (
            update.message.text.strip()
        )

        email = context.user_data[
            "email"
        ]

        logger.info(
            "OTP entered for %s",
            email,
        )

        if verify_otp(
            email,
            otp_input,
        ):
            save_verified_user(
                email,
                update.effective_chat.id,
            )

            logger.info(
                "User verified successfully: %s",
                email,
            )

            await update.message.reply_text(
                "Authentication successful."
            )

            return ConversationHandler.END

        logger.warning(
            "Invalid OTP attempt for %s",
            email,
        )

        await update.message.reply_text(
            "Invalid OTP."
        )

        return VERIFY_OTP

    async def status(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):
        chat_id = (
            update.effective_chat.id
        )

        logger.info(
            "/status requested by chat_id=%s",
            chat_id,
        )

        if not is_authorized(
            chat_id
        ):
            logger.warning(
                "Unauthorized status access from %s",
                chat_id,
            )

            await update.message.reply_text(
                "Unauthorized."
            )

            return

        await update.message.reply_text(
            "Bot is working."
        )

    def run(self):
        logger.info(
            "Starting Telegram bot..."
        )

        self.app.run_polling()
