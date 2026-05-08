import os
import logging

from dotenv import load_dotenv

from telegram import (
    Update,
)

from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ConversationHandler,
    ContextTypes,
    CallbackQueryHandler,
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

from src.db.attack_repository import (
    update_attack_assessment,
)

load_dotenv()

logging.basicConfig(
    level=logging.INFO
)

logger = logging.getLogger(__name__)

ASK_EMAIL, VERIFY_OTP = range(2)


class TelegramBotListener:

    def __init__(self):

        self.token = os.getenv(
            "TELEGRAM_TOKEN"
        )

        if not self.token:
            raise ValueError(
                "TELEGRAM_TOKEN missing"
            )

        self.app = (
            Application.builder()
            .token(self.token)
            .build()
        )

        self._register_handlers()

    def _register_handlers(
        self,
    ):

        conversation_handler = (
            ConversationHandler(
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
        )

        self.app.add_handler(
            conversation_handler
        )

        self.app.add_handler(
            CommandHandler(
                "status",
                self.status,
            )
        )

        self.app.add_handler(
            CallbackQueryHandler(
                self.handle_attack_feedback
            )
        )

    async def start(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):

        chat_id = (
            update.effective_chat.id
        )

        logger.info(
            "/start received chat_id=%s",
            chat_id,
        )

        if is_authorized(
            chat_id
        ):

            await update.message.reply_text(
                (
                    "You are already "
                    "authenticated."
                )
            )

            return ConversationHandler.END

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
            .lower()
        )

        logger.info(
            "Email entered: %s",
            email,
        )

        if not is_allowed_email(
            email
        ):

            logger.warning(
                (
                    "Unauthorized email "
                    "attempt: %s"
                ),
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
                "Failed sending OTP email"
            )

            await update.message.reply_text(
                (
                    "Failed sending OTP email."
                )
            )

            return ConversationHandler.END

        store_otp(
            email,
            otp,
        )

        context.user_data[
            "email"
        ] = email

        logger.info(
            "OTP stored for %s",
            email,
        )

        await update.message.reply_text(
            (
                "OTP sent to your email.\n"
                "Enter OTP:"
            )
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

        email = context.user_data.get(
            "email"
        )

        if not email:

            logger.warning(
                "OTP flow missing email"
            )

            await update.message.reply_text(
                "Session expired."
            )

            return ConversationHandler.END

        logger.info(
            "OTP entered for %s",
            email,
        )

        if not verify_otp(
            email,
            otp_input,
        ):

            logger.warning(
                (
                    "Invalid OTP "
                    "attempt for %s"
                ),
                email,
            )

            await update.message.reply_text(
                "Invalid OTP."
            )

            return VERIFY_OTP

        save_verified_user(
            email,
            update.effective_chat.id,
        )

        logger.info(
            (
                "User authenticated "
                "email=%s "
                "chat_id=%s"
            ),
            email,
            update.effective_chat.id,
        )

        await update.message.reply_text(
            (
                "Authentication successful.\n"
                "You will now receive "
                "attack alerts."
            )
        )

        return ConversationHandler.END

    async def status(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):

        chat_id = (
            update.effective_chat.id
        )

        logger.info(
            "/status requested chat_id=%s",
            chat_id,
        )

        if not is_authorized(
            chat_id
        ):

            logger.warning(
                (
                    "Unauthorized "
                    "status access "
                    "chat_id=%s"
                ),
                chat_id,
            )

            await update.message.reply_text(
                "Unauthorized."
            )

            return

        await update.message.reply_text(
            "Bot is operational."
        )

    async def handle_attack_feedback(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):

        query = update.callback_query

        await query.answer()

        data = query.data

        logger.info(
            "Feedback callback=%s",
            data,
        )

        try:

            action, event_id = (
                data.split(":")
            )

            event_id = int(
                event_id
            )

            if action == "attack_yes":

                assessment = "yes"

            elif action == "attack_no":

                assessment = "no"

            else:

                logger.warning(
                    (
                        "Unknown feedback "
                        "action=%s"
                    ),
                    action,
                )

                return

            update_attack_assessment(
                event_id,
                assessment,
            )

            await query.edit_message_reply_markup(
                reply_markup=None
            )

            await query.message.reply_text(
                (
                    "Feedback saved: "
                    f"{assessment}"
                )
            )

            logger.info(
                (
                    "Assessment updated "
                    "event_id=%s "
                    "assessment=%s"
                ),
                event_id,
                assessment,
            )

        except Exception:

            logger.exception(
                (
                    "Failed processing "
                    "attack feedback"
                )
            )

            await query.message.reply_text(
                "Failed saving feedback."
            )

    def run(self):

        logger.info(
            "Starting Telegram bot..."
        )

        self.app.run_polling()