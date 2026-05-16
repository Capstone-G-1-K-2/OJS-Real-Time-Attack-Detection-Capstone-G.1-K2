import os
import logging
import re

from dotenv import load_dotenv

from telegram import (
    Update,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
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
    revoke_verified_user,
    is_authorized,
    get_user_probability,
    update_user_probability,
    get_subscription_status,
    update_subscription_status,
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

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

ASK_EMAIL, VERIFY_OTP, SET_PROBABILITY = range(3)

EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


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

    def _register_handlers(self):

        conversation_handler = ConversationHandler(

            entry_points=[

                CommandHandler(
                    "start",
                    self.start,
                ),

                MessageHandler(
                    filters.Regex(
                        "^📊 Probability$"
                    ),
                    self.probability_menu,
                ),

                MessageHandler(
                    filters.Regex(
                        "^📡 Status$"
                    ),
                    self.status,
                ),

                MessageHandler(
                    filters.Regex(
                        (
                            "^🔕 Disable Notification$|"
                            "^🔔 Enable Notification$"
                        )
                    ),
                    self.toggle_notification,
                ),

                MessageHandler(
                    filters.Regex(
                        "^🚪 Logout$"
                    ),
                    self.logout,
                ),
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

                SET_PROBABILITY: [
                    MessageHandler(
                        filters.TEXT
                        & ~filters.COMMAND,
                        self.handle_probability,
                    )
                ],
            },

            fallbacks=[
                CommandHandler(
                    "menu",
                    self.menu,
                )
            ],
        )

        self.app.add_handler(
            conversation_handler
        )

        self.app.add_handler(
            CommandHandler(
                "menu",
                self.menu,
            )
        )

        self.app.add_handler(
            CommandHandler(
                "status",
                self.status,
            )
        )

        self.app.add_handler(
            CallbackQueryHandler(
                self.handle_attack_feedback,
                pattern="^attack_",
            )
        )

    def build_main_menu(
        self,
        chat_id,
    ):

        subscribed = (
            get_subscription_status(
                chat_id
            )
        )

        notification_button = (
            "🔕 Disable Notification"
            if subscribed
            else "🔔 Enable Notification"
        )

        keyboard = [
            [
                "📊 Probability",
                "📡 Status",
            ],
            [
                notification_button,
                "🚪 Logout",
            ],
        ]

        return ReplyKeyboardMarkup(
            keyboard,
            resize_keyboard=True,
        )

    async def menu(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):

        chat_id = (
            update.effective_chat.id
        )

        if not is_authorized(chat_id):

            await update.message.reply_text(
                "Unauthorized."
            )

            return ConversationHandler.END

        await update.message.reply_text(
            "Main menu",
            reply_markup=self.build_main_menu(
                chat_id
            ),
        )

        return ConversationHandler.END

    async def start(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):

        chat_id = (
            update.effective_chat.id
        )

        if is_authorized(chat_id):

            await update.message.reply_text(
                "You are already authenticated.",
                reply_markup=self.build_main_menu(
                    chat_id
                ),
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

        context.user_data.pop(
            "email",
            None,
        )

        if not EMAIL_PATTERN.match(email):

            await update.message.reply_text(
                (
                    "Invalid email format.\n\n"
                    "Please enter a registered email:"
                )
            )

            return ASK_EMAIL

        if not is_allowed_email(email):

            await update.message.reply_text(
                (
                    "❌ Email not authorized.\n\n"
                    "Please enter a registered email:"
                )
            )

            return ASK_EMAIL

        otp = generate_otp()

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
                "Failed sending OTP email."
            )

            return ConversationHandler.END

        store_otp(
            email,
            otp,
        )

        context.user_data[
            "email"
        ] = email

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

            await update.message.reply_text(
                (
                    "Session expired.\n\n"
                    "Please enter your authorized email:"
                )
            )

            return ASK_EMAIL

        if not verify_otp(
            email,
            otp_input,
        ):

            await update.message.reply_text(
                "Invalid OTP."
            )

            return VERIFY_OTP

        save_verified_user(
            email,
            update.effective_chat.id,
        )

        await update.message.reply_text(
            (
                "Authentication successful.\n"
                "You will now receive alerts."
            ),
            reply_markup=self.build_main_menu(
                update.effective_chat.id
            ),
        )

        return ConversationHandler.END

    async def probability_menu(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):

        chat_id = (
            update.effective_chat.id
        )

        if not is_authorized(chat_id):

            await update.message.reply_text(
                "Unauthorized."
            )

            return ConversationHandler.END

        current_probability = (
            get_user_probability(
                chat_id
            )
        )

        await update.message.reply_text(
            (
                f"Current minimum probability: "
                f"{current_probability * 100:.0f}%\n\n"
                "Enter new minimum probability (0-100):"
            )
        )

        return SET_PROBABILITY

    async def handle_probability(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):

        chat_id = (
            update.effective_chat.id
        )

        value = (
            update.message.text.strip()
        )

        try:
            probability = float(value)

        except ValueError:

            await update.message.reply_text(
                "Invalid number."
            )

            return SET_PROBABILITY

        if probability < 0 or probability > 100:

            await update.message.reply_text(
                "Probability must be between 0-100."
            )

            return SET_PROBABILITY

        normalized_probability = (
            probability / 100
        )

        update_user_probability(
            chat_id,
            normalized_probability,
        )

        await update.message.reply_text(
            (
                f"Minimum probability updated "
                f"to {probability:.0f}%"
            ),
            reply_markup=self.build_main_menu(
                chat_id
            ),
        )

        return ConversationHandler.END

    async def toggle_notification(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):

        chat_id = (
            update.effective_chat.id
        )

        if not is_authorized(chat_id):

            await update.message.reply_text(
                "Unauthorized."
            )

            return ConversationHandler.END

        current_status = (
            get_subscription_status(
                chat_id
            )
        )

        new_status = (
            not current_status
        )

        update_subscription_status(
            chat_id,
            new_status,
        )

        status_text = (
            "enabled"
            if new_status
            else "disabled"
        )

        await update.message.reply_text(
            (
                f"Notifications {status_text}."
            ),
            reply_markup=self.build_main_menu(
                chat_id
            ),
        )

        return ConversationHandler.END

    async def logout(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):

        chat_id = (
            update.effective_chat.id
        )

        if not is_authorized(chat_id):

            await update.message.reply_text(
                "You are already logged out.",
                reply_markup=ReplyKeyboardRemove(),
            )

            return ConversationHandler.END

        revoke_verified_user(chat_id)

        context.user_data.clear()

        await update.message.reply_text(
            (
                "Logged out.\n\n"
                "Use /start to authenticate again."
            ),
            reply_markup=ReplyKeyboardRemove(),
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

        if not is_authorized(chat_id):

            await update.message.reply_text(
                "Unauthorized."
            )

            return ConversationHandler.END

        current_probability = (
            get_user_probability(
                chat_id
            )
        )

        subscribed = (
            get_subscription_status(
                chat_id
            )
        )

        await update.message.reply_text(
            (
                "Bot operational.\n\n"
                f"Notification: "
                f"{'enabled' if subscribed else 'disabled'}\n"
                f"Minimum probability: "
                f"{current_probability * 100:.0f}%"
            ),
            reply_markup=self.build_main_menu(
                chat_id
            ),
        )

        return ConversationHandler.END

    async def handle_attack_feedback(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):

        query = update.callback_query

        await query.answer()

        try:

            action, event_id = (
                query.data.split(":")
            )

            event_id = int(event_id)

            assessment = (
                "yes"
                if action == "attack_yes"
                else "no"
            )

            update_attack_assessment(
                event_id,
                assessment,
            )

            await query.edit_message_reply_markup(
                reply_markup=None
            )

            await query.message.reply_text(
                f"Feedback saved: {assessment}"
            )

        except Exception:

            logger.exception(
                "Failed processing feedback"
            )

            await query.message.reply_text(
                "Failed saving feedback."
            )

    def run(self):

        logger.info(
            "Starting Telegram bot..."
        )

        self.app.run_polling()
