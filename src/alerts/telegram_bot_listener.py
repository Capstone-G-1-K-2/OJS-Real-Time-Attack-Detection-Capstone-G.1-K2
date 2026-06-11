import os
import logging
import re
import asyncio
import time

from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path

from dotenv import load_dotenv

from telegram import (
    BotCommand,
    BotCommandScopeChat,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    MenuButtonCommands,
    Update,
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

from src.db.modsec_event_repository import (
    mark_false_positive_by_attack_event_id,
)

from src.db.status_repository import (
    get_attack_history_summary,
    get_status_metrics,
    set_attack_notifications_paused,
)

from src.services.model_deployment_service import (
    ModelCopyError,
    ModelRestartError,
    build_confirm_message,
    build_model_registry_message,
    deploy_model,
    format_metric,
    get_current_model_info,
)

load_dotenv()

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

ASK_EMAIL, VERIFY_OTP, SET_PROBABILITY = range(3)

EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


class TelegramBotListener:

    COMMAND_DESCRIPTIONS = {
        "start": "🚀 Mulai bot ini",
        "status": "⚙️ Periksa status bot",
        "threshold": "👁 Ubah threshold kepercayaan",
        "train": "🎓 Latih ulang model",
        "model": "🤖 Pilih model aktif",
        "history": "⚔️ Tampilkan riwayat serangan",
        "mute": "🔕 Matikan Notifikasi",
        "unmute": "🔔 Hidupkan Notifikasi",
        "logout": "🚪 Logout dari bot",
    }

    def __init__(self):

        self.started_at = datetime.now()
        self.training_in_progress = False
        self.model_deploy_in_progress = False

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
            .post_init(
                self.configure_command_menu
            )
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

                CommandHandler(
                    "threshold",
                    self.probability_menu,
                ),

                CommandHandler(
                    "train",
                    self.train,
                ),

                CommandHandler(
                    "model",
                    self.model,
                ),

                CommandHandler(
                    "history",
                    self.history,
                ),

                CommandHandler(
                    "mute",
                    self.mute_notification,
                ),

                CommandHandler(
                    "unmute",
                    self.unmute_notification,
                ),

                CommandHandler(
                    "logout",
                    self.logout,
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
                ),
                CommandHandler(
                    "status",
                    self.status,
                ),
                CommandHandler(
                    "threshold",
                    self.probability_menu,
                ),
                CommandHandler(
                    "train",
                    self.train,
                ),
                CommandHandler(
                    "model",
                    self.model,
                ),
                CommandHandler(
                    "history",
                    self.history,
                ),
                CommandHandler(
                    "mute",
                    self.mute_notification,
                ),
                CommandHandler(
                    "unmute",
                    self.unmute_notification,
                ),
                CommandHandler(
                    "logout",
                    self.logout,
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
            CommandHandler(
                "threshold",
                self.probability_menu,
            )
        )

        self.app.add_handler(
            CommandHandler(
                "train",
                self.train,
            )
        )

        self.app.add_handler(
            CommandHandler(
                "model",
                self.model,
            )
        )

        self.app.add_handler(
            CommandHandler(
                "history",
                self.history,
            )
        )

        self.app.add_handler(
            CommandHandler(
                "mute",
                self.mute_notification,
            )
        )

        self.app.add_handler(
            CommandHandler(
                "unmute",
                self.unmute_notification,
            )
        )

        self.app.add_handler(
            CommandHandler(
                "logout",
                self.logout,
            )
        )

        self.app.add_handler(
            CallbackQueryHandler(
                self.handle_attack_feedback,
                pattern="^attack_",
            )
        )

        self.app.add_handler(
            CallbackQueryHandler(
                self.handle_train_confirmation,
                pattern="^train_",
            )
        )

        self.app.add_handler(
            CallbackQueryHandler(
                self.handle_model_callback,
                pattern="^model:",
            )
        )

    async def configure_command_menu(
        self,
        application: Application,
    ):

        await application.bot.set_my_commands(
            self.build_command_menu(
                subscribed=True
            )
        )

        await application.bot.set_chat_menu_button(
            menu_button=MenuButtonCommands()
        )

    def build_command_menu(
        self,
        subscribed,
    ):

        notification_command = (
            "mute"
            if subscribed
            else "unmute"
        )

        return [
            self.build_command(command)
            for command in (
                "start",
                "status",
                "threshold",
                "train",
                "model",
                notification_command,
                "history",
                "logout",
            )
        ]

    def build_command(
        self,
        command,
    ):

        return BotCommand(
            command,
            self.COMMAND_DESCRIPTIONS[
                command
            ],
        )

    async def configure_chat_command_menu(
        self,
        context: ContextTypes.DEFAULT_TYPE,
        chat_id,
    ):

        subscribed = get_subscription_status(
            chat_id
        )

        await context.bot.set_my_commands(
            self.build_command_menu(
                subscribed
            ),
            scope=BotCommandScopeChat(
                chat_id=chat_id
            ),
        )

        await context.bot.set_chat_menu_button(
            chat_id=chat_id,
            menu_button=MenuButtonCommands(),
        )

    def build_main_menu(
        self,
        chat_id,
    ):
        return ReplyKeyboardRemove()

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

        await self.configure_chat_command_menu(
            context,
            chat_id,
        )

        await update.message.reply_text(
            "Use the Menu button to choose a command.",
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

            await self.configure_chat_command_menu(
                context,
                chat_id,
            )

            await update.message.reply_text(
                (
                    "You are already authenticated.\n"
                    "Use the Menu button to choose a command."
                ),
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

        await self.configure_chat_command_menu(
            context,
            update.effective_chat.id,
        )

        await update.message.reply_text(
            (
                "Authentication successful.\n"
                "You will now receive alerts.\n\n"
                "Use the Menu button to choose a command."
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

        await self.configure_chat_command_menu(
            context,
            chat_id,
        )

        current_probability = (
            get_user_probability(
                chat_id
            )
        )

        await update.message.reply_text(
            (
                f"Current confidence threshold: "
                f"{current_probability * 100:.0f}%\n\n"
                "Enter new confidence threshold (0-100):"
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
                "Threshold must be between 0-100."
            )

            return SET_PROBABILITY

        normalized_probability = (
            probability / 100
        )

        update_user_probability(
            chat_id,
            normalized_probability,
        )

        await self.configure_chat_command_menu(
            context,
            chat_id,
        )

        await update.message.reply_text(
            (
                f"Confidence threshold updated "
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

        await self.configure_chat_command_menu(
            context,
            chat_id,
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

    async def mute_notification(
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

        update_subscription_status(
            chat_id,
            False,
        )

        await self.configure_chat_command_menu(
            context,
            chat_id,
        )

        await update.message.reply_text(
            "Notifications disabled.",
            reply_markup=self.build_main_menu(
                chat_id
            ),
        )

        return ConversationHandler.END

    async def unmute_notification(
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

        update_subscription_status(
            chat_id,
            True,
        )

        await self.configure_chat_command_menu(
            context,
            chat_id,
        )

        await update.message.reply_text(
            "Notifications enabled.",
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

        await context.bot.delete_my_commands(
            scope=BotCommandScopeChat(
                chat_id=chat_id
            ),
        )

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

        await self.configure_chat_command_menu(
            context,
            chat_id,
        )

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

        try:

            metrics = get_status_metrics()

        except Exception:

            logger.exception(
                "Failed loading status metrics"
            )

            metrics = {
                "overall_logs": 0,
                "attack_logs": 0,
                "most_attack_type": "Unavailable",
                "attacks_today": 0,
                "attacks_last_week": 0,
                "attacks_last_month": 0,
            }

        try:
            current_model = await asyncio.to_thread(
                get_current_model_info
            )

        except Exception:
            logger.exception(
                "Failed loading current model"
            )
            current_model = None

        uptime_started_at = (
            self.started_at.strftime(
                "%Y/%m/%d %H:%M"
            )
        )

        notification_status = (
            "On"
            if subscribed
            else "Off"
        )

        most_attack_type = escape(
            str(
                metrics[
                    "most_attack_type"
                ]
            )
        )

        await update.message.reply_text(
            (
                "<b><u>🤖 System Status</u></b>\n"
                f"Bot Uptime: Since <b>{uptime_started_at}</b>\n"
                f"Notification: {notification_status}\n"
                f"Current Threshold: {current_probability * 100:.0f}%\n\n"
                "<b><u>📈 Dataset Information</u></b>\n"
                f"Overall Logs: {metrics['overall_logs']}\n"
                f"Attack Logs: {metrics['attack_logs']}\n"
                f"Most attack type: {most_attack_type}\n\n"
                "<b><u>🤖 Active Model</u></b>\n"
                f"{self.format_current_model_status(current_model)}\n\n"
            ),
            parse_mode="HTML",
            reply_markup=self.build_main_menu(
                chat_id
            ),
        )

        return ConversationHandler.END

    def format_current_model_status(
        self,
        model_info,
    ):

        if not model_info:
            return "No active model recorded"

        model_name = escape(
            str(
                model_info.get(
                    "model_name",
                    "Unknown",
                )
            )
        )

        return "\n".join([
            f"Model: <b>{model_name}</b>",
            f"Accuracy: {format_metric(model_info.get('accuracy'))}",
            f"Precision: {format_metric(model_info.get('precision_score'))}",
            f"Recall: {format_metric(model_info.get('recall_score'))}",
            f"F1 Score: {format_metric(model_info.get('f1_score'))}",
        ])

    async def history(
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

        await self.configure_chat_command_menu(
            context,
            chat_id,
        )

        try:

            history_summary = (
                get_attack_history_summary()
            )

        except Exception:

            logger.exception(
                "Failed loading attack history"
            )

            await update.message.reply_text(
                "Failed loading attack history."
            )

            return ConversationHandler.END

        await update.message.reply_text(
            self.format_attack_history(
                history_summary
            ),
            parse_mode="HTML",
            reply_markup=self.build_main_menu(
                chat_id
            ),
        )

        return ConversationHandler.END

    def format_attack_history(
        self,
        history_summary,
    ):

        if history_summary[
            "total_attacks"
        ] == 0:
            return (
                "<b><u>⚔️ Attack History</u></b>\n\n"
                "No attack history found yet."
            )

        latest_attack = (
            self.format_wib_datetime(
                history_summary[
                    "latest_attack"
                ]
            )
        )

        summary_lines = "\n".join([
            f"Today: {history_summary['attacks_today']}",
            f"Last 7 Days: {history_summary['attacks_last_7_days']}",
            f"Last 30 Days: {history_summary['attacks_last_30_days']}",
            f"Most Attack Type: {escape(str(history_summary['most_attack_type']))}",
            f"Most Attacker IP: {escape(str(history_summary['most_attacker_ip']))}",
            f"Latest Attack: {escape(latest_attack)}",
        ])

        recent_lines = []

        for index, attack in enumerate(
            history_summary[
                "recent_attacks"
            ],
            1,
        ):

            attack_type = (
                attack.get("attack_type")
                or "Unknown"
            )
            probability = (
                self.format_probability(
                    attack.get("probability")
                )
            )
            attack_url = (
                self.truncate_text(
                    attack.get("attack_url")
                    or "N/A",
                    46,
                )
            )

            recent_lines.append(
                (
                    f"{index}. {escape(str(attack_type))} | "
                    f"{escape(probability)} | "
                    f"{escape(attack_url)}"
                )
            )

        recent_text = (
            "\n".join(recent_lines)
            if recent_lines
            else "No recent attacks."
        )

        return (
            "<b><u>⚔️ Attack History</u></b>\n"
            f"{summary_lines}\n\n"
            "<b><u>⌛ Recent attacks</u></b>\n"
            f"{recent_text}"
        )

    def format_wib_datetime(
        self,
        value,
    ):

        if not value:
            return "N/A"

        if isinstance(
            value,
            datetime,
        ):
            timestamp = value
        else:
            raw_value = str(value).strip()
            timestamp = None

            for date_format in (
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ",
            ):
                try:
                    timestamp = datetime.strptime(
                        raw_value,
                        date_format,
                    )
                    break
                except ValueError:
                    continue

            if timestamp is None:
                return raw_value

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(
                tzinfo=timezone.utc
            )

        wib_timezone = timezone(
            timedelta(hours=7),
            "WIB",
        )

        return timestamp.astimezone(
            wib_timezone
        ).strftime(
            "%Y/%m/%d %H:%M WIB"
        )

    def format_probability(
        self,
        value,
    ):

        if value is None:
            return "N/A"

        try:
            return f"{float(value) * 100:.1f}%"
        except (TypeError, ValueError):
            return "N/A"

    def truncate_text(
        self,
        value,
        max_length,
    ):

        text = str(value)

        if len(text) <= max_length:
            return text

        return f"{text[:max_length - 3]}..."

    async def model(
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

        await self.configure_chat_command_menu(
            context,
            chat_id,
        )

        try:
            await self.send_model_registry(
                update.message,
                context,
                page=0,
            )

        except Exception:
            logger.exception(
                "Failed loading model registry"
            )

            await update.message.reply_text(
                "Failed loading model registry."
            )

        return ConversationHandler.END

    async def send_model_registry(
        self,
        message,
        context: ContextTypes.DEFAULT_TYPE,
        page,
        edit=False,
    ):

        view = await asyncio.to_thread(
            build_model_registry_message,
            page,
        )

        context.user_data[
            "model_registry_models"
        ] = [
            model_info["model_name"]
            for model_info in view["models"]
        ]
        context.user_data[
            "model_registry_page"
        ] = view["page"]

        reply_markup = self.build_model_keyboard(
            view
        )

        if edit:
            await message.edit_text(
                view["message"],
                parse_mode="HTML",
                reply_markup=reply_markup,
            )
        else:
            await message.reply_text(
                view["message"],
                parse_mode="HTML",
                reply_markup=reply_markup,
            )

    def build_model_keyboard(
        self,
        view,
    ):

        keyboard = []

        if view["total_pages"] > 1:
            keyboard.append([
                InlineKeyboardButton(
                    "⬅️ Previous",
                    callback_data=(
                        f"model:page:{max(view['page'] - 1, 0)}"
                    ),
                ),
                InlineKeyboardButton(
                    "➡️ Next",
                    callback_data=(
                        f"model:page:{min(view['page'] + 1, view['total_pages'] - 1)}"
                    ),
                ),
            ])

        number_buttons = []
        start_index = (
            view["page"]
            * view["per_page"]
        )

        for slot, _model_info in enumerate(
            view["page_models"],
            1,
        ):
            number_buttons.append(
                InlineKeyboardButton(
                    str(slot),
                    callback_data=(
                        f"model:pick:{start_index + slot - 1}"
                    ),
                )
            )

        if number_buttons:
            keyboard.append(
                number_buttons
            )

        return InlineKeyboardMarkup(
            keyboard
        )

    def build_model_confirm_keyboard(
        self,
    ):

        return InlineKeyboardMarkup([
            [
                InlineKeyboardButton(
                    "✅ Yes, deploy",
                    callback_data="model:yes",
                ),
                InlineKeyboardButton(
                    "❌ Cancel",
                    callback_data="model:no",
                ),
            ]
        ])

    async def handle_model_callback(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):

        query = update.callback_query
        chat_id = update.effective_chat.id

        await query.answer()

        if not is_authorized(chat_id):

            await query.message.reply_text(
                "Unauthorized."
            )

            return

        data_parts = query.data.split(
            ":"
        )

        if len(data_parts) < 2:
            return

        action = data_parts[1]

        if action == "page":
            try:
                page = int(
                    data_parts[2]
                )
            except (IndexError, ValueError):
                page = 0

            if page == context.user_data.get(
                "model_registry_page"
            ):
                return

            await self.send_model_registry(
                query.message,
                context,
                page=page,
                edit=True,
            )
            return

        if action == "pick":
            await self.handle_model_pick(
                query,
                context,
                data_parts,
            )
            return

        if action == "no":
            await query.edit_message_text(
                "Deployment cancelled."
            )
            return

        if action == "yes":
            await self.handle_model_deploy_confirmed(
                query,
                context,
                chat_id,
            )

    async def handle_model_pick(
        self,
        query,
        context: ContextTypes.DEFAULT_TYPE,
        data_parts,
    ):

        try:
            selected_index = int(
                data_parts[2]
            )
        except (IndexError, ValueError):
            await query.message.reply_text(
                "Invalid model selection."
            )
            return

        model_names = context.user_data.get(
            "model_registry_models",
            [],
        )

        if (
            selected_index < 0
            or selected_index >= len(model_names)
        ):
            await query.message.reply_text(
                "Invalid model selection."
            )
            return

        model_name = model_names[
            selected_index
        ]

        try:
            confirm_message = await asyncio.to_thread(
                build_confirm_message,
                model_name,
            )

        except Exception:
            logger.exception(
                "Failed building model deployment confirmation"
            )

            await query.message.reply_text(
                "Selected model is no longer available."
            )
            return

        context.user_data[
            "selected_model_name"
        ] = model_name

        await query.edit_message_text(
            confirm_message,
            parse_mode="HTML",
            reply_markup=self.build_model_confirm_keyboard(),
        )

    async def handle_model_deploy_confirmed(
        self,
        query,
        context: ContextTypes.DEFAULT_TYPE,
        chat_id,
    ):

        if self.model_deploy_in_progress:

            await query.message.reply_text(
                "Another model deployment is already in progress. Please wait."
            )
            return

        model_name = context.user_data.get(
            "selected_model_name"
        )

        if not model_name:
            await query.message.reply_text(
                "Selected model is no longer available."
            )
            return

        self.model_deploy_in_progress = True

        await query.edit_message_text(
            "Model is loading, please wait..."
        )

        try:
            model_info = await asyncio.to_thread(
                deploy_model,
                model_name,
                chat_id,
            )

        except ModelCopyError:
            logger.exception(
                "Model copy failed"
            )

            await query.message.reply_text(
                "❌ Failed to deploy model: could not copy selected model."
            )
            return

        except ModelRestartError:
            logger.exception(
                "Model restart failed"
            )

            await query.message.reply_text(
                "❌ Model file was replaced, but inference restart failed. Please check the server."
            )
            return

        except Exception:
            logger.exception(
                "Model deployment failed"
            )

            await query.message.reply_text(
                "❌ Failed to deploy model. Please check the server."
            )
            return

        finally:
            self.model_deploy_in_progress = False

        await query.message.reply_text(
            self.format_model_deploy_success(
                model_info
            ),
            parse_mode="HTML",
        )

    def format_model_deploy_success(
        self,
        model_info,
    ):

        return (
            "✅ Successfully loaded new model!\n\n"
            "You are now using:\n"
            f"<b>{escape(model_info['model_name'])}</b>\n\n"
            f"{'Accuracy':<9}: {self.format_model_metric(model_info.get('accuracy'))}\n"
            f"{'Precision':<9}: {self.format_model_metric(model_info.get('precision_score'))}\n"
            f"{'Recall':<9}: {self.format_model_metric(model_info.get('recall_score'))}\n"
            f"{'F1 Score':<9}: {self.format_model_metric(model_info.get('f1_score'))}"
        )

    def format_model_metric(
        self,
        value,
    ):

        return format_metric(
            value
        )

    async def train(
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

        if self.training_in_progress:

            await update.message.reply_text(
                "Training is already running."
            )

            return ConversationHandler.END

        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton(
                    "Yes",
                    callback_data="train_yes",
                ),
                InlineKeyboardButton(
                    "No",
                    callback_data="train_no",
                ),
            ]
        ])

        await update.message.reply_text(
            "Are you sure you want to perform retraining ?",
            reply_markup=keyboard,
        )

        return ConversationHandler.END

    async def handle_train_confirmation(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):

        query = update.callback_query
        chat_id = update.effective_chat.id

        await query.answer()

        if not is_authorized(chat_id):

            await query.message.reply_text(
                "Unauthorized."
            )

            return

        await query.edit_message_reply_markup(
            reply_markup=None
        )

        if query.data == "train_no":

            await query.message.reply_text(
                "Training aborted"
            )

            return

        if query.data != "train_yes":
            return

        if self.training_in_progress:

            await query.message.reply_text(
                "Training is already running."
            )

            return

        self.training_in_progress = True

        await query.message.reply_text(
            "Start training... please wait"
        )

        try:

            set_attack_notifications_paused(
                True
            )

            result = await asyncio.to_thread(
                self.run_retraining
            )

        except Exception as exc:

            logger.exception(
                "Training failed"
            )

            await query.message.reply_text(
                f"Training failed: {escape(str(exc))}",
                parse_mode="HTML",
            )

            return

        finally:

            try:
                set_attack_notifications_paused(
                    False
                )
            except Exception:
                logger.exception(
                    "Failed resuming attack notifications"
                )

            self.training_in_progress = False

        await query.message.reply_text(
            self.format_training_result(
                result
            ),
            parse_mode="HTML",
        )

    def run_retraining(self):

        from scripts.export_modsec_events_for_retraining import (
            export_events,
        )
        from scripts.run_modsec_training import (
            train,
        )

        timestamp = datetime.now().strftime(
            "%y%m%d%H%M%S"
        )
        model_path = Path(
            f"models/trained_models/model_{timestamp}.pkl"
        )
        metrics_path = Path(
            f"models/trained_models/model_{timestamp}_metrics.json"
        )
        dataset_path = Path(
            f"data/processed/retraining_dataset_{timestamp}.csv"
        )

        start_time = time.monotonic()

        row_count = export_events(
            output_path=dataset_path
        )

        if row_count == 0:
            raise ValueError(
                "No modsec_events rows available for retraining."
            )

        summary = train(
            dataset_path=str(dataset_path),
            model_output=str(model_path),
            metrics_output=str(metrics_path),
        )

        elapsed_seconds = int(
            round(
                time.monotonic() - start_time
            )
        )

        return {
            "model_path": model_path,
            "model_name": model_path.name,
            "elapsed_seconds": elapsed_seconds,
            "metrics": summary[
                "test_metrics"
            ],
        }

    def format_training_result(
        self,
        result,
    ):

        metrics = result[
            "metrics"
        ]

        details = "\n".join([
            f"{'Saved PKL':<12}: {result['model_name']}",
            f"{'Time needed':<12}: {result['elapsed_seconds']} seconds",
            f"{'Accuracy':<12}: {metrics['accuracy']:.4f}",
            f"{'F1':<12}: {metrics['f1']:.4f}",
            f"{'Precision':<12}: {metrics['precision']:.4f}",
            f"{'Recall':<12}: {metrics['recall']:.4f}",
            f"{'Roc_auc':<12}: {metrics['roc_auc']:.4f}",
        ])

        return (
            "<b><u>🎓 Training Results</u></b>\n"
            f"<pre>{escape(details)}</pre>\n"
            f"📂 Saved on <code>{escape(str(result['model_path']))}</code>"
        )

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

            if action == "attack_no":

                mark_false_positive_by_attack_event_id(
                    event_id
                )

                feedback_message = (
                    "Ditandai sebagai bukan serangan."
                )

            else:

                feedback_message = (
                    "Feedback saved: yes"
                )

            await query.edit_message_reply_markup(
                reply_markup=None
            )

            await query.message.reply_text(
                feedback_message
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
