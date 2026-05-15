from src.alerts.telegram_bot_listener import (
    TelegramBotListener
)

if __name__ == "__main__":
    bot = TelegramBotListener()

    bot.run()
