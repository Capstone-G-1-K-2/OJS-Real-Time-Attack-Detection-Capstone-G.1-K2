"""Telegram notification system for attack alerts."""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class TelegramNotifier:
    """Send attack alerts via Telegram Bot."""
    
    def __init__(self):
        """Initialize with token and chat ID from environment."""
        self.token = os.getenv("TELEGRAM_TOKEN", "")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        self.enabled = bool(self.token and self.chat_id)
        
        if self.enabled:
            try:
                from telegram import Bot
                self.bot = Bot(token=self.token)
                logger.info("✓ Telegram Bot initialized")
            except Exception as e:
                logger.error(f"Failed to init Telegram Bot: {e}")
                self.enabled = False
    
    def is_configured(self) -> bool:
        """Check if Telegram is properly configured."""
        return self.enabled
    
    async def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "medium",
        attack_count: int = 0,
    ) -> bool:
        """
        Send alert to Telegram.
        
        Args:
            title: Alert title
            message: Alert message
            severity: "low", "medium", "high", "critical"
            attack_count: Number of attacks detected
        
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.enabled:
            logger.warning("Telegram not configured, skipping alert")
            return False
        
        try:
            # Format severity emoji
            emoji_map = {
                "low": "🟢",
                "medium": "🟡",
                "high": "🔴",
                "critical": "🔴🔴",
            }
            emoji = emoji_map.get(severity, "⚠️")
            
            # Build message
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            text = (
                f"{emoji} *{title}*\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"*Severity*: {severity.upper()}\n"
                f"*Attacks Detected*: {attack_count}\n"
                f"*Time*: {timestamp}\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"{message}\n"
            )
            
            # Send message
            await self.bot.send_message(
                chat_id=self.chat_id,
                text=text,
                parse_mode="Markdown",
            )
            
            logger.info(f"✓ Alert sent: {title}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
            return False
    
    async def send_summary(
        self,
        period: str,
        total_logs: int,
        attack_count: int,
        top_attacks: Optional[list[str]] = None,
    ) -> bool:
        """
        Send periodic summary report.
        
        Args:
            period: "hourly", "daily", etc.
            total_logs: Total logs processed
            attack_count: Total attacks detected
            top_attacks: List of top attack patterns
        
        Returns:
            True if sent successfully
        """
        if not self.enabled:
            return False
        
        try:
            attack_rate = (attack_count / total_logs * 100) if total_logs > 0 else 0
            
            text = (
                f"📊 *{period.upper()} SUMMARY*\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"*Logs Processed*: {total_logs}\n"
                f"*Attacks Detected*: {attack_count}\n"
                f"*Attack Rate*: {attack_rate:.2f}%\n"
            )
            
            if top_attacks:
                text += (
                    f"\n*Top Attack Patterns*:\n"
                    + "\n".join(f"• {attack}" for attack in top_attacks[:5])
                )
            
            text += "\n━━━━━━━━━━━━━━━━━━━━"
            
            await self.bot.send_message(
                chat_id=self.chat_id,
                text=text,
                parse_mode="Markdown",
            )
            
            logger.info(f"✓ Summary sent: {period}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to send summary: {e}")
            return False
