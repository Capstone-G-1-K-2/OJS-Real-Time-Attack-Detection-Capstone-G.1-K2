"""
Alert formatter for attack notifications.
"""

from __future__ import annotations


def build_attack_alert(
    *,
    timestamp: str,
    source_ip: str,
    method: str,
    uri: str,
    http_status: int,
    prediction: str,
    confidence: str,
    threshold: str,
) -> str:
    """
    Build Telegram alert message.
    """

    return f"""
🚨 *OJS ATTACK DETECTED*

━━━━━━━━━━━━━━━━━━━━

*Time*
`{timestamp}`

*Source IP*
`{source_ip}`

*Request*
`{method} {uri}`

*HTTP Status*
`{http_status}`

*Prediction*
`{prediction}`

*Confidence*
`{confidence}`

*Threshold*
`{threshold}`

━━━━━━━━━━━━━━━━━━━━

⚠️ Immediate investigation recommended.
"""
