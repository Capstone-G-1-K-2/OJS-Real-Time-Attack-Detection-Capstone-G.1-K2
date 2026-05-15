RULE_CATEGORIES = {
    # Scanner / Recon
    "913100": "Scanner",
    "913101": "Scanner",
    "913102": "Scanner",
    # Protocol
    "920350": "Protocol",  # numeric IP (suppressed, tapi jaga-jaga)
    # Path Traversal
    "930100": "Path Traversal",
    "930110": "Path Traversal",
    "930120": "LFI",
    "930130": "LFI",
    # RCE
    "932100": "RCE",
    "932105": "RCE",
    "932110": "RCE",
    "932115": "RCE",
    "932160": "RCE",
    "932170": "RCE",
    "932171": "RCE",
    # XSS
    "941100": "XSS",
    "941101": "XSS",
    "941110": "XSS",
    "941120": "XSS",
    "941130": "XSS",
    "941140": "XSS",
    "941150": "XSS",
    "941160": "XSS",
    "941170": "XSS",
    "941180": "XSS",
    "941190": "XSS",
    "941200": "XSS",
    "941210": "XSS",
    "941220": "XSS",
    "941230": "XSS",
    "941240": "XSS",
    "941250": "XSS",
    "941260": "XSS",
    "941270": "XSS",
    "941280": "XSS",
    "941290": "XSS",
    "941300": "XSS",
    "941310": "XSS",
    "941320": "XSS",
    "941330": "XSS",
    "941340": "XSS",
    "941350": "XSS",
    # SQLi
    "942100": "SQLi",
    "942101": "SQLi",
    "942110": "SQLi",
    "942120": "SQLi",
    "942130": "SQLi",
    "942140": "SQLi",
    "942150": "SQLi",
    "942160": "SQLi",
    "942170": "SQLi",
    "942180": "SQLi",
    "942190": "SQLi",
    "942200": "SQLi",
    "942210": "SQLi",
    "942220": "SQLi",
    "942230": "SQLi",
    "942240": "SQLi",
    "942250": "SQLi",
    "942260": "SQLi",
    "942270": "SQLi",
    "942280": "SQLi",
    "942290": "SQLi",
    "942300": "SQLi",
    "942310": "SQLi",
    "942320": "SQLi",
    "942330": "SQLi",
    "942340": "SQLi",
    "942350": "SQLi",
    "942360": "SQLi",
    "942361": "SQLi",
    "942370": "SQLi",
    "942380": "SQLi",
    "942390": "SQLi",
    "942400": "SQLi",
    "942410": "SQLi",
    "942420": "SQLi",
    "942421": "SQLi",
    "942430": "SQLi",
    "942440": "SQLi",
    "942450": "SQLi",
    "942460": "SQLi",
    "942470": "SQLi",
    "942480": "SQLi",
    # Anomaly score threshold (indicator, bukan attack type sendiri)
    "949110": "Anomaly Threshold",
    "980130": "Anomaly Threshold",
}

def extract_attack_type(messages):
    
        attack_types = set()
    
        for msg in messages:
    
            rule_id = (
                msg.get("details", {})
                .get("ruleId")
            )
    
            if not rule_id:
                continue
    
            category = RULE_CATEGORIES.get(
                rule_id
            )
    
            if not category:
                continue
    
            if category == "Anomaly Threshold":
                continue
    
            attack_types.add(category)
    
        if not attack_types:
            return "unknown"
    
        return ", ".join(
            sorted(attack_types)
        )
