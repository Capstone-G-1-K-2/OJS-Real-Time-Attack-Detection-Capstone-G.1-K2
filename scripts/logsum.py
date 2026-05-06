#!/usr/bin/env python3
import json
import sys
import argparse
from collections import defaultdict
from datetime import datetime

# Rule ID to attack type mapping
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

NOISE_RULES = {"920350"}  # ndak terlalu butuh ini, cuman warn karena ga pake domain doang

def get_attack_types(messages):
    """Ekstrak attack types dari messages, ignore noise rules dan anomaly threshold."""
    types = set()
    for m in messages:
        rule_id = m.get("details", {}).get("ruleId", "")
        if rule_id in NOISE_RULES:
            continue
        if rule_id == "949110" or rule_id == "980130":
            continue
        category = RULE_CATEGORIES.get(rule_id, f"Other ({rule_id})")
        types.add(category)
    return types

def classify_transaction(messages):
    """Klasifikasikan transaksi: normal atau attack (+ tipenya)."""
    attack_types = get_attack_types(messages)
    if not attack_types:
        return "Normal", set()
    return "Malicious", attack_types

def parse_log(filepath):
    """Parse audit log dan return list of transactions."""
    transactions = []
    errors = 0
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                transactions.append(entry)
            except json.JSONDecodeError:
                errors += 1
    return transactions, errors

def summarize(transactions):
    """Generate summary statistics."""
    total = len(transactions)
    normal = 0
    malicious = 0
    attack_type_counts = defaultdict(int)
    rule_counts = defaultdict(int)
    uri_counts = defaultdict(int)
    ip_counts = defaultdict(int)
    method_counts = defaultdict(int)
    status_counts = defaultdict(int)

    for entry in transactions:
        t = entry.get("transaction", {})
        msgs = t.get("messages", [])
        uri = t.get("request", {}).get("uri", "-")
        method = t.get("request", {}).get("method", "-")
        client_ip = t.get("client_ip", "-")
        status = t.get("response", {}).get("http_code", "-")

        label, attack_types = classify_transaction(msgs)

        uri_counts[uri] += 1
        ip_counts[client_ip] += 1
        method_counts[method] += 1
        status_counts[str(status)] += 1

        if label == "Normal":
            normal += 1
        else:
            malicious += 1
            for at in attack_types:
                attack_type_counts[at] += 1

        for m in msgs:
            rule_id = m.get("details", {}).get("ruleId", "")
            if rule_id and rule_id not in NOISE_RULES:
                rule_counts[rule_id] += 1

    return {
        "total": total,
        "normal": normal,
        "malicious": malicious,
        "attack_type_counts": dict(attack_type_counts),
        "rule_counts": dict(rule_counts),
        "uri_counts": dict(uri_counts),
        "ip_counts": dict(ip_counts),
        "method_counts": dict(method_counts),
        "status_counts": dict(status_counts),
    }

def print_summary(summary, show_detail=False):
    total = summary["total"]
    normal = summary["normal"]
    malicious = summary["malicious"]

    print("=" * 55)
    print("   ModSecurity Audit Log - Summary")
    print("=" * 55)
    print(f"  Total Traffic   : {total}")
    print(f"  Normal          : {normal} ({normal/total*100:.1f}%)" if total else "  Normal          : 0")
    print(f"  Malicious       : {malicious} ({malicious/total*100:.1f}%)" if total else "  Malicious       : 0")
    print()

    if summary["attack_type_counts"]:
        print("  Attack Types Detected:")
        for atype, count in sorted(summary["attack_type_counts"].items(), key=lambda x: -x[1]):
            print(f"    {atype:<20} : {count}")
        print()

    if show_detail:
        print("  HTTP Methods:")
        for method, count in sorted(summary["method_counts"].items(), key=lambda x: -x[1]):
            print(f"    {method:<10} : {count}")
        print()

        print("  Response Status Codes:")
        for status, count in sorted(summary["status_counts"].items(), key=lambda x: -x[1]):
            print(f"    {status:<10} : {count}")
        print()

        print("  Top 10 URIs:")
        for uri, count in sorted(summary["uri_counts"].items(), key=lambda x: -x[1])[:10]:
            print(f"    {count:>5}x  {uri}")
        print()

        print("  Top 10 Client IPs:")
        for ip, count in sorted(summary["ip_counts"].items(), key=lambda x: -x[1])[:10]:
            print(f"    {count:>5}x  {ip}")
        print()

        if summary["rule_counts"]:
            print("  Top Rules Triggered:")
            for rule, count in sorted(summary["rule_counts"].items(), key=lambda x: -x[1])[:10]:
                category = RULE_CATEGORIES.get(rule, "Unknown")
                print(f"    Rule {rule} ({category:<20}) : {count}x")
        print()

    print("=" * 55)

def main():
    parser = argparse.ArgumentParser(
        description="ModSecurity Audit Log Summary Tool"
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        default="/var/log/modsecurity/audit.log",
        help="Path ke audit log (default: /var/log/modsecurity/audit.log)"
    )
    parser.add_argument(
        "-d", "--detail",
        action="store_true",
        help="Tampilkan detail lengkap (URI, IP, methods, rules)"
    )
    args = parser.parse_args()

    print(f"\nParsing: {args.logfile}")
    print(f"Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    try:
        transactions, errors = parse_log(args.logfile)
    except FileNotFoundError:
        print(f"ERROR: File tidak ditemukan: {args.logfile}")
        sys.exit(1)

    if errors:
        print(f"  WARNING: {errors} baris gagal di-parse (skip)\n")

    if not transactions:
        print("  Audit log kosong atau tidak ada transaksi.")
        sys.exit(0)

    summary = summarize(transactions)
    print_summary(summary, show_detail=args.detail)

if __name__ == "__main__":
    main()
