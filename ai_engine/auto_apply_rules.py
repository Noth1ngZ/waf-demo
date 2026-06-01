import json
import os
import shutil
from datetime import datetime

RULE_FILE = "/root/waf-demo/rules/rules.json"
SUGGEST_FILE = "/root/waf-demo/ai_engine/ai_suggestions.json"

PENDING_FILE = "/root/waf-demo/ai_engine/pending_rules.json"
REJECTED_FILE = "/root/waf-demo/ai_engine/rejected_rules.json"

BACKUP_DIR = "/root/waf-demo/rules/backups"

ALLOW_TARGETS = {"args_name", "args_value", "uri", "user_agent", "post_body"}
ALLOW_LEVELS = {"low", "medium", "high"}

DANGEROUS_BROAD_PATTERNS = [
    "file",
    "data",
    "url",
    "path",
    "select",
    "admin",
    "api",
    "test",
    "upload",
    "pass",
    "password"
]


def load_json(path, default):
    if not os.path.exists(path):
        return default

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def backup_rules():
    os.makedirs(BACKUP_DIR, exist_ok=True)

    time_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"rules_{time_str}.json")

    shutil.copy2(RULE_FILE, backup_path)

    print(f"[+] 已备份原规则库: {backup_path}")


def get_next_rule_id(rules):
    if not rules:
        return 1001

    return max(rule.get("id", 1000) for rule in rules) + 1


def rule_exists(rules, new_rule):
    for rule in rules:
        if (
            rule.get("target") == new_rule.get("target")
            and rule.get("pattern") == new_rule.get("pattern")
        ):
            return True

    return False


def is_pattern_too_broad(pattern):
    if not pattern:
        return True

    clean_pattern = pattern.lower().strip()

    for broad in DANGEROUS_BROAD_PATTERNS:
        if clean_pattern == broad:
            return True

    if len(clean_pattern) <= 3:
        return True

    if clean_pattern.isalpha() and "|" not in clean_pattern and "\\" not in clean_pattern:
        return True

    return False


def build_rule(suggestion, rule_id):
    suggest_rule = suggestion.get("suggest_rule")

    if not suggest_rule:
        return None, "no_suggest_rule"

    target = suggest_rule.get("target")
    pattern = suggest_rule.get("pattern")
    action = suggest_rule.get("action", "block")
    level = suggest_rule.get("level", "medium")
    description = suggest_rule.get("description", suggestion.get("reason", "AI 分析可疑日志后生成的规则"))

    if target not in ALLOW_TARGETS:
        return None, "invalid_target"

    if level not in ALLOW_LEVELS:
        return None, "invalid_level"

    if action != "block":
        return None, "invalid_action"

    if not pattern:
        return None, "empty_pattern"

    if is_pattern_too_broad(pattern):
        return None, "pattern_too_broad"

    risk_type = suggestion.get("risk_type", "unknown")

    rule = {
        "id": rule_id,
        "name": "ai_auto_" + risk_type,
        "target": target,
        "pattern": pattern,
        "action": "block",
        "level": level,
        "description": description
    }

    return rule, "ok"


def should_auto_apply(suggestion, rule):
    confidence = float(suggestion.get("confidence", 0))
    auto_apply = suggestion.get("auto_apply", False)

    if auto_apply is True and confidence >= 0.85:
        return True

    return False


def main():
    rules = load_json(RULE_FILE, [])
    suggestions = load_json(SUGGEST_FILE, [])

    if not suggestions:
        print("[!] 没有 AI 建议规则，请先运行 ai_analyzer.py")
        return

    auto_rules = []
    pending_rules = []
    rejected_rules = []

    next_id = get_next_rule_id(rules)

    for suggestion in suggestions:
        rule, reason = build_rule(suggestion, next_id)

        if not rule:
            suggestion["reject_reason"] = reason
            rejected_rules.append(suggestion)
            print(f"[-] 拒绝规则建议: {reason}")
            continue

        if rule_exists(rules, rule):
            suggestion["reject_reason"] = "rule_already_exists"
            rejected_rules.append(suggestion)
            print(f"[-] 规则已存在，跳过: {rule['pattern']}")
            continue

        if should_auto_apply(suggestion, rule):
            auto_rules.append(rule)
            rules.append(rule)
            next_id += 1
            print(f"[+] 自动加入规则: {rule['name']} | {rule['pattern']}")
        else:
            suggestion["pending_rule"] = rule
            suggestion["pending_reason"] = "confidence_or_auto_apply_not_enough"
            pending_rules.append(suggestion)
            print(f"[*] 进入待审核队列: {rule['pattern']}")

    if auto_rules:
        backup_rules()
        save_json(RULE_FILE, rules)
        print(f"[+] 已自动更新规则库，新增 {len(auto_rules)} 条规则")
    else:
        print("[*] 没有规则自动加入 rules.json")

    save_json(PENDING_FILE, pending_rules)
    save_json(REJECTED_FILE, rejected_rules)

    print(f"[+] 待审核规则已写入: {PENDING_FILE}")
    print(f"[+] 拒绝规则已写入: {REJECTED_FILE}")
    print("[+] 分级自动更新完成")


if __name__ == "__main__":
    main()