import json
import os

RULE_FILE = "/root/waf-demo/rules/rules.json"
SUGGEST_FILE = "/root/waf-demo/ai_engine/ai_suggestions.json"
OUTPUT_FILE = "/root/waf-demo/ai_engine/reviewed_rules.json"


def load_json(path, default):
    if not os.path.exists(path):
        print(f"[!] 文件不存在: {path}")
        return default

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def get_next_rule_id(rules):
    if not rules:
        return 1001

    max_id = max(rule.get("id", 1000) for rule in rules)
    return max_id + 1


def build_rule_from_suggestion(suggestion, rule_id):
    suggest_rule = suggestion.get("suggest_rule")

    if not suggest_rule:
        return None

    allow_targets = {"args_name", "args_value", "uri", "user_agent", "post_body"}

    target = suggest_rule.get("target")
    pattern = suggest_rule.get("pattern")
    action = suggest_rule.get("action", "block")
    level = suggest_rule.get("level", "medium")
    description = suggest_rule.get("description", suggestion.get("reason", "AI 分析可疑日志后生成的规则建议"))

    if target not in allow_targets:
        print(f"[-] 不支持的 target，跳过: {target}")
        return None

    if not pattern:
        print("[-] pattern 为空，跳过")
        return None

    rule = {
        "id": rule_id,
        "name": "ai_suggest_" + suggestion.get("risk_type", "unknown"),
        "target": target,
        "pattern": pattern,
        "action": action,
        "level": level,
        "description": description
    }

    return rule


def rule_exists(rules, new_rule):
    for rule in rules:
        if (
            rule.get("target") == new_rule.get("target")
            and rule.get("pattern") == new_rule.get("pattern")
        ):
            return True
    return False


def main():
    rules = load_json(RULE_FILE, [])
    suggestions = load_json(SUGGEST_FILE, [])

    if not suggestions:
        print("[!] 没有可用的规则建议")
        return

    new_rules = []
    next_id = get_next_rule_id(rules)

    for suggestion in suggestions:
        rule = build_rule_from_suggestion(suggestion, next_id)

        if not rule:
            continue

        if rule_exists(rules, rule):
            print(f"[-] 规则已存在，跳过: {rule['pattern']}")
            continue

        print("\n发现一条建议规则：")
        print(json.dumps(rule, ensure_ascii=False, indent=2))

        choice = input("是否加入规则库？[y/N]: ").strip().lower()

        if choice == "y":
            new_rules.append(rule)
            next_id += 1
            print("[+] 已加入待审核规则")
        else:
            print("[-] 已跳过")

    reviewed_rules = rules + new_rules

    save_json(OUTPUT_FILE, reviewed_rules)

    print("\n[+] 审核完成")
    print(f"[+] 新增规则数量: {len(new_rules)}")
    print(f"[+] 已生成审核后规则文件: {OUTPUT_FILE}")
    print("[!] 注意：目前还没有覆盖 rules.json，需要你确认后手动替换")


if __name__ == "__main__":
    main()