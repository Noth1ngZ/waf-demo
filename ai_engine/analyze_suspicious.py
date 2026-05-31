import json
import os
from datetime import datetime

SUSPICIOUS_LOG = "/root/waf-demo/logs/suspicious.log"
OUTPUT_FILE = "/root/waf-demo/ai_engine/ai_suggestions.json"


def load_suspicious_logs():
    logs = []

    if not os.path.exists(SUSPICIOUS_LOG):
        print("[!] suspicious.log 不存在")
        return logs

    with open(SUSPICIOUS_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                logs.append(json.loads(line))
            except json.JSONDecodeError:
                print("[!] 跳过一行无法解析的日志:", line)

    return logs


def analyze_one(log):
    uri = log.get("uri", "")
    reasons = log.get("reasons", [])
    score = log.get("risk_score", 0)

    suggestion = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_uri": uri,
        "risk_score": score,
        "reasons": reasons,
        "risk_type": "unknown",
        "suggest_rule": None,
        "explain": ""
    }

    for reason in reasons:
        if "possible_sql_keyword" in reason:
            suggestion["risk_type"] = "possible_sql_injection"
            suggestion["suggest_rule"] = {
                "target": "args_value",
                "pattern": "sleep\\(|benchmark\\(|or\\s+1=1",
                "action": "block",
                "level": "medium"
            }
            suggestion["explain"] = "请求参数中出现 SQL 注入相关关键词，建议加入更精确的 SQL 注入检测规则。"
            return suggestion

    for reason in reasons:
        if "possible_base64_value" in reason:
            suggestion["risk_type"] = "possible_encoded_payload"
            suggestion["suggest_rule"] = {
                "target": "args_value",
                "pattern": "^[A-Za-z0-9+/=]{30,}$",
                "action": "block",
                "level": "medium"
            }
            suggestion["explain"] = "请求参数值疑似长 Base64 编码内容，可能用于隐藏攻击载荷，建议作为可疑编码特征继续观察。"
            return suggestion

    for reason in reasons:
        if "suspicious_arg_name" in reason:
            suggestion["risk_type"] = "suspicious_parameter_name"
            suggestion["suggest_rule"] = {
                "target": "args_name",
                "pattern": "payload|data|file|path|url",
                "action": "block",
                "level": "low"
            }
            suggestion["explain"] = "请求中出现 file、path、url、data、payload 等敏感参数名，建议结合参数值进一步判断，暂不建议直接强拦。"
            return suggestion

    suggestion["explain"] = "该请求存在一定异常特征，但暂未提取到稳定规则，建议继续观察。"
    return suggestion


def save_suggestions(suggestions):
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(suggestions, f, ensure_ascii=False, indent=2)

    print(f"[+] 已生成规则建议: {OUTPUT_FILE}")


def main():
    logs = load_suspicious_logs()

    if not logs:
        print("[!] 没有可疑日志可分析")
        return

    suggestions = []

    for log in logs:
        suggestions.append(analyze_one(log))

    save_suggestions(suggestions)

    print("[+] 分析完成，共分析", len(logs), "条可疑日志")


if __name__ == "__main__":
    main()