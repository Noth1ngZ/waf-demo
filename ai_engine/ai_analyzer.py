import json
import os
from datetime import datetime
from openai import OpenAI

SUSPICIOUS_LOG = "/root/waf-demo/logs/suspicious.log"
OUTPUT_FILE = "/root/waf-demo/ai_engine/ai_suggestions.json"

client = OpenAI()


def load_suspicious_logs(limit=10):
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
                print("[!] 跳过无法解析的日志:", line)

    return logs[-limit:]


def build_prompt(log):
    return f"""
你是一个 Web 安全 WAF 规则分析助手。

请分析下面这条可疑 HTTP 请求日志，并生成一条候选 WAF 规则建议。

要求：
1. 只输出 JSON,不要输出解释性文字。
2. JSON 必须包含：
   - risk_type
   - confidence
   - reason
   - suggest_rule
   - auto_apply
3. confidence 范围是 0 到 1。
4. suggest_rule 必须包含：
   - target
   - pattern
   - action
   - level
   - description
5. target 只能是：
   - args_name
   - args_value
   - uri
   - user_agent
6. action 固定为 "block"。
7. level 只能是 "low"、"medium"、"high"。
8. 不要生成过于宽泛、容易误报的规则。
9. 不要直接把 select、admin、api 作为强拦截规则。
10. 如果不适合生成规则,suggest_rule 设置为 null,auto_apply 设置为 false。
11. 规则要适配当前 WAF 的 rules.json 格式。
12. pattern 使用 Lua ngx.re.find 可兼容的正则，不要使用过于复杂的语法。

可疑日志如下：

{json.dumps(log, ensure_ascii=False, indent=2)}

请输出 JSON,例如：

{{
  "risk_type": "possible_sql_injection",
  "confidence": 0.82,
  "reason": "参数中出现疑似 SQL 注入特征，但需要避免误报。",
  "suggest_rule": {{
    "target": "args_value",
    "pattern": "sleep\\\\(|benchmark\\\\(|or\\\\s+1=1",
    "action": "block",
    "level": "medium",
    "description": "检测较明确的 SQL 注入时间盲注或恒真条件特征"
  }},
  "auto_apply": false
}}
"""


def parse_ai_json(text):
    text = text.strip()

    # 兼容 AI 返回 ```json ... ``` 的情况
    if text.startswith("```"):
        text = text.strip("`").strip()
        if text.startswith("json"):
            text = text[4:].strip()

    return json.loads(text)


def analyze_with_ai(log):
    prompt = build_prompt(log)

    response = client.responses.create(
        model="gpt-5.5",
        input=prompt
    )

    raw_text = response.output_text

    try:
        result = parse_ai_json(raw_text)
    except Exception as e:
        result = {
            "risk_type": "ai_parse_error",
            "confidence": 0,
            "reason": f"AI 输出解析失败: {str(e)}",
            "raw_output": raw_text,
            "suggest_rule": None,
            "auto_apply": False
        }

    result["source_uri"] = log.get("uri", "")
    result["source_reasons"] = log.get("reasons", [])
    result["source_risk_score"] = log.get("risk_score", 0)
    result["source_ip"] = log.get("ip", "")
    result["source_user_agent"] = log.get("user_agent", "")
    result["analyze_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return result


def save_suggestions(suggestions):
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(suggestions, f, ensure_ascii=False, indent=2)

    print(f"[+] AI 分析结果已保存: {OUTPUT_FILE}")


def main():
    logs = load_suspicious_logs(limit=10)

    if not logs:
        print("[!] 没有可疑日志可分析")
        return

    suggestions = []

    for i, log in enumerate(logs, start=1):
        print(f"[*] 正在分析第 {i}/{len(logs)} 条可疑日志...")
        suggestion = analyze_with_ai(log)
        suggestions.append(suggestion)

    save_suggestions(suggestions)
    print(f"[+] 完成，共分析 {len(suggestions)} 条日志")


if __name__ == "__main__":
    main()