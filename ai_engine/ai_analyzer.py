import json
import os
from datetime import datetime
from openai import OpenAI

SUSPICIOUS_LOG = "/root/waf-demo/logs/suspicious.log"
OUTPUT_FILE = "/root/waf-demo/ai_engine/ai_suggestions.json"

client = OpenAI(
    api_key=os.getenv("DASHSCOPE_API_KEY"),
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1"
)


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
1. 只输出 JSON，不要输出解释性文字。
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
   - post_body
6. action 固定为 "block"。
7. level 只能是：
   - low
   - medium
   - high
8. 不要生成过于宽泛、容易误报的规则。
9. 不要直接把 select、admin、api 作为强拦截规则。
10. 如果不适合生成规则，suggest_rule 设置为 null，auto_apply 设置为 false。
11. 规则要适配当前 WAF 的 rules.json 格式。
12. pattern 使用 Lua ngx.re.find 可兼容的正则，不要使用过于复杂的语法。
13. 如果只是普通业务参数名，例如 file、url、data，不要直接生成强拦截规则。
14. 优先生成低误报规则，例如明确的命令执行、WebShell、敏感文件、SQL 时间盲注、POST Body 中的 WebShell 通信特征。
15. 如果可疑原因与 POST 请求体相关，例如 post_body_command_keyword、post_body_sensitive_file、post_body_possible_encoded_payload、post_body_php_dangerous_function、post_body_webshell_keyword，优先考虑生成 target 为 post_body 的规则。
16. 如果只是长 Base64 或疑似编码内容，除非置信度很高，否则 auto_apply 应为 false。

可疑日志如下：

{json.dumps(log, ensure_ascii=False, indent=2)}

请严格输出 JSON，例如：

{{
  "risk_type": "possible_webshell_post_payload",
  "confidence": 0.86,
  "reason": "POST 请求体中出现 WebShell 管理工具常见参数和编码载荷特征，疑似 WebShell 通信。",
  "suggest_rule": {{
    "target": "post_body",
    "pattern": "pass=|password=|payload=|rebeyond|Godzilla|Behinder|AntSword",
    "action": "block",
    "level": "medium",
    "description": "检测 POST 请求体中的常见 WebShell 管理工具参数或标识"
  }},
  "auto_apply": false
}}
"""


def parse_ai_json(text):
    text = text.strip()

    if text.startswith("```"):
        text = text.strip("`").strip()
        if text.startswith("json"):
            text = text[4:].strip()

    return json.loads(text)


def analyze_with_ai(log):
    prompt = build_prompt(log)

    response = client.chat.completions.create(
        model="qwen-plus",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.2
    )

    raw_text = response.choices[0].message.content

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
    result["source_post_body_length"] = log.get("post_body_length", 0)
    result["analyze_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return result


def save_suggestions(suggestions):
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(suggestions, f, ensure_ascii=False, indent=2)

    print(f"[+] AI 分析结果已保存: {OUTPUT_FILE}")


def main():
    if not os.getenv("DASHSCOPE_API_KEY"):
        print("[!] 未设置 DASHSCOPE_API_KEY")
        print('示例：export DASHSCOPE_API_KEY="你的百炼API_KEY"')
        return

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