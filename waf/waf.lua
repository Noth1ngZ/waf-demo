local cjson = require "cjson"

local rule_file = "/root/waf-demo/rules/rules.json"
local waf_log_file = "/root/waf-demo/logs/waf.log"
local suspicious_log_file = "/root/waf-demo/logs/suspicious.log"

local function read_file(path)
    local file = io.open(path, "r")
    if not file then
        ngx.log(ngx.ERR, "WAF ERROR: cannot open rule file: ", path)
        return nil
    end

    local content = file:read("*a")
    file:close()
    return content
end

local function load_rules()
    local content = read_file(rule_file)
    if not content then
        return {}
    end

    local ok, rules = pcall(cjson.decode, content)
    if not ok then
        ngx.log(ngx.ERR, "WAF ERROR: json decode failed")
        return {}
    end

    return rules
end

local function write_json_log(path, data)
    local line = cjson.encode(data)

    local file = io.open(path, "a")
    if file then
        file:write(line .. "\n")
        file:close()
    else
        ngx.log(ngx.ERR, "WAF ERROR: cannot write log file: ", path)
    end
end

local function get_request_info()
    return {
        time = ngx.localtime(),
        ip = ngx.var.remote_addr or "",
        method = ngx.req.get_method() or "",
        uri = ngx.var.request_uri or "",
        user_agent = ngx.var.http_user_agent or "",
        host = ngx.var.host or ""
    }
end

local function block_request(rule)
    local log_data = get_request_info()

    log_data.rule_id = rule.id
    log_data.rule_name = rule.name
    log_data.level = rule.level
    log_data.action = "block"

    write_json_log(waf_log_file, log_data)

    ngx.log(
        ngx.ERR,
        "WAF BLOCK: rule_id=", rule.id,
        ", rule_name=", rule.name,
        ", level=", rule.level,
        ", uri=", ngx.var.request_uri
    )

    ngx.status = 403
    ngx.say("Blocked by WAF")
    ngx.say("Rule ID: " .. rule.id)
    ngx.say("Rule Name: " .. rule.name)
    return ngx.exit(403)
end

local function write_suspicious_log(score, reasons)
    local log_data = get_request_info()

    log_data.risk_score = score
    log_data.reasons = reasons
    log_data.action = "suspicious_pass"

    write_json_log(suspicious_log_file, log_data)

    ngx.log(
        ngx.ERR,
        "WAF SUSPICIOUS: score=", score,
        ", reasons=", table.concat(reasons, ","),
        ", uri=", ngx.var.request_uri
    )
end

local function match_rule(text, pattern)
    if not text or not pattern then
        return false
    end

    local from, err = ngx.re.find(text, pattern, "ijo")
    if from then
        return true
    end

    return false
end

local function calc_risk_score(args, uri, ua)
    local score = 0
    local reasons = {}

    -- 1. URI 中出现敏感关键词，但未必直接拦截
    if match_rule(uri, "admin|upload|api|debug|test") then
        score = score + 20
        table.insert(reasons, "sensitive_uri_keyword")
    end

    -- 2. 参数名可疑
    for key, value in pairs(args) do
        if match_rule(key, "file|path|url|data|payload|token") then
            score = score + 20
            table.insert(reasons, "suspicious_arg_name:" .. key)
        end
    end

    -- 3. 参数值疑似编码内容
    for key, value in pairs(args) do
        local v = value

        if type(v) == "table" then
            v = table.concat(v, ",")
        end

        if type(v) == "string" then
            -- 长 Base64 风格字符串
            if match_rule(v, "^[A-Za-z0-9+/=]{20,}$") then
                score = score + 25
                table.insert(reasons, "possible_base64_value:" .. key)
            end

            -- URL 编码痕迹
            if match_rule(v, "%x%x") and match_rule(v, "%%") then
                score = score + 15
                table.insert(reasons, "url_encoded_value:" .. key)
            end

            -- 出现 SQL 关键词，先标记为可疑，不直接拦
            if match_rule(v, "select|union|sleep|benchmark|or 1=1") then
                score = score + 30
                table.insert(reasons, "possible_sql_keyword:" .. key)
            end
        end
    end

    -- 4. User-Agent 缺失或过短
    if ua == "" then
        score = score + 10
        table.insert(reasons, "empty_user_agent")
    elseif string.len(ua) < 8 then
        score = score + 10
        table.insert(reasons, "short_user_agent")
    end

    return score, reasons
end

local rules = load_rules()

local args = ngx.req.get_uri_args()
local uri = ngx.var.request_uri or ""
local ua = ngx.var.http_user_agent or ""

-- 第一层：静态规则直接拦截
for _, rule in ipairs(rules) do
    if rule.target == "args_name" then
        for key, value in pairs(args) do
            if match_rule(key, rule.pattern) then
                block_request(rule)
            end
        end

    elseif rule.target == "args_value" then
        for key, value in pairs(args) do
            if type(value) == "table" then
                for _, v in ipairs(value) do
                    if match_rule(v, rule.pattern) then
                        block_request(rule)
                    end
                end
            else
                if match_rule(value, rule.pattern) then
                    block_request(rule)
                end
            end
        end

    elseif rule.target == "uri" then
        if match_rule(uri, rule.pattern) then
            block_request(rule)
        end

    elseif rule.target == "user_agent" then
        if match_rule(ua, rule.pattern) then
            block_request(rule)
        end
    end
end

-- 第二层：未命中拦截规则，但计算风险分
local score, reasons = calc_risk_score(args, uri, ua)

-- 30 分以上：可疑，放行但记录
if score >= 30 then
    write_suspicious_log(score, reasons)
end