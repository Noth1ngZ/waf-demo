local cjson = require "cjson"

local rule_file = "/root/waf-demo/rules/rules.json"
local waf_log_file = "/root/waf-demo/logs/waf.log"
local suspicious_log_file = "/root/waf-demo/logs/suspicious.log"

local ip_risk_dict = ngx.shared.waf_ip_risk

local HIGH_RISK_SCORE = 60
local BLOCK_SCORE = 80
local RISK_COUNT_LIMIT = 3
local RISK_COUNT_WINDOW = 300
local IP_BLOCK_TIME = 600


local function read_file(path)
    local file = io.open(path, "r")
    if not file then
        ngx.log(ngx.ERR, "WAF ERROR: cannot open file: ", path)
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
    local ok, line = pcall(cjson.encode, data)

    if not ok then
        ngx.log(ngx.ERR, "WAF ERROR: json encode failed")
        return
    end

    local file = io.open(path, "a")
    if file then
        file:write(line .. "\n")
        file:close()
    else
        ngx.log(ngx.ERR, "WAF ERROR: cannot write log file: ", path)
    end
end


local function match_rule(text, pattern)
    if not text or not pattern then
        return false
    end

    local from, err = ngx.re.find(text, pattern, "ijo")
    if from then
        return true
    end

    if err then
        ngx.log(ngx.ERR, "WAF REGEX ERROR: pattern=", pattern, ", err=", err)
    end

    return false
end


local function get_post_body()
    ngx.req.read_body()

    local body_data = ngx.req.get_body_data()
    if body_data then
        return body_data
    end

    -- 如果请求体太大，OpenResty 可能会把 body 写入临时文件。
    -- 当前原型阶段不读取临时文件内容，避免性能和安全问题。
    return ""
end


local function get_request_info(post_body)
    post_body = post_body or ""

    return {
        time = ngx.localtime(),
        ip = ngx.var.remote_addr or "",
        method = ngx.req.get_method() or "",
        uri = ngx.var.request_uri or "",
        host = ngx.var.host or "",
        user_agent = ngx.var.http_user_agent or "",
        post_body_length = string.len(post_body)
    }
end


local function block_request(rule, post_body)
    local log_data = get_request_info(post_body)

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
    ngx.say("Rule ID: " .. tostring(rule.id))
    ngx.say("Rule Name: " .. tostring(rule.name))
    return ngx.exit(403)
end


local function write_suspicious_log(score, reasons, post_body)
    local log_data = get_request_info(post_body)

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


local function write_ip_risk_log(ip, count, score, reasons, post_body)
    local log_data = get_request_info(post_body)

    log_data.action = "ip_risk_count"
    log_data.risk_ip = ip
    log_data.risk_count = count
    log_data.risk_score = score
    log_data.reasons = reasons
    log_data.risk_count_window = RISK_COUNT_WINDOW

    write_json_log(waf_log_file, log_data)

    ngx.log(
        ngx.ERR,
        "WAF IP RISK: ip=", ip,
        ", count=", count,
        ", score=", score,
        ", reasons=", table.concat(reasons, ","),
        ", uri=", ngx.var.request_uri
    )
end


local function write_ip_block_log(ip, count, score, reasons, post_body)
    local log_data = get_request_info(post_body)

    log_data.action = "ip_temp_block"
    log_data.blocked_ip = ip
    log_data.risk_count = count
    log_data.risk_score = score
    log_data.reasons = reasons
    log_data.block_time = IP_BLOCK_TIME

    write_json_log(waf_log_file, log_data)

    ngx.log(
        ngx.ERR,
        "WAF IP TEMP BLOCK: ip=", ip,
        ", count=", count,
        ", score=", score,
        ", block_time=", IP_BLOCK_TIME,
        ", reasons=", table.concat(reasons, ","),
        ", uri=", ngx.var.request_uri
    )
end


local function check_ip_blocked(post_body)
    local ip = ngx.var.remote_addr or ""
    if ip == "" or not ip_risk_dict then
        return false
    end

    local blocked = ip_risk_dict:get("blocked_ip:" .. ip)
    if blocked then
        block_request({
            id = 9100,
            name = "temporary_blocked_ip",
            level = "high"
        }, post_body)
        return true
    end

    return false
end


local function record_high_risk_ip(score, reasons, post_body)
    if score < HIGH_RISK_SCORE then
        return false, 0
    end

    local ip = ngx.var.remote_addr or ""
    if ip == "" then
        ngx.log(ngx.ERR, "WAF IP RISK ERROR: remote_addr is empty")
        return false, 0
    end

    if not ip_risk_dict then
        ngx.log(ngx.ERR, "WAF IP RISK ERROR: shared dict waf_ip_risk is unavailable")
        return false, 0
    end

    local risk_key = "risk_count:" .. ip
    local ok, add_err = ip_risk_dict:add(risk_key, 1, RISK_COUNT_WINDOW)
    local count = 1

    if not ok then
        local err
        count, err = ip_risk_dict:incr(risk_key, 1)
        if not count then
            ngx.log(ngx.ERR, "WAF IP RISK ERROR: failed to increment risk count for ip=", ip, ", add_err=", add_err, ", incr_err=", err)
            return false, 0
        end
    end

    write_ip_risk_log(ip, count, score, reasons, post_body)

    if count >= RISK_COUNT_LIMIT then
        local ok, set_err = ip_risk_dict:set("blocked_ip:" .. ip, true, IP_BLOCK_TIME)
        if not ok then
            ngx.log(ngx.ERR, "WAF IP RISK ERROR: failed to block ip=", ip, ", err=", set_err)
            return false, count
        end

        write_ip_block_log(ip, count, score, reasons, post_body)
        return true, count
    end

    return false, count
end


local function table_value_to_string(value)
    if type(value) == "table" then
        return table.concat(value, ",")
    end

    if value == nil then
        return ""
    end

    return tostring(value)
end


local function calc_risk_score(args, uri, ua, post_body)
    local score = 0
    local reasons = {}

    -- 1. URI 中出现敏感入口关键词
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

    -- 3. 参数值可疑
    for key, value in pairs(args) do
        local v = table_value_to_string(value)

        -- 长 Base64 风格字符串
        if match_rule(v, "^[A-Za-z0-9+/=]{20,}$") then
            score = score + 25
            table.insert(reasons, "possible_base64_value:" .. key)
        end

        -- URL 编码痕迹
        if match_rule(v, "%%[0-9A-Fa-f][0-9A-Fa-f]") then
            score = score + 15
            table.insert(reasons, "url_encoded_value:" .. key)
        end

        -- SQL 关键词，仅标记可疑，不直接强拦
        if match_rule(v, "select|union|sleep|benchmark|or%s+1=1") then
            score = score + 30
            table.insert(reasons, "possible_sql_keyword:" .. key)
        end
    end

    -- 4. User-Agent 异常
    if ua == "" then
        score = score + 10
        table.insert(reasons, "empty_user_agent")
    elseif string.len(ua) < 8 then
        score = score + 10
        table.insert(reasons, "short_user_agent")
    end

    -- 5. POST Body 可疑特征
    if post_body and post_body ~= "" then
        -- POST Body 中出现系统命令
        if match_rule(post_body, "whoami|uname|id|pwd|ifconfig|ipconfig|netstat|bash|sh") then
            score = score + 40
            table.insert(reasons, "post_body_command_keyword")
        end

        -- POST Body 中出现敏感文件路径
        if match_rule(post_body, "/etc/passwd|/etc/shadow|/root/.ssh|id_rsa") then
            score = score + 40
            table.insert(reasons, "post_body_sensitive_file")
        end

        -- POST Body 疑似长 Base64 / 加密载荷
        if match_rule(post_body, "[A-Za-z0-9+/=]{30,}") then
            score = score + 30
            table.insert(reasons, "post_body_possible_encoded_payload")
        end

        -- POST Body 中出现 PHP 危险函数
        if match_rule(post_body, "eval\\(|assert\\(|system\\(|shell_exec\\(|passthru\\(|base64_decode\\(") then
            score = score + 40
            table.insert(reasons, "post_body_php_dangerous_function")
        end

        -- POST Body 中出现常见 WebShell 管理工具相关关键词
        if match_rule(post_body, "Godzilla|Behinder|AntSword|rebeyond|pass=|password=|payload=") then
            score = score + 30
            table.insert(reasons, "post_body_webshell_keyword")
        end
    end

    return score, reasons
end


local function check_static_rules(rules, args, uri, ua, post_body)
    for _, rule in ipairs(rules) do
        if rule.target == "args_name" then
            for key, value in pairs(args) do
                if match_rule(key, rule.pattern) then
                    block_request(rule, post_body)
                end
            end

        elseif rule.target == "args_value" then
            for key, value in pairs(args) do
                if type(value) == "table" then
                    for _, v in ipairs(value) do
                        if match_rule(v, rule.pattern) then
                            block_request(rule, post_body)
                        end
                    end
                else
                    if match_rule(value, rule.pattern) then
                        block_request(rule, post_body)
                    end
                end
            end

        elseif rule.target == "uri" then
            if match_rule(uri, rule.pattern) then
                block_request(rule, post_body)
            end

        elseif rule.target == "user_agent" then
            if match_rule(ua, rule.pattern) then
                block_request(rule, post_body)
            end

        elseif rule.target == "post_body" then
            if match_rule(post_body, rule.pattern) then
                block_request(rule, post_body)
            end
        end
    end
end


-- 主流程开始

local rules = load_rules()

local args = ngx.req.get_uri_args()
local uri = ngx.var.request_uri or ""
local ua = ngx.var.http_user_agent or ""
local post_body = get_post_body()

-- 第一层：先检查当前 IP 是否已经被临时封禁
check_ip_blocked(post_body)

-- 第二层：静态规则强拦截
check_static_rules(rules, args, uri, ua, post_body)

-- 第三层：未命中强拦截规则时，进行风险评分
local score, reasons = calc_risk_score(args, uri, ua, post_body)

if score >= BLOCK_SCORE then
    record_high_risk_ip(score, reasons, post_body)
    write_suspicious_log(score, reasons, post_body)
    block_request({
        id = 9200,
        name = "high_risk_score_block",
        level = "high"
    }, post_body)
elseif score >= HIGH_RISK_SCORE then
    local blocked_now = record_high_risk_ip(score, reasons, post_body)
    write_suspicious_log(score, reasons, post_body)

    if blocked_now then
        block_request({
            id = 9100,
            name = "temporary_blocked_ip",
            level = "high"
        }, post_body)
    end
elseif score >= 30 then
    write_suspicious_log(score, reasons, post_body)
end
