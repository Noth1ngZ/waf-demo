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

local record_high_risk_ip


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


local function mask_sensitive_value(text)
    if not text or text == "" then
        return ""
    end

    local masked = tostring(text)
    local patterns = {
        [=[(^|[\r\n])((?:Authorization))\s*:\s*[^\r\n]+]=],
        [=[(^|[\r\n;&?\s])((?:sessionid|session|token|authorization|jwt|auth|PHPSESSID|JSESSIONID))\s*=\s*[^;\r\n\s]+]=]
    }

    for _, pattern in ipairs(patterns) do
        local result, _, err = ngx.re.gsub(masked, pattern, "$1$2=[MASKED]", "ijo")
        if result then
            masked = result
        elseif err then
            ngx.log(ngx.ERR, "WAF MASK REGEX ERROR: pattern=", pattern, ", err=", err)
        end
    end

    return masked
end


local function truncate_sample(text, max_len)
    if not text or text == "" then
        return ""
    end

    max_len = max_len or 120
    text = tostring(text)

    if string.len(text) <= max_len then
        return text
    end

    return string.sub(text, 1, 60) .. "...[TRUNCATED]..." .. string.sub(text, -20)
end


local function make_safe_sample(text)
    return truncate_sample(mask_sensitive_value(text), 120)
end


local function extract_match_sample(text, pattern)
    if not text or text == "" or not pattern or pattern == "" then
        return ""
    end

    local sample_source = mask_sensitive_value(text)
    local from, to, err = ngx.re.find(sample_source, pattern, "ijo")

    if not from then
        sample_source = tostring(text)
        from, to, err = ngx.re.find(sample_source, pattern, "ijo")
    end

    if not from then
        if err then
            ngx.log(ngx.ERR, "WAF SAMPLE REGEX ERROR: pattern=", pattern, ", err=", err)
        end
        return ""
    end

    local start_pos = math.max(1, from - 30)
    local end_pos = math.min(string.len(sample_source), to + 30)
    return make_safe_sample(string.sub(sample_source, start_pos, end_pos))
end


local function add_sample(samples, area, reason, sample)
    if sample and sample ~= "" then
        table.insert(samples, {
            area = area,
            reason = reason,
            sample = sample
        })
    end
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


local function get_request_info(post_body, cookie, headers)
    post_body = post_body or ""
    cookie = cookie or ""
    headers = headers or ""

    return {
        time = ngx.localtime(),
        ip = ngx.var.remote_addr or "",
        method = ngx.req.get_method() or "",
        uri = ngx.var.request_uri or "",
        host = ngx.var.host or "",
        user_agent = ngx.var.http_user_agent or "",
        post_body_length = string.len(post_body),
        cookie_length = string.len(cookie or ""),
        headers_length = string.len(headers or "")
    }
end


local function block_request(rule, post_body, cookie, headers, matched_area, matched_sample)
    local log_data = get_request_info(post_body, cookie, headers)

    log_data.rule_id = rule.id
    log_data.rule_name = rule.name
    log_data.level = rule.level
    log_data.action = "block"
    log_data.matched_area = matched_area or ""
    log_data.matched_sample = matched_sample or ""

    write_json_log(waf_log_file, log_data)

    -- 静态规则命中也累计 IP 风险次数。
    -- rule.id = 9100 表示该 IP 已经被临时封禁后的拦截，不再重复累计。
    -- rule.id = 9200 的高风险评分拦截已在主流程中完成累计，避免重复计数。
    if rule.id ~= 9100 and rule.id ~= 9200 and record_high_risk_ip then
        local reasons = {"static_rule_hit:" .. tostring(rule.name)}
        local samples = {}
        add_sample(samples, matched_area or tostring(rule.target or ""), reasons[1], matched_sample or "")
        record_high_risk_ip(80, reasons, samples, post_body, cookie, headers)
    end

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


local function write_suspicious_log(score, reasons, samples, post_body, cookie, headers)
    local log_data = get_request_info(post_body, cookie, headers)

    log_data.risk_score = score
    log_data.reasons = reasons
    log_data.samples = samples or {}
    log_data.action = "suspicious_pass"

    write_json_log(suspicious_log_file, log_data)

    ngx.log(
        ngx.ERR,
        "WAF SUSPICIOUS: score=", score,
        ", reasons=", table.concat(reasons, ","),
        ", uri=", ngx.var.request_uri
    )
end


local function write_ip_risk_log(ip, count, score, reasons, samples, post_body, cookie, headers)
    local log_data = get_request_info(post_body, cookie, headers)

    log_data.action = "ip_risk_count"
    log_data.risk_ip = ip
    log_data.risk_count = count
    log_data.risk_score = score
    log_data.reasons = reasons
    log_data.samples = samples or {}
    log_data.risk_count_window = RISK_COUNT_WINDOW

    write_json_log(waf_log_file, log_data)

    ngx.log(
        ngx.ERR,
        "WAF IP RISK COUNT: ip=", ip,
        ", count=", count,
        ", score=", score,
        ", reasons=", table.concat(reasons, ","),
        ", uri=", ngx.var.request_uri
    )
end


local function write_ip_block_log(ip, count, score, reasons, samples, post_body, cookie, headers)
    local log_data = get_request_info(post_body, cookie, headers)

    log_data.action = "ip_temp_block"
    log_data.blocked_ip = ip
    log_data.risk_count = count
    log_data.risk_score = score
    log_data.reasons = reasons
    log_data.samples = samples or {}
    log_data.block_time = IP_BLOCK_TIME

    write_json_log(waf_log_file, log_data)

    ngx.log(
        ngx.ERR,
        "WAF IP BLOCK: ip=", ip,
        ", count=", count,
        ", score=", score,
        ", block_time=", IP_BLOCK_TIME,
        ", reasons=", table.concat(reasons, ","),
        ", uri=", ngx.var.request_uri
    )
end


local function check_ip_blocked(post_body, cookie, headers)
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
        }, post_body, cookie, headers)
        return true
    end

    return false
end


record_high_risk_ip = function(score, reasons, samples, post_body, cookie, headers)
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

    write_ip_risk_log(ip, count, score, reasons, samples, post_body, cookie, headers)

    if count >= RISK_COUNT_LIMIT then
        local ok, set_err = ip_risk_dict:set("blocked_ip:" .. ip, true, IP_BLOCK_TIME)
        if not ok then
            ngx.log(ngx.ERR, "WAF IP RISK ERROR: failed to block ip=", ip, ", err=", set_err)
            return false, count
        end

        write_ip_block_log(ip, count, score, reasons, samples, post_body, cookie, headers)
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


local function calc_risk_score(args, uri, ua, post_body, cookie, headers)
    local score = 0
    local reasons = {}
    local samples = {}

    -- 1. URI 中出现敏感入口关键词
    if match_rule(uri, "admin|upload|api|debug|test") then
        score = score + 20
        table.insert(reasons, "sensitive_uri_keyword")
        add_sample(samples, "uri", "sensitive_uri_keyword", extract_match_sample(uri, "admin|upload|api|debug|test"))
    end

    -- 2. 参数名可疑
    for key, value in pairs(args) do
        if match_rule(key, "file|path|url|data|payload|token") then
            score = score + 20
            table.insert(reasons, "suspicious_arg_name:" .. key)
            add_sample(samples, "args_name", "suspicious_arg_name:" .. key, make_safe_sample(key))
        end
    end

    -- 3. 参数值可疑
    for key, value in pairs(args) do
        local v = table_value_to_string(value)

        -- 长 Base64 风格字符串
        if match_rule(v, "^[A-Za-z0-9+/=]{20,}$") then
            score = score + 25
            table.insert(reasons, "possible_base64_value:" .. key)
            add_sample(samples, "args_value", "possible_base64_value:" .. key, make_safe_sample(tostring(key) .. "=" .. v))
        end

        -- URL 编码痕迹
        if match_rule(v, "%%[0-9A-Fa-f][0-9A-Fa-f]") then
            score = score + 15
            table.insert(reasons, "url_encoded_value:" .. key)
            add_sample(samples, "args_value", "url_encoded_value:" .. key, extract_match_sample(tostring(key) .. "=" .. v, "%%[0-9A-Fa-f][0-9A-Fa-f]"))
        end

        -- SQL 关键词，仅标记可疑，不直接强拦
        if match_rule(v, "select|union|sleep|benchmark|or%s+1=1") then
            score = score + 30
            table.insert(reasons, "possible_sql_keyword:" .. key)
            add_sample(samples, "args_value", "possible_sql_keyword:" .. key, extract_match_sample(tostring(key) .. "=" .. v, "select|union|sleep|benchmark|or%s+1=1"))
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
            add_sample(samples, "post_body", "post_body_command_keyword", extract_match_sample(post_body, "whoami|uname|id|pwd|ifconfig|ipconfig|netstat|bash|sh"))
        end

        -- POST Body 中出现敏感文件路径
        if match_rule(post_body, "/etc/passwd|/etc/shadow|/root/.ssh|id_rsa") then
            score = score + 40
            table.insert(reasons, "post_body_sensitive_file")
            add_sample(samples, "post_body", "post_body_sensitive_file", extract_match_sample(post_body, "/etc/passwd|/etc/shadow|/root/.ssh|id_rsa"))
        end

        -- POST Body 疑似长 Base64 / 加密载荷
        if match_rule(post_body, "[A-Za-z0-9+/=]{30,}") then
            score = score + 30
            table.insert(reasons, "post_body_possible_encoded_payload")
            add_sample(samples, "post_body", "post_body_possible_encoded_payload", extract_match_sample(post_body, "[A-Za-z0-9+/=]{30,}"))
        end

        -- POST Body 中出现 PHP 危险函数
        if match_rule(post_body, "eval\\(|assert\\(|system\\(|shell_exec\\(|passthru\\(|base64_decode\\(") then
            score = score + 40
            table.insert(reasons, "post_body_php_dangerous_function")
            add_sample(samples, "post_body", "post_body_php_dangerous_function", extract_match_sample(post_body, "eval\\(|assert\\(|system\\(|shell_exec\\(|passthru\\(|base64_decode\\("))
        end

        -- POST Body 中出现常见 WebShell 管理工具相关关键词
        if match_rule(post_body, "Godzilla|Behinder|AntSword|rebeyond|pass=|password=|payload=") then
            score = score + 30
            table.insert(reasons, "post_body_webshell_keyword")
            add_sample(samples, "post_body", "post_body_webshell_keyword", extract_match_sample(post_body, "Godzilla|Behinder|AntSword|rebeyond|pass=|password=|payload="))
        end
    end


    -- 6. Cookie 可疑特征
    if cookie and cookie ~= "" then
        if match_rule(cookie, "Godzilla|Behinder|AntSword|rebeyond") then
            score = score + 30
            table.insert(reasons, "cookie_webshell_keyword")
            add_sample(samples, "cookie", "cookie_webshell_keyword", extract_match_sample(cookie, "Godzilla|Behinder|AntSword|rebeyond"))
        end

        if match_rule(cookie, "payload=|pass=|cmd=") then
            score = score + 25
            table.insert(reasons, "cookie_suspicious_param")
            add_sample(samples, "cookie", "cookie_suspicious_param", extract_match_sample(cookie, "payload=|pass=|cmd="))
        end

        if match_rule(cookie, "[A-Za-z0-9+/=]{30,}") then
            score = score + 25
            table.insert(reasons, "cookie_possible_encoded_payload")
            add_sample(samples, "cookie", "cookie_possible_encoded_payload", extract_match_sample(cookie, "[A-Za-z0-9+/=]{30,}"))
        end

        if match_rule(cookie, "eval\\(|system\\(|base64_decode\\(") then
            score = score + 40
            table.insert(reasons, "cookie_php_dangerous_function")
            add_sample(samples, "cookie", "cookie_php_dangerous_function", extract_match_sample(cookie, "eval\\(|system\\(|base64_decode\\("))
        end
    end

    -- 7. Header 可疑特征
    if headers and headers ~= "" then
        if match_rule(headers, "Godzilla|Behinder|AntSword|rebeyond") then
            score = score + 30
            table.insert(reasons, "header_webshell_keyword")
            add_sample(samples, "headers", "header_webshell_keyword", extract_match_sample(headers, "Godzilla|Behinder|AntSword|rebeyond"))
        end

        if match_rule(headers, "X-Cmd|X-Payload|X-Command") then
            score = score + 30
            table.insert(reasons, "suspicious_custom_header")
            add_sample(samples, "headers", "suspicious_custom_header", extract_match_sample(headers, "X-Cmd|X-Payload|X-Command"))
        end

        if match_rule(headers, "[A-Za-z0-9+/=]{30,}") then
            score = score + 25
            table.insert(reasons, "header_possible_encoded_payload")
            add_sample(samples, "headers", "header_possible_encoded_payload", extract_match_sample(headers, "[A-Za-z0-9+/=]{30,}"))
        end

        if match_rule(headers, "Authorization\\s*:\\s*[^\\s]{40,}") then
            score = score + 20
            table.insert(reasons, "authorization_long_token")
            add_sample(samples, "headers", "authorization_long_token", extract_match_sample(headers, "Authorization\\s*:\\s*[^\\s]{40,}"))
        end
    end

    return score, reasons, samples
end


local function check_static_rules(rules, args, uri, ua, post_body, cookie, headers)
    for _, rule in ipairs(rules) do
        if rule.target == "args_name" then
            for key, value in pairs(args) do
                if match_rule(key, rule.pattern) then
                    block_request(rule, post_body, cookie, headers, "args_name", make_safe_sample(key))
                end
            end

        elseif rule.target == "args_value" then
            for key, value in pairs(args) do
                if type(value) == "table" then
                    for _, v in ipairs(value) do
                        if match_rule(v, rule.pattern) then
                            block_request(rule, post_body, cookie, headers, "args_value", extract_match_sample(tostring(v), rule.pattern))
                        end
                    end
                else
                    if match_rule(value, rule.pattern) then
                        block_request(rule, post_body, cookie, headers, "args_value", extract_match_sample(tostring(value), rule.pattern))
                    end
                end
            end

        elseif rule.target == "uri" then
            if match_rule(uri, rule.pattern) then
                block_request(rule, post_body, cookie, headers, "uri", extract_match_sample(uri, rule.pattern))
            end

        elseif rule.target == "user_agent" then
            if match_rule(ua, rule.pattern) then
                block_request(rule, post_body, cookie, headers, "user_agent", extract_match_sample(ua, rule.pattern))
            end

        elseif rule.target == "post_body" then
            if match_rule(post_body, rule.pattern) then
                block_request(rule, post_body, cookie, headers, "post_body", extract_match_sample(post_body, rule.pattern))
            end

        elseif rule.target == "cookie" then
            if match_rule(cookie, rule.pattern) then
                block_request(rule, post_body, cookie, headers, "cookie", extract_match_sample(cookie, rule.pattern))
            end

        elseif rule.target == "headers" then
            if match_rule(headers, rule.pattern) then
                block_request(rule, post_body, cookie, headers, "headers", extract_match_sample(headers, rule.pattern))
            end
        end
    end
end


local function get_headers_string()
    local headers_table = ngx.req.get_headers()
    local parts = {}

    for key, value in pairs(headers_table) do
        local header_value = table_value_to_string(value)
        table.insert(parts, tostring(key) .. ": " .. header_value)
    end

    table.sort(parts)

    return table.concat(parts, "\n")
end


-- 主流程开始

local rules = load_rules()

local args = ngx.req.get_uri_args()
local uri = ngx.var.request_uri or ""
local ua = ngx.var.http_user_agent or ""
local cookie = ngx.var.http_cookie or ""
local headers = get_headers_string()
local post_body = get_post_body()

-- 第一层：先检查当前 IP 是否已经被临时封禁
check_ip_blocked(post_body, cookie, headers)

-- 第二层：静态规则强拦截
check_static_rules(rules, args, uri, ua, post_body, cookie, headers)

-- 第三层：未命中强拦截规则时，进行风险评分
local score, reasons, samples = calc_risk_score(args, uri, ua, post_body, cookie, headers)

if score >= BLOCK_SCORE then
    record_high_risk_ip(score, reasons, samples, post_body, cookie, headers)
    write_suspicious_log(score, reasons, samples, post_body, cookie, headers)
    local first_sample = samples[1] or {}
    block_request({
        id = 9200,
        name = "high_risk_score_block",
        level = "high"
    }, post_body, cookie, headers, first_sample.area or "risk_score", first_sample.sample or "")
elseif score >= HIGH_RISK_SCORE then
    local blocked_now = record_high_risk_ip(score, reasons, samples, post_body, cookie, headers)
    write_suspicious_log(score, reasons, samples, post_body, cookie, headers)

    if blocked_now then
        local first_sample = samples[1] or {}
        block_request({
            id = 9100,
            name = "temporary_blocked_ip",
            level = "high"
        }, post_body, cookie, headers, first_sample.area or "ip", first_sample.sample or "")
    end
elseif score >= 30 then
    write_suspicious_log(score, reasons, samples, post_body, cookie, headers)
end
