local cjson = require "cjson"

local rule_file = "/root/waf-demo/rules/rules.json"
local waf_log_file = "/root/waf-demo/logs/waf.log"

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

local function write_waf_log(rule)
    local log_data = {
        time = ngx.localtime(),
        ip = ngx.var.remote_addr or "",
        method = ngx.req.get_method() or "",
        uri = ngx.var.request_uri or "",
        user_agent = ngx.var.http_user_agent or "",
        rule_id = rule.id,
        rule_name = rule.name,
        level = rule.level,
        action = rule.action or "block"
    }

    local line = cjson.encode(log_data)

    local file = io.open(waf_log_file, "a")
    if file then
        file:write(line .. "\n")
        file:close()
    else
        ngx.log(ngx.ERR, "WAF ERROR: cannot write waf log file: ", waf_log_file)
    end
end

local function block_request(rule)
    write_waf_log(rule)

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

local rules = load_rules()

local args = ngx.req.get_uri_args()
local uri = ngx.var.request_uri or ""
local ua = ngx.var.http_user_agent or ""

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