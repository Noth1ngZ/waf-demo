local args = ngx.req.get_uri_args()

if args["cmd"] then
    ngx.log(ngx.ERR, "WAF BLOCK: cmd parameter detected, uri=", ngx.var.request_uri)

    ngx.status = 403
    ngx.say("Blocked by WAF")
    return ngx.exit(403)
end