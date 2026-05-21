local http = require("suricata.http")

function init (args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    a = tx:request_line()
    if #a > 0 then
        if a:find("^POST%s+/.*%.php%s+HTTP/1.0$") then
            return 1
        end
    end

    return 0
end
