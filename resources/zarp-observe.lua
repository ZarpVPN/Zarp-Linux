-- Count successful raw sends from the trusted strategy library, without payloads.
-- Queue counters alone do not prove that a desync function changed the flow.
local sent = 0
local faulted = false
for _, name in ipairs({"rawsend", "rawsend_dissect"}) do
    local original = _G[name]
    if type(original) == "function" then
        _G[name] = function(...)
            local ok = original(...)
            if not ok then
                faulted = true
                io.stdout:write("ZARP_ERROR:rawsend\n")
                io.stdout:flush()
            end
            if ok and sent < 4096 then
                sent = sent + 1
                io.stdout:write("ZARP_SENT\n")
                io.stdout:flush()
            end
            return ok
        end
    end
end
for _, name in ipairs({"fake", "multisplit", "multidisorder", "hostfakesplit", "send", "drop"}) do
    local original = _G[name]
    if type(original) == "function" then
        _G[name] = function(...)
            if faulted then return VERDICT_DROP end
            local ok, result = pcall(original, ...)
            if not ok then
                faulted = true
                -- Trusted Lua-library errors only; no packet data or WARP output.
                local detail = tostring(result):gsub("[\r\n]", " "):sub(1, 512)
                io.stdout:write("ZARP_ERROR:lua:" .. name .. ":" .. detail .. "\n")
                io.stdout:flush()
                return VERDICT_DROP
            end
            if faulted then return VERDICT_DROP end
            return result
        end
    end
end
