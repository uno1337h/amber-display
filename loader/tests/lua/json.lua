-- minimal JSON decoder used only to stand in for Neverlose's json.parse in tests
local json = {}

local function err(s, i, msg) error(("json error at %d: %s"):format(i, msg)) end

local decode_value

local function skip(s, i)
    local _, e = s:find("^[ \t\r\n]*", i)
    return e + 1
end

local function decode_string(s, i)
    local out, j = {}, i + 1
    while true do
        local c = s:sub(j, j)
        if c == "" then err(s, j, "unterminated string") end
        if c == '"' then return table.concat(out), j + 1 end
        if c == "\\" then
            local e = s:sub(j + 1, j + 1)
            local map = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }
            if map[e] then
                out[#out + 1] = map[e]; j = j + 2
            elseif e == "u" then
                local cp = tonumber(s:sub(j + 2, j + 5), 16)
                if not cp then err(s, j, "bad \\u escape") end
                j = j + 6
                if cp >= 0xD800 and cp <= 0xDBFF and s:sub(j, j + 1) == "\\u" then
                    local lo = tonumber(s:sub(j + 2, j + 5), 16)
                    cp = 0x10000 + (cp - 0xD800) * 0x400 + (lo - 0xDC00)
                    j = j + 6
                end
                if cp < 0x80 then out[#out + 1] = string.char(cp)
                elseif cp < 0x800 then out[#out + 1] = string.char(0xC0 + math.floor(cp / 64), 0x80 + cp % 64)
                elseif cp < 0x10000 then out[#out + 1] = string.char(0xE0 + math.floor(cp / 4096), 0x80 + math.floor(cp / 64) % 64, 0x80 + cp % 64)
                else out[#out + 1] = string.char(0xF0 + math.floor(cp / 262144), 0x80 + math.floor(cp / 4096) % 64, 0x80 + math.floor(cp / 64) % 64, 0x80 + cp % 64) end
            else err(s, j, "bad escape") end
        else
            out[#out + 1] = c; j = j + 1
        end
    end
end

function decode_value(s, i)
    i = skip(s, i)
    local c = s:sub(i, i)
    if c == "{" then
        local t = {}
        i = skip(s, i + 1)
        if s:sub(i, i) == "}" then return t, i + 1 end
        while true do
            local k; k, i = decode_string(s, skip(s, i))
            i = skip(s, i)
            if s:sub(i, i) ~= ":" then err(s, i, "expected :") end
            t[k], i = decode_value(s, i + 1)
            i = skip(s, i)
            local d = s:sub(i, i)
            if d == "}" then return t, i + 1 end
            if d ~= "," then err(s, i, "expected , or }") end
            i = i + 1
        end
    elseif c == "[" then
        local t, n = {}, 0
        i = skip(s, i + 1)
        if s:sub(i, i) == "]" then return t, i + 1 end
        while true do
            n = n + 1
            t[n], i = decode_value(s, i)
            i = skip(s, i)
            local d = s:sub(i, i)
            if d == "]" then return t, i + 1 end
            if d ~= "," then err(s, i, "expected , or ]") end
            i = i + 1
        end
    elseif c == '"' then return decode_string(s, i)
    elseif s:sub(i, i + 3) == "true" then return true, i + 4
    elseif s:sub(i, i + 4) == "false" then return false, i + 5
    elseif s:sub(i, i + 3) == "null" then return nil, i + 4
    else
        local num = s:match("^-?%d+%.?%d*[eE]?[-+]?%d*", i)
        if not num or num == "" then err(s, i, "unexpected character") end
        return tonumber(num), i + #num
    end
end

function json.parse(s)
    local v, i = decode_value(s, 1)
    if skip(s, i) <= #s then err(s, i, "trailing data") end
    return v
end

return json
