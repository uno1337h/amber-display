-- End-to-end: runs the real loader.lua inside a mocked Neverlose runtime and
-- talks to a real loader server through curl.
-- usage: luajit e2e.lua <loader.lua> <server_url> <pubkey_hex> <license> <username> <script_name>
package.path = arg[0]:gsub("[^/]+$", "") .. "?.lua;" .. package.path
local json_mod = require("json")
local loader_path, server_url, pubkey, license, user, script = unpack(arg)

local function shell_quote(s) return "'" .. s:gsub("'", "'\\''") .. "'" end

-- ---- Neverlose API mocks -------------------------------------------------
local log = {}
local pending = {}
local buttons, list_item = {}, nil

local env = setmetatable({}, { __index = _G })
env._G = env
env.print_raw = function(s) log[#log + 1] = s end
env.json = { parse = json_mod.parse }
env.db = { nl_secure_loader_v1 = { license = license, versions = {} } }
env.common = {
    get_timestamp = function() return os.clock() * 1000 end,
    get_unixtime = function() return os.time() end,
    get_username = function() return user end,
}
env.utils = {
    random_int = function(a, b) return math.random(a, b) end,
    execute_after = function(_, fn) pending[#pending + 1] = { timeout = fn } end,
}
env.network = {
    get = function(url, headers, cb)
        local cmd = { "curl -sS --max-time 10" }
        for k, v in pairs(headers) do cmd[#cmd + 1] = "-H " .. shell_quote(k .. ": " .. v) end
        cmd[#cmd + 1] = shell_quote(url)
        local f = io.popen(table.concat(cmd, " "))
        local body = f:read("*a"); f:close()
        pending[#pending + 1] = { cb = cb, body = body }
    end,
}
local function item(kind, name, value)
    local it = { kind = kind, label = name, value = value }
    function it:get() return self.value end
    function it:set(v) self.value = v end
    function it:name(v) if v then self.label = v end return self.label end
    function it:update(items) self.items = items end
    return it
end
env.ui = {
    create = function()
        return {
            input = function(_, n, v) return item("input", n, v) end,
            label = function(_, n) return item("label", n) end,
            list = function(_, n, items) list_item = item("list", n, 1); list_item.items = items; return list_item end,
            button = function(_, n, cb) buttons[n] = cb; return item("button", n) end,
        }
    end,
}

-- what the loaded script is expected to do
env.E2E_MARK = function(v) env.__e2e_mark = v end

local function pump()
    -- deliver network responses (simulates Neverlose calling back later)
    while #pending > 0 do
        local p = table.remove(pending, 1)
        if p.cb then p.cb(p.body) end
    end
end

-- ---- run -----------------------------------------------------------------
local src = assert(io.open(loader_path)):read("*a")
src = src:gsub('local SERVER_URL = "[^"]*"', 'local SERVER_URL = "' .. server_url .. '"')
src = src:gsub('local PUBLIC_KEY_HEX = "[^"]*"', 'local PUBLIC_KEY_HEX = "' .. pubkey .. '"')
-- the test server is plain http on localhost; relax only the scheme check
src = src:gsub('"%^https://', '"^https?://')
local chunk = assert(loadstring(src, "=loader.lua"))
setfenv(chunk, env)
chunk()
pump() -- manifest fetched on startup because a license is stored

local names = list_item.items
assert(names[1]:find(script, 1, true), "manifest should list " .. script .. ", got: " .. tostring(names[1]))

buttons["Load selected"]()
pump()

print(table.concat(log, "\n"))
assert(env.__e2e_mark == "ran", "script did not run")
assert(env.db.nl_secure_loader_v1.versions[script] ~= nil, "version floor not recorded")
print("E2E_OK version=" .. tostring(env.db.nl_secure_loader_v1.versions[script]))
