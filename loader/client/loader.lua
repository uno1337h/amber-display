--[[
    Secure script loader for Neverlose (CS:GO)
    API reference: https://docs-csgo.neverlose.cc

    Every script the server sends is wrapped in an Ed25519-signed envelope.
    The loader refuses to run anything unless ALL of these hold:
      * the signature verifies against the public key pinned below
      * the envelope names the script that was requested
      * the envelope echoes the random nonce of THIS request (no replay)
      * the envelope is bound to this Neverlose username
      * the envelope is inside its validity window
      * the version is not older than the newest version seen before (no rollback)
      * the code is Lua source, not precompiled bytecode

    The license key and transport are secondary: even someone in full control
    of the network or the web server cannot get code executed without the
    private signing key, which never leaves the machine where you sign.

    CONFIGURE the two values below before distributing.
]]

---------------------------------------------------------------------------
-- configuration
---------------------------------------------------------------------------
-- base URL of your loader server; must be https
local SERVER_URL = "https://loader.example.com"

-- Ed25519 public key, 64 hex characters, printed by `python manage.py genkey`
local PUBLIC_KEY_HEX = "0000000000000000000000000000000000000000000000000000000000000000"

local PROTOCOL       = "NLLOADER-V1"   -- domain separation tag, must match server
local MAX_CLOCK_SKEW = 300             -- seconds of tolerated clock difference
local MAX_RESPONSE   = 4 * 1024 * 1024 -- refuse responses larger than this (bytes)
local REQUEST_TIMEOUT = 15             -- seconds before a request is abandoned
local DB_KEY         = "nl_secure_loader_v1"

---------------------------------------------------------------------------
-- captured builtins (taken once so later changes to globals cannot affect us)
---------------------------------------------------------------------------
local bit = bit or require("bit")
local band, bor, bxor, bnot = bit.band, bit.bor, bit.bxor, bit.bnot
local rshift, lshift, arshift = bit.rshift, bit.lshift, bit.arshift
local floor = math.floor
local s_byte, s_char, s_sub, s_rep, s_find, s_format, s_gsub =
    string.byte, string.char, string.sub, string.rep, string.find, string.format, string.gsub
local t_concat = table.concat
local _type, _pairs, _tostring, _tonumber, _pcall, _setmetatable, _rawget =
    type, pairs, tostring, tonumber, pcall, setmetatable, rawget
local _load, _loadstring, _setfenv = load, loadstring, setfenv

local TWO32 = 4294967296

---------------------------------------------------------------------------
-- SHA-512 (64-bit words held as hi/lo 32-bit pairs)
---------------------------------------------------------------------------
local K = {0x428a2f98,0xd728ae22, 0x71374491,0x23ef65cd, 0xb5c0fbcf,0xec4d3b2f, 0xe9b5dba5,0x8189dbbc, 0x3956c25b,0xf348b538, 0x59f111f1,0xb605d019, 0x923f82a4,0xaf194f9b, 0xab1c5ed5,0xda6d8118, 0xd807aa98,0xa3030242, 0x12835b01,0x45706fbe, 0x243185be,0x4ee4b28c, 0x550c7dc3,0xd5ffb4e2, 0x72be5d74,0xf27b896f, 0x80deb1fe,0x3b1696b1, 0x9bdc06a7,0x25c71235, 0xc19bf174,0xcf692694, 0xe49b69c1,0x9ef14ad2, 0xefbe4786,0x384f25e3, 0x0fc19dc6,0x8b8cd5b5, 0x240ca1cc,0x77ac9c65, 0x2de92c6f,0x592b0275, 0x4a7484aa,0x6ea6e483, 0x5cb0a9dc,0xbd41fbd4, 0x76f988da,0x831153b5, 0x983e5152,0xee66dfab, 0xa831c66d,0x2db43210, 0xb00327c8,0x98fb213f, 0xbf597fc7,0xbeef0ee4, 0xc6e00bf3,0x3da88fc2, 0xd5a79147,0x930aa725, 0x06ca6351,0xe003826f, 0x14292967,0x0a0e6e70, 0x27b70a85,0x46d22ffc, 0x2e1b2138,0x5c26c926, 0x4d2c6dfc,0x5ac42aed, 0x53380d13,0x9d95b3df, 0x650a7354,0x8baf63de, 0x766a0abb,0x3c77b2a8, 0x81c2c92e,0x47edaee6, 0x92722c85,0x1482353b, 0xa2bfe8a1,0x4cf10364, 0xa81a664b,0xbc423001, 0xc24b8b70,0xd0f89791, 0xc76c51a3,0x0654be30, 0xd192e819,0xd6ef5218, 0xd6990624,0x5565a910, 0xf40e3585,0x5771202a, 0x106aa070,0x32bbd1b8, 0x19a4c116,0xb8d2d0c8, 0x1e376c08,0x5141ab53, 0x2748774c,0xdf8eeb99, 0x34b0bcb5,0xe19b48a8, 0x391c0cb3,0xc5c95a63, 0x4ed8aa4a,0xe3418acb, 0x5b9cca4f,0x7763e373, 0x682e6ff3,0xd6b2b8a3, 0x748f82ee,0x5defb2fc, 0x78a5636f,0x43172f60, 0x84c87814,0xa1f0ab72, 0x8cc70208,0x1a6439ec, 0x90befffa,0x23631e28, 0xa4506ceb,0xde82bde9, 0xbef9a3f7,0xb2c67915, 0xc67178f2,0xe372532b, 0xca273ece,0xea26619c, 0xd186b8c7,0x21c0c207, 0xeada7dd6,0xcde0eb1e, 0xf57d4f7f,0xee6ed178, 0x06f067aa,0x72176fba, 0x0a637dc5,0xa2c898a6, 0x113f9804,0xbef90dae, 0x1b710b35,0x131c471b, 0x28db77f5,0x23047d84, 0x32caab7b,0x40c72493, 0x3c9ebe0a,0x15c9bebc, 0x431d67c4,0x9c100d4c, 0x4cc5d4be,0xcb3e42b6, 0x597f299c,0xfc657e2a, 0x5fcb6fab,0x3ad6faec, 0x6c44198c,0x4a475817}
local H0 = {0x6a09e667,0xf3bcc908, 0xbb67ae85,0x84caa73b, 0x3c6ef372,0xfe94f82b, 0xa54ff53a,0x5f1d36f1, 0x510e527f,0xade682d1, 0x9b05688c,0x2b3e6c1f, 0x1f83d9ab,0xfb41bd6b, 0x5be0cd19,0x137e2179}

local function u32(x) return x % TWO32 end

local function be32(x)
    return s_char(floor(x / 16777216) % 256, floor(x / 65536) % 256, floor(x / 256) % 256, x % 256)
end

-- returns the 64-byte digest as a raw string
local function sha512(msg)
    local len = #msg
    local pad = (128 - (len + 17) % 128) % 128
    local bitlen = len * 8
    msg = msg .. "\128" .. s_rep("\0", pad + 8) .. be32(floor(bitlen / TWO32)) .. be32(bitlen % TWO32)

    local h = {}
    for i = 1, 16 do h[i] = H0[i] end
    local wh, wl = {}, {}

    for blk = 1, #msg, 128 do
        for i = 0, 15 do
            local a, b, c, d, e, f, g, hh = s_byte(msg, blk + i * 8, blk + i * 8 + 7)
            wh[i] = ((a * 256 + b) * 256 + c) * 256 + d
            wl[i] = ((e * 256 + f) * 256 + g) * 256 + hh
        end
        for i = 16, 79 do
            local xh, xl = wh[i - 15], wl[i - 15]
            local s0h = bxor(bor(rshift(xh, 1), lshift(xl, 31)), bor(rshift(xh, 8), lshift(xl, 24)), rshift(xh, 7))
            local s0l = bxor(bor(rshift(xl, 1), lshift(xh, 31)), bor(rshift(xl, 8), lshift(xh, 24)), bor(rshift(xl, 7), lshift(xh, 25)))
            xh, xl = wh[i - 2], wl[i - 2]
            local s1h = bxor(bor(rshift(xh, 19), lshift(xl, 13)), bor(rshift(xl, 29), lshift(xh, 3)), rshift(xh, 6))
            local s1l = bxor(bor(rshift(xl, 19), lshift(xh, 13)), bor(rshift(xh, 29), lshift(xl, 3)), bor(rshift(xl, 6), lshift(xh, 26)))
            local lo = u32(wl[i - 16]) + u32(s0l) + u32(wl[i - 7]) + u32(s1l)
            local hi = u32(wh[i - 16]) + u32(s0h) + u32(wh[i - 7]) + u32(s1h) + floor(lo / TWO32)
            wl[i], wh[i] = lo % TWO32, hi % TWO32
        end

        local ah, al, bh, bl, ch, cl, dh, dl = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
        local eh, el, fh, fl, gh, gl, hh, hl = h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16]

        for i = 0, 79 do
            local S1h = bxor(bor(rshift(eh, 14), lshift(el, 18)), bor(rshift(eh, 18), lshift(el, 14)), bor(rshift(el, 9), lshift(eh, 23)))
            local S1l = bxor(bor(rshift(el, 14), lshift(eh, 18)), bor(rshift(el, 18), lshift(eh, 14)), bor(rshift(eh, 9), lshift(el, 23)))
            local chh = bxor(band(eh, fh), band(bnot(eh), gh))
            local chl = bxor(band(el, fl), band(bnot(el), gl))
            local t1l = u32(hl) + u32(S1l) + u32(chl) + K[i * 2 + 2] + wl[i]
            local t1h = u32(hh) + u32(S1h) + u32(chh) + K[i * 2 + 1] + wh[i] + floor(t1l / TWO32)
            t1l, t1h = t1l % TWO32, t1h % TWO32

            local S0h = bxor(bor(rshift(ah, 28), lshift(al, 4)), bor(rshift(al, 2), lshift(ah, 30)), bor(rshift(al, 7), lshift(ah, 25)))
            local S0l = bxor(bor(rshift(al, 28), lshift(ah, 4)), bor(rshift(ah, 2), lshift(al, 30)), bor(rshift(ah, 7), lshift(al, 25)))
            local mjh = bxor(band(ah, bh), band(ah, ch), band(bh, ch))
            local mjl = bxor(band(al, bl), band(al, cl), band(bl, cl))
            local t2l = u32(S0l) + u32(mjl)
            local t2h = u32(S0h) + u32(mjh) + floor(t2l / TWO32)
            t2l = t2l % TWO32

            hh, hl = gh, gl
            gh, gl = fh, fl
            fh, fl = eh, el
            local nel = u32(dl) + t1l
            eh, el = (u32(dh) + t1h + floor(nel / TWO32)) % TWO32, nel % TWO32
            dh, dl = ch, cl
            ch, cl = bh, bl
            bh, bl = ah, al
            local nal = t1l + t2l
            ah, al = (t1h + t2h + floor(nal / TWO32)) % TWO32, nal % TWO32
        end

        local v = {ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl}
        for i = 1, 16, 2 do
            local lo = u32(h[i + 1]) + u32(v[i + 1])
            h[i] = (u32(h[i]) + u32(v[i]) + floor(lo / TWO32)) % TWO32
            h[i + 1] = lo % TWO32
        end
    end

    local out = {}
    for i = 1, 16 do out[i] = be32(h[i]) end
    return t_concat(out)
end

---------------------------------------------------------------------------
-- Ed25519 signature verification (port of TweetNaCl's crypto_sign_open)
-- field elements: 16 limbs of 16 bits, 0-indexed
---------------------------------------------------------------------------
local function gf(init)
    local r = {}
    for i = 0, 15 do r[i] = 0 end
    if init then for i = 1, #init do r[i - 1] = init[i] end end
    return r
end

local gf0, gf1 = gf(), gf{1}
local D  = gf{0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203}
local D2 = gf{0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406}
local I  = gf{0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83}
local X  = gf{0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169}
local Y  = gf{0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666}
local L  = {[0]=0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}

local function set25519(r, a) for i = 0, 15 do r[i] = a[i] end end

local function car25519(o)
    local c = 1
    for i = 0, 15 do
        local v = o[i] + c + 65535
        c = floor(v / 65536)
        o[i] = v - c * 65536
    end
    o[0] = o[0] + c - 1 + 37 * (c - 1)
end

local function sel25519(p, q, b)
    -- swap p and q when b == 1 (public data only, constant time not required)
    if b == 1 then
        for i = 0, 15 do p[i], q[i] = q[i], p[i] end
    end
end

local function pack25519(o, n)
    local m, t = gf(), gf()
    for i = 0, 15 do t[i] = n[i] end
    car25519(t); car25519(t); car25519(t)
    for _ = 1, 2 do
        m[0] = t[0] - 0xffed
        for i = 1, 14 do
            m[i] = t[i] - 0xffff - band(arshift(m[i - 1], 16), 1)
            m[i - 1] = band(m[i - 1], 0xffff)
        end
        m[15] = t[15] - 0x7fff - band(arshift(m[14], 16), 1)
        local b = band(arshift(m[15], 16), 1)
        m[14] = band(m[14], 0xffff)
        sel25519(t, m, 1 - b)
    end
    for i = 0, 15 do
        o[2 * i] = band(t[i], 0xff)
        o[2 * i + 1] = rshift(band(t[i], 0xffff), 8)
    end
end

local function neq25519(a, b)
    local c, d = {}, {}
    pack25519(c, a); pack25519(d, b)
    for i = 0, 31 do if c[i] ~= d[i] then return true end end
    return false
end

local function par25519(a)
    local d = {}
    pack25519(d, a)
    return band(d[0], 1)
end

local function unpack25519(o, n)
    for i = 0, 15 do o[i] = n[2 * i] + n[2 * i + 1] * 256 end
    o[15] = band(o[15], 0x7fff)
end

local function A(o, a, b) for i = 0, 15 do o[i] = a[i] + b[i] end end
local function Z(o, a, b) for i = 0, 15 do o[i] = a[i] - b[i] end end

local function M(o, a, b)
    local t = {}
    for i = 0, 30 do t[i] = 0 end
    for i = 0, 15 do
        local ai = a[i]
        for j = 0, 15 do t[i + j] = t[i + j] + ai * b[j] end
    end
    for i = 0, 14 do t[i] = t[i] + 38 * t[i + 16] end
    for i = 0, 15 do o[i] = t[i] end
    car25519(o); car25519(o)
end

local function S(o, a) M(o, a, a) end

local function inv25519(o, i)
    local c = gf()
    set25519(c, i)
    for a = 253, 0, -1 do
        S(c, c)
        if a ~= 2 and a ~= 4 then M(c, c, i) end
    end
    set25519(o, c)
end

local function pow2523(o, i)
    local c = gf()
    set25519(c, i)
    for a = 250, 0, -1 do
        S(c, c)
        if a ~= 1 then M(c, c, i) end
    end
    set25519(o, c)
end

local function add(p, q)
    local a, b, c, d, e, f, g, h, t = gf(), gf(), gf(), gf(), gf(), gf(), gf(), gf(), gf()
    Z(a, p[1], p[0]); Z(t, q[1], q[0]); M(a, a, t)
    A(b, p[0], p[1]); A(t, q[0], q[1]); M(b, b, t)
    M(c, p[3], q[3]); M(c, c, D2)
    M(d, p[2], q[2]); A(d, d, d)
    Z(e, b, a); Z(f, d, c); A(g, d, c); A(h, b, a)
    M(p[0], e, f); M(p[1], h, g); M(p[2], g, f); M(p[3], e, h)
end

local function cswap(p, q, b) for i = 0, 3 do sel25519(p[i], q[i], b) end end

local function pack(r, p)
    local tx, ty, zi = gf(), gf(), gf()
    inv25519(zi, p[2])
    M(tx, p[0], zi); M(ty, p[1], zi)
    pack25519(r, ty)
    r[31] = bxor(r[31], lshift(par25519(tx), 7))
end

local function scalarmult(p, q, s)
    set25519(p[0], gf0); set25519(p[1], gf1); set25519(p[2], gf1); set25519(p[3], gf0)
    for i = 255, 0, -1 do
        local b = band(rshift(s[floor(i / 8)], i % 8), 1)
        cswap(p, q, b)
        add(q, p)
        add(p, p)
        cswap(p, q, b)
    end
end

local function scalarbase(p, s)
    local q = {[0] = gf(), gf(), gf(), gf()}
    set25519(q[0], X); set25519(q[1], Y); set25519(q[2], gf1); M(q[3], X, Y)
    scalarmult(p, q, s)
end

local function unpackneg(r, p)
    local t, chk, num, den, den2, den4, den6 = gf(), gf(), gf(), gf(), gf(), gf(), gf()
    set25519(r[2], gf1)
    unpack25519(r[1], p)
    S(num, r[1]); M(den, num, D); Z(num, num, r[2]); A(den, r[2], den)
    S(den2, den); S(den4, den2); M(den6, den4, den2); M(t, den6, num); M(t, t, den)
    pow2523(t, t); M(t, t, num); M(t, t, den); M(t, t, den); M(r[0], t, den)
    S(chk, r[0]); M(chk, chk, den)
    if neq25519(chk, num) then M(r[0], r[0], I) end
    S(chk, r[0]); M(chk, chk, den)
    if neq25519(chk, num) then return false end
    if par25519(r[0]) == rshift(p[31], 7) then Z(r[0], gf0, r[0]) end
    M(r[3], r[0], r[1])
    return true
end

local function modL(r, x)
    for i = 63, 32, -1 do
        local carry = 0
        local j = i - 32
        local k = i - 12
        while j < k do
            x[j] = x[j] + carry - 16 * x[i] * L[j - (i - 32)]
            carry = floor((x[j] + 128) / 256)
            x[j] = x[j] - carry * 256
            j = j + 1
        end
        x[j] = x[j] + carry
        x[i] = 0
    end
    local carry = 0
    for j = 0, 31 do
        x[j] = x[j] + carry - arshift(x[31], 4) * L[j]
        carry = arshift(x[j], 8)
        x[j] = band(x[j], 255)
    end
    for j = 0, 31 do x[j] = x[j] - carry * L[j] end
    for i = 0, 31 do
        x[i + 1] = x[i + 1] + arshift(x[i], 8)
        r[i] = band(x[i], 255)
    end
end

local function bytes_of(s, from, to)
    local r, n = {}, 0
    for i = from, to do r[n] = s_byte(s, i); n = n + 1 end
    return r
end

-- true only for a canonical signature scalar (S < L), rejects malleated signatures
local function scalar_is_canonical(sig)
    for i = 63, 32, -1 do
        local s, l = s_byte(sig, i + 1), L[i - 32]
        if s < l then return true end
        if s > l then return false end
    end
    return false
end

-- pk: 32-byte string, sig: 64-byte string, msg: string
local function ed25519_verify(pk, sig, msg)
    if _type(pk) ~= "string" or _type(sig) ~= "string" or _type(msg) ~= "string" then return false end
    if #pk ~= 32 or #sig ~= 64 then return false end
    if not scalar_is_canonical(sig) then return false end

    local q = {[0] = gf(), gf(), gf(), gf()}
    local pkb = bytes_of(pk, 1, 32)
    if not unpackneg(q, pkb) then return false end

    local hstr = sha512(s_sub(sig, 1, 32) .. pk .. msg)
    local x = {}
    for i = 0, 63 do x[i] = s_byte(hstr, i + 1) end
    local h = {}
    modL(h, x)

    local p = {[0] = gf(), gf(), gf(), gf()}
    scalarmult(p, q, h)
    local q2 = {[0] = gf(), gf(), gf(), gf()}
    scalarbase(q2, bytes_of(sig, 33, 64))
    add(p, q2)
    local t = {}
    pack(t, p)

    -- compare against R; accumulate so all bytes are always checked
    local diff = 0
    for i = 0, 31 do diff = bor(diff, bxor(t[i], s_byte(sig, i + 1))) end
    return diff == 0
end

---------------------------------------------------------------------------
-- encoding helpers
---------------------------------------------------------------------------
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64_REV = {}
for i = 1, 64 do B64_REV[s_byte(B64, i)] = i - 1 end

-- strict base64 decoder; returns nil on any malformed input
local function b64decode(s)
    if _type(s) ~= "string" or #s % 4 ~= 0 then return nil end
    local out, n = {}, 0
    local len = #s
    for i = 1, len, 4 do
        local c1, c2, c3, c4 = s_byte(s, i, i + 3)
        local last = (i + 3 == len)
        local v1, v2 = B64_REV[c1], B64_REV[c2]
        if not v1 or not v2 then return nil end
        if c4 == 61 then -- '='
            if not last then return nil end
            if c3 == 61 then
                if v2 % 16 ~= 0 then return nil end
                n = n + 1; out[n] = s_char(v1 * 4 + floor(v2 / 16))
            else
                local v3 = B64_REV[c3]
                if not v3 or v3 % 4 ~= 0 then return nil end
                n = n + 1; out[n] = s_char(v1 * 4 + floor(v2 / 16), (v2 % 16) * 16 + floor(v3 / 4))
            end
        else
            local v3, v4 = B64_REV[c3], B64_REV[c4]
            if not v3 or not v4 then return nil end
            n = n + 1
            out[n] = s_char(v1 * 4 + floor(v2 / 16), (v2 % 16) * 16 + floor(v3 / 4), (v3 % 4) * 64 + v4)
        end
    end
    return t_concat(out)
end

local function hex_decode(h)
    if _type(h) ~= "string" or #h % 2 ~= 0 or s_find(h, "[^0-9a-fA-F]") then return nil end
    return (s_gsub(h, "..", function(cc) return s_char(_tonumber(cc, 16)) end))
end

local function hex_encode(s)
    return (s_gsub(s, ".", function(c) return s_format("%02x", s_byte(c)) end))
end

local function url_component_ok(s)
    return _type(s) == "string" and #s >= 1 and #s <= 64 and not s_find(s, "[^%w_%-]")
end

---------------------------------------------------------------------------
-- envelope verification (pure; no side effects, easy to test)
---------------------------------------------------------------------------
-- expect = { kind, nonce, username, now, name (for scripts), min_version }
-- returns payload table on success, or nil, reason
local function open_envelope(pk, body, expect, json_parse)
    if _type(body) ~= "string" or #body == 0 or #body > MAX_RESPONSE then
        return nil, "bad response size"
    end
    local ok, outer = _pcall(json_parse, body)
    if not ok or _type(outer) ~= "table" then return nil, "malformed response" end
    if outer.error ~= nil then return nil, "server: " .. _tostring(outer.error):sub(1, 120) end
    if _type(outer.payload) ~= "string" or _type(outer.sig) ~= "string" then
        return nil, "malformed envelope"
    end

    local payload = b64decode(outer.payload)
    local sig = b64decode(outer.sig)
    if not payload or not sig or #sig ~= 64 then return nil, "malformed envelope" end

    -- the signature check happens BEFORE the payload is parsed or trusted
    if not ed25519_verify(pk, sig, PROTOCOL .. "\0" .. payload) then
        return nil, "signature verification failed"
    end

    local ok2, p = _pcall(json_parse, payload)
    if not ok2 or _type(p) ~= "table" then return nil, "malformed payload" end

    if p.proto ~= PROTOCOL then return nil, "protocol mismatch" end
    if p.kind ~= expect.kind then return nil, "wrong envelope kind" end
    if p.nonce ~= expect.nonce then return nil, "nonce mismatch (replayed response?)" end
    if p.user ~= expect.username then return nil, "envelope issued for another user" end

    local iat, exp = _tonumber(p.iat), _tonumber(p.exp)
    if not iat or not exp or exp <= iat then return nil, "bad validity window" end
    if expect.now + MAX_CLOCK_SKEW < iat then return nil, "envelope from the future (check clock)" end
    if expect.now - MAX_CLOCK_SKEW > exp then return nil, "envelope expired (check clock)" end

    if expect.kind == "script" then
        if p.name ~= expect.name then return nil, "script name mismatch" end
        local ver = _tonumber(p.version)
        if not ver or ver < 0 or ver ~= floor(ver) then return nil, "bad version" end
        if expect.min_version and ver < expect.min_version then
            return nil, "rollback to older version refused"
        end
        if _type(p.code) ~= "string" or #p.code == 0 then return nil, "empty script" end
        if s_byte(p.code, 1) == 27 then return nil, "bytecode refused" end
    elseif expect.kind == "manifest" then
        if _type(p.scripts) ~= "table" then return nil, "bad manifest" end
    end

    return p
end

---------------------------------------------------------------------------
-- sandboxed execution
---------------------------------------------------------------------------
-- globals a loaded script may not see; they could be used to reach into
-- this loader (upvalues, environments) or to load unverified code
local BLOCKED_GLOBALS = {
    debug = true, getfenv = true, setfenv = true,
    load = true, loadstring = true, loadfile = true, dofile = true,
    require = true, package = true, module = true,
    collectgarbage = true, newproxy = true,
}

local function make_env(base)
    local env = {}
    env._G = env
    return _setmetatable(env, {
        __index = function(_, k)
            if BLOCKED_GLOBALS[k] then return nil end
            return base[k]
        end,
        __metatable = false,
    })
end

local function compile(code, chunkname, env)
    if s_byte(code, 1) == 27 then return nil, "bytecode refused" end
    local fn, err
    if _load then
        -- mode "t": text only; LuaJIT refuses binary chunks
        local ok, f, e = _pcall(_load, code, chunkname, "t", env)
        if ok then fn, err = f, e end
    end
    if not fn and _loadstring and _setfenv and not err then
        fn, err = _loadstring(code, chunkname)
        if fn then _setfenv(fn, env) end
    end
    if not fn then return nil, err or "no compiler available" end
    return fn
end

---------------------------------------------------------------------------
-- test hook: lets tests reach the pure functions without the Neverlose runtime
---------------------------------------------------------------------------
if _rawget(_G, "__NL_LOADER_TEST") then
    return {
        sha512 = sha512, ed25519_verify = ed25519_verify, b64decode = b64decode,
        hex_decode = hex_decode, hex_encode = hex_encode, open_envelope = open_envelope,
        compile = compile, make_env = make_env, PROTOCOL = PROTOCOL,
    }
end

---------------------------------------------------------------------------
-- Neverlose integration
---------------------------------------------------------------------------
local PUBLIC_KEY = hex_decode(PUBLIC_KEY_HEX)
local function log(msg)  print_raw("\a7FB2FF[loader] \aDEFAULT" .. msg) end
local function fail(msg) print_raw("\aFF5050[loader] \aDEFAULT" .. msg) end

if not PUBLIC_KEY or #PUBLIC_KEY ~= 32 or PUBLIC_KEY == s_rep("\0", 32) then
    fail("PUBLIC_KEY_HEX is not configured; refusing to run.")
    return
end
if not s_find(SERVER_URL, "^https://[%w%.%-]+[:%d]*/?$") then
    fail("SERVER_URL must be an https:// origin; refusing to run.")
    return
end
SERVER_URL = s_gsub(SERVER_URL, "/$", "")

-- persistent state: license key + highest version seen per script
local state = db[DB_KEY]
if _type(state) ~= "table" then state = {} end
if _type(state.versions) ~= "table" then state.versions = {} end
if _type(state.license) ~= "string" then state.license = "" end
local function save_state() db[DB_KEY] = state end

-- nonce: not a CSPRNG, but only needs to be unpredictable enough that a
-- recorded response cannot be replayed; mixes several entropy sources
local nonce_counter = 0
local function new_nonce()
    nonce_counter = nonce_counter + 1
    local parts = {
        _tostring(common.get_timestamp()), _tostring(common.get_unixtime()),
        _tostring(nonce_counter), _tostring({}), _tostring(collectgarbage and collectgarbage("count") or 0),
    }
    for _ = 1, 8 do parts[#parts + 1] = _tostring(utils.random_int(0, 2147483647)) end
    return s_sub(hex_encode(sha512(t_concat(parts, "|"))), 1, 32)
end

local function username()
    local ok, u = _pcall(common.get_username)
    return ok and _type(u) == "string" and u or ""
end

-- network.get's callback signature is not documented; accept a raw string
-- or a response table with a body field
local function body_of(r)
    if _type(r) == "string" then return r end
    if _type(r) == "table" then
        local b = r.body or r.data or r.text or r[1]
        if _type(b) == "string" then return b end
    end
    return nil
end

local busy = false
local function request(path, on_done)
    if busy then fail("a request is already running"); return end
    if not s_find(state.license, "^[%w%-]+$") then fail("enter a valid license key first"); return end
    busy = true
    local nonce = new_nonce()
    local finished = false
    local function finish(body)
        if finished then return end
        finished, busy = true, false
        on_done(body, nonce)
    end
    utils.execute_after(REQUEST_TIMEOUT, function()
        if not finished then fail("request timed out") end
        finish(nil)
    end)
    local headers = {
        ["X-License"] = state.license,
        ["X-Nonce"] = nonce,
        ["X-User"] = username(),
    }
    local ok, err = _pcall(network.get, SERVER_URL .. path, headers, function(r) finish(body_of(r)) end)
    if not ok then
        fail("network error: " .. _tostring(err))
        finish(nil)
    end
end

-- UI
local group = ui.create("Loader", "Secure loader")
local license_input = group:input("License key", state.license)
local script_list = group:list("Scripts", {"(press Refresh)"})
local status_label = group:label("Status: idle")
local manifest = {}   -- index -> name
local loaded = {}     -- name -> true

local function set_status(text) _pcall(status_label.name, status_label, "Status: " .. text) end

group:button("Save key", function()
    local key = license_input:get()
    if _type(key) ~= "string" then return end
    key = s_gsub(key, "^%s+", ""); key = s_gsub(key, "%s+$", "")
    if not s_find(key, "^[%w%-]+$") or #key > 128 then fail("license key has invalid characters"); return end
    state.license = key
    save_state()
    log("license key saved")
end)

local function refresh()
    set_status("fetching script list...")
    request("/v1/manifest", function(body, nonce)
        local p, why = open_envelope(PUBLIC_KEY, body, {
            kind = "manifest", nonce = nonce, username = username(), now = common.get_unixtime(),
        }, json.parse)
        if not p then set_status("error"); fail("manifest rejected: " .. why); return end
        manifest = {}
        local names = {}
        for _, entry in _pairs(p.scripts) do
            if _type(entry) == "table" and url_component_ok(entry.name) then
                manifest[#manifest + 1] = entry.name
                names[#names + 1] = s_format("%s  (v%s)", entry.name, _tostring(_tonumber(entry.version) or "?"))
            end
        end
        if #names == 0 then names[1] = "(no scripts available)" end
        script_list:update(names)
        set_status(#manifest .. " script(s) available")
    end)
end

local function load_selected()
    local idx = _tonumber(script_list:get())
    local name = idx and manifest[idx]
    if not name then fail("select a script first"); return end
    if loaded[name] then fail(name .. " is already loaded"); return end

    set_status("downloading " .. name .. "...")
    request("/v1/script/" .. name, function(body, nonce)
        local p, why = open_envelope(PUBLIC_KEY, body, {
            kind = "script", name = name, nonce = nonce, username = username(),
            now = common.get_unixtime(), min_version = _tonumber(state.versions[name]) or 0,
        }, json.parse)
        if not p then set_status("error"); fail(name .. " rejected: " .. why); return end

        local fn, err = compile(p.code, "=" .. name, make_env(_G))
        if not fn then set_status("error"); fail(name .. " failed to compile: " .. _tostring(err)); return end

        -- record the version before running so a crashing script still advances the floor
        state.versions[name] = _tonumber(p.version)
        save_state()
        loaded[name] = true

        local ok, rerr = _pcall(fn)
        if not ok then
            set_status("error")
            fail(name .. " errored: " .. _tostring(rerr))
            return
        end
        set_status(name .. " v" .. _tostring(p.version) .. " loaded")
        log(s_format("loaded %s v%s (signature verified)", name, _tostring(p.version)))
    end)
end

group:button("Refresh", refresh)
group:button("Load selected", load_selected)

if state.license ~= "" then refresh() end
