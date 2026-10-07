function _xorHexDecode(hexStr, key) {

    let out = '';
    for (let i = 0; i < hexStr.length; i += 2) {
        const byte = parseInt(hexStr.substr(i, 2), 16) ^ key;
        out += String.fromCharCode(byte);
    }
    return out;
}

function _assembleChunks(chunks, key) {

    let full = '';
    for (let i = 0; i < chunks.length; i++) {
        full += _xorHexDecode(chunks[i], key);
        chunks[i] = null;
    }
    return full;
}

function _extractCode(cRes) {

    if (cRes && typeof cRes.encCode === 'string' && cRes.encCode.length > 0) {
        return cRes.encCode;
    }
    if (cRes && Array.isArray(cRes.chunks) && typeof cRes.key === 'number') {
        const code = _assembleChunks(cRes.chunks, cRes.key);
        cRes.chunks = null;
        cRes.key = null;
        return code;
    }
    return (cRes && (cRes.code || cRes.content)) || null;
}

const OLM_USE_AES_GATE = true;
const _K1B_TTL_MS      = 60 * 60 * 1000;
const _KEY_K1B         = '__olm_kv_k1b__';

const _4efdd2=[(27+18),(6+46),(13+41),(167+24),(104+34),(130+38),(78+40),(74+11)];
const _e2470c=254;
const _4667ca=[(97+50),(33+186),(86+37),(96+22),(44+121),(78+67),(144+94),(4+52)];
const _70ee6e=276;
const _EK1a=[..._4efdd2,..._4667ca].map(n=>n.toString(16).padStart(2,'0')).join('');
const _32d0c9=[(6+61),(21+8),(13+224),(15+5),(25+5),(28+19),(39+170),(26+13)];
const _d093c2=251;
const _fddc09=[(1+7),(35+216),(97+80),(60+66),(69+57),(31+48),(118+1),(88+98)];
const _5988ef=695;
const _EIV=[..._32d0c9,..._fddc09].map(n=>n.toString(16).padStart(2,'0')).join('');
const _186068=[(6+23),(55+61),(12+45),(122+91),(130+35),(29+41),(60+0),(190+4),(75+3),(13+13),(7+67),(106+99),(125+78),(30+4),(23+88),(39+29),(156+74),(65+26),(68+61),(23+86),(25+39),(101+61),(74+114),(10+61),(96+47),(0+15),(14+235),(13+161),(29+23),(46+39),(138+63),(79+139)];
const _e300cc=112;
const _3a09d2=[(49+104),(46+11),(133+63),(57+151),(90+144),(118+34),(215+31),(81+74),(15+40),(47+10),(30+53),(63+37),(13+141),(46+67),(59+53),(16+14),(13+20),(134+8),(33+189),(84+41),(42+199),(32+120),(4+16),(108+11),(21+0),(30+78),(108+59),(73+24),(100+71),(32+84),(135+106),(141+90)];
const _d36130=426;
const _EK2=[..._186068,..._3a09d2].map(n=>n.toString(16).padStart(2,'0')).join('');

const _kxppw9=[85,67,146,181,252,53,248,31];
const _ka1=[237,222,124,5,87,214,40,0].map((b,i)=>b^_kxppw9[i]);
const _kxrx4c=[30,157,92,14,64,233,122,13];
const _ka2=[106,21,252,89,136,31,31,45].map((b,i)=>b^_kxrx4c[i]);
const _kxj323=[148,83,95,114,243,58,18,7];
const _ka3=[78,250,43,221,53,73,103,230].map((b,i)=>b^_kxj323[i]);
const _kxsnm9=[251,209,142,140,92,19,215,139];
const _ka4=[80,33,73,114,162,111,243,7].map((b,i)=>b^_kxsnm9[i]);
const _kvAesGateKey=[..._ka1,..._ka2,..._ka3,..._ka4].map(b=>b.toString(16).padStart(2,'0')).join('');

const _KV_AUTO_AES_KEY = '4116c5e296b0d61cf80c813997e8a7f8f0a7af52da09e475f38d5b443db50e64';

function _hexToBytes(h) {
    const b = new Uint8Array(h.length / 2);
    for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
    return b;
}

function _isEncPayload(s) {
    return typeof s === 'string' && s.length > 64 && /^[A-Za-z0-9+\/=\s]+$/.test(s);
}

function _kvErr(msg, flags) {
    const e = new Error(msg);
    if (flags) Object.keys(flags).forEach(function(k) { e[k] = flags[k]; });
    return e;
}

function _kvGetStr(k) {
    try { const v = GM_getValue(k, ''); return typeof v === 'string' ? v : ''; } catch (_) { return ''; }
}

function _kvPrompt(msg) {
    try { return (typeof prompt === 'function' ? (prompt(msg) || '') : '').trim(); } catch (_) { return ''; }
}

function _kvIsTopFrame() {
    try { return window.top === window.self; } catch (_) { return false; }
}

function _kvPromptKeyUI(notice) {
    return new Promise(function(resolve) {
        const ID = '__kv_key_modal__';
        function mount() {
            try {
                if (document.getElementById(ID)) {
                    const t = setInterval(function() {
                        if (!document.getElementById(ID)) { clearInterval(t); resolve(_kvGetStr('_kv_lic')); }
                    }, 300);
                    return;
                }
                let note = notice || '';
                try {
                    const m = sessionStorage.getItem('__kv_modal_msg');
                    if (m) { note = m; sessionStorage.removeItem('__kv_modal_msg'); }
                } catch (_) {}

                const host = document.createElement('div');
                host.id = ID;
                host.style.cssText = 'all:initial;position:fixed;top:0;left:0;right:0;bottom:0;z-index:2147483647;';
                const root = host.attachShadow({ mode: 'closed' });

                const css = document.createElement('style');
                css.textContent = [
                    "*{box-sizing:border-box;font-family:'Segoe UI',system-ui,-apple-system,Roboto,sans-serif}",
                    ".ov{position:fixed;top:0;left:0;right:0;bottom:0;display:flex;align-items:center;justify-content:center;padding:18px;",
                    "background:radial-gradient(900px 500px at 50% 0%,rgba(255,43,214,.22),transparent 60%),radial-gradient(800px 480px at 50% 100%,rgba(0,229,168,.14),transparent 60%),rgba(6,2,12,.94);",
                    "-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px);animation:fade .25s ease}",
                    ".card{position:relative;width:100%;max-width:400px;border-radius:24px;overflow:hidden;",
                    "background:linear-gradient(180deg,#220b1f 0%,#13060f 100%);border:1px solid rgba(255,43,214,.35);",
                    "box-shadow:0 20px 60px rgba(0,0,0,.65),0 0 60px rgba(255,43,214,.18);animation:pop .35s cubic-bezier(.2,.9,.3,1.2)}",
                    ".card:before{content:'';position:absolute;left:0;right:0;top:0;height:3px;",
                    "background:linear-gradient(90deg,#ff2bd6,#00e5a8,#ff2bd6);background-size:200% 100%;animation:slide 3s linear infinite}",
                    ".hd{padding:28px 22px 18px;text-align:center;background:linear-gradient(180deg,rgba(255,43,214,.12),transparent);border-bottom:1px solid rgba(255,43,214,.18)}",
                    ".ic{font-size:36px;line-height:1;filter:drop-shadow(0 0 12px rgba(255,43,214,.7));animation:float 2.4s ease-in-out infinite}",
                    ".tt{margin-top:10px;font-size:19px;font-weight:800;letter-spacing:.06em;color:#ff2bd6;text-shadow:0 0 18px rgba(255,43,214,.55)}",
                    ".st{margin-top:3px;font-size:12px;letter-spacing:.35em;color:#00e5a8;font-weight:700}",
                    ".bd{padding:22px}",
                    ".lb{margin-bottom:14px;text-align:center;font-size:12px;font-weight:600;letter-spacing:.14em;color:#c9b8d6}",
                    ".ms{display:none;margin-bottom:12px;padding:10px 12px;border-radius:12px;text-align:center;font-size:13px;line-height:1.5;",
                    "color:#ffd27a;background:rgba(255,160,0,.10);border:1px solid rgba(255,160,0,.28)}",
                    ".ms.on{display:block}",
                    ".ip{width:100%;padding:15px 16px;border-radius:14px;text-align:center;font-size:16px;letter-spacing:.04em;color:#fff;",
                    "font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#0a0309;border:1.5px solid rgba(255,43,214,.35);",
                    "outline:none;transition:border-color .2s,box-shadow .2s}",
                    ".ip::placeholder{color:#7d6a88;letter-spacing:.02em}",
                    ".ip:focus{border-color:#00e5a8;box-shadow:0 0 0 4px rgba(0,229,168,.15),0 0 24px rgba(0,229,168,.18)}",
                    ".bt{width:100%;margin-top:14px;padding:15px;border:0;border-radius:14px;cursor:pointer;font-size:16px;font-weight:800;letter-spacing:.06em;color:#fff;",
                    "background:linear-gradient(90deg,#00b894,#7bd34a);box-shadow:0 8px 24px rgba(0,200,150,.28);transition:transform .15s,filter .15s}",
                    ".bt:hover{filter:brightness(1.08)}.bt:active{transform:scale(.98)}",
                    ".ft{margin-top:16px;text-align:center;font-size:11px;line-height:1.7;color:#6f5c7a}",
                    ".shake{animation:shake .4s}",
                    "@keyframes fade{from{opacity:0}to{opacity:1}}",
                    "@keyframes pop{from{opacity:0;transform:translateY(14px) scale(.94)}to{opacity:1;transform:none}}",
                    "@keyframes slide{from{background-position:0 0}to{background-position:200% 0}}",
                    "@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-5px)}}",
                    "@keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-9px)}40%{transform:translateX(9px)}60%{transform:translateX(-6px)}80%{transform:translateX(6px)}}"
                ].join('');
                root.appendChild(css);

                function el(tag, cls, text) {
                    const e = document.createElement(tag);
                    if (cls) e.className = cls;
                    if (text) e.textContent = text;
                    return e;
                }
                const ov   = el('div', 'ov');
                const card = el('div', 'card');
                const hd   = el('div', 'hd');
                hd.appendChild(el('div', 'ic', '🚀'));
                hd.appendChild(el('div', 'tt', 'THIÊN TAI TÙ TỘI'));
                hd.appendChild(el('div', 'st', '// GOD MODE'));
                const bd = el('div', 'bd');
                bd.appendChild(el('div', 'lb', '🔐 NHẬP LICENSE KEY ĐỂ KÍCH HOẠT'));
                const ms = el('div', 'ms');
                if (note) { ms.textContent = '⚠ ' + note; ms.className = 'ms on'; }
                bd.appendChild(ms);
                const ip = el('input', 'ip');
                ip.type = 'text';
                ip.placeholder = 'Nhập key bản quyền...';
                ip.setAttribute('autocomplete', 'off');
                ip.setAttribute('autocapitalize', 'off');
                ip.setAttribute('autocorrect', 'off');
                ip.setAttribute('spellcheck', 'false');
                ip.setAttribute('enterkeyhint', 'done');
                bd.appendChild(ip);
                const bt = el('button', 'bt', '🔓 KÍCH HOẠT');
                bt.type = 'button';
                bd.appendChild(bt);
                bd.appendChild(el('div', 'ft', 'Key sẽ được kiểm tra định kỳ · Chống sao chép · Bảo mật HWID'));
                card.appendChild(hd);
                card.appendChild(bd);
                ov.appendChild(card);
                root.appendChild(ov);

                function submit() {
                    const v = String(ip.value || '').trim();
                    if (!v) {
                        ms.textContent = '⚠ Vui lòng nhập License Key để tiếp tục';
                        ms.className = 'ms on';
                        card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake');
                        ip.value = '';
                        try { ip.focus(); } catch (_) {}
                        return;
                    }
                    try { host.remove(); } catch (_) {}
                    resolve(v);
                }
                bt.addEventListener('click', submit);
                ['keydown', 'keyup', 'keypress'].forEach(function(ev) {
                    ip.addEventListener(ev, function(e) {
                        e.stopPropagation();
                        if (ev === 'keydown' && e.key === 'Enter') { e.preventDefault(); submit(); }
                    });
                });

                document.documentElement.appendChild(host);
                setTimeout(function() { try { ip.focus(); } catch (_) {} }, 80);
            } catch (_) {

                resolve(_kvPrompt('🔑 KeyVault — Nhập License Key của bạn:'));
            }
        }
        if (document.documentElement && document.body) mount();
        else document.addEventListener('DOMContentLoaded', mount, { once: true });
    });
}

function _kvToast(msg, ms, force) {
    if (_KV_SILENT && !force) return;
    function show() {
        try {
            const d = document.createElement('div');
            d.style.cssText = 'position:fixed;bottom:12px;right:12px;background:rgba(239,83,80,.95);color:#fff;'
                + 'padding:10px 14px;border-radius:8px;font-size:11px;z-index:2147483647;max-width:300px;'
                + 'line-height:1.5;box-shadow:0 4px 16px rgba(0,0,0,.5);font-family:system-ui,sans-serif';
            d.textContent = msg;
            (document.body || document.documentElement).appendChild(d);
            setTimeout(function() { d.remove(); }, ms || 12000);
        } catch (_) {}
    }
    if (document.body) show();
    else document.addEventListener('DOMContentLoaded', show);
}

function _gmPostJSON(url, bodyObj, timeoutMs) {
    return new Promise(function(resolve, reject) {
        GM_xmlhttpRequest({
            method: 'POST',
            url: url,
            headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' },
            data: JSON.stringify(bodyObj),
            timeout: timeoutMs || 30000,
            onload: function(r) { resolve(r); },
            onerror: function(e) { reject(new Error('Network error: ' + ((e && e.statusText) || 'unknown'))); },
            ontimeout: function() { reject(new Error('Request timeout')); },
            onabort: function() { reject(new Error('Request aborted')); }
        });
    });
}

const _KEY_DEV      = '_kv_dev';
const _TOK_MAX_USES = 55;
let _kvTok        = null;
let _kvTokPromise = null;
let _kvTokFail    = null;
let _kvLegacy     = false;

function _bytesToHex(b) {
    return Array.from(b, function(x) { return x.toString(16).padStart(2, '0'); }).join('');
}
function _b64ToBytes(s) {
    return Uint8Array.from(atob(String(s)), function(c) { return c.charCodeAt(0); });
}

function _kvDeviceId() {
    let d = _kvGetStr(_KEY_DEV);
    if (!/^[A-Za-z0-9_\-]{8,96}$/.test(d)) {
        d = 'VM-' + _bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
        try { GM_setValue(_KEY_DEV, d); } catch (_) {}
    }
    return d;
}

async function _kvUnwrapToken(w, lic) {
    const enc  = new TextEncoder();
    const base = await crypto.subtle.importKey('raw', enc.encode(String(lic).trim().toUpperCase()), 'HKDF', false, ['deriveKey']);
    const wk   = await crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: _b64ToBytes(w.s), info: enc.encode('kvgate-wrap|v1') },
        base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const pt   = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: _b64ToBytes(w.i) }, wk, _b64ToBytes(w.d));
    return _bytesToHex(new Uint8Array(pt));
}

async function _kvTokExchange() {
    const lic = _kvGetStr('_kv_lic');
    if (!lic) throw _kvErr('Chưa có License Key.', { kvLicense: true, kvStop: true });
    const dev = _kvDeviceId();
    const MAX = 4;
    let lastErr = null;
    for (let i = 1; i <= MAX; i++) {
        try {
            const nonce = _bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
            const r = await _gmPostJSON(SERVER_BASE + '/api/g/x', { key: lic, c: nonce, d: dev }, 30000);
            let j = null;
            try { j = JSON.parse(r.responseText); } catch (_) {}

            if (r.status === 404) throw _kvErr('no_gate', { kvNoGate: true });
            if (r.status === 403) {
                if (j && j.error === 'device_limit') {
                    const m = /(\d+)\s*\/\s*(\d+)/.exec(String(j.message || ''));
                    throw _kvErr('Key đã dùng đủ ' + (m ? m[1] + '/' + m[2] + ' ' : '') + 'thiết bị — liên hệ admin để reset thiết bị.', { kvDevice: true, kvStop: true });
                }
                throw _kvErr('License key không hợp lệ hoặc đã hết hạn', { kvLicense: true, kvStop: true });
            }
            if (r.status === 429) throw _kvErr('Gọi server quá nhanh — thử lại sau ít phút.', { kvStop: true });
            if (r.status === 400) throw _kvErr('Server từ chối yêu cầu đổi token (' + String((j && j.error) || 'bad_request').replace(/[^\w-]/g, '') + ').', { kvStop: true });
            if (r.status < 200 || r.status >= 300) throw new Error('HTTP ' + r.status);
            if (!j || j.ok !== true || !j.s || !j.i || !j.d) throw _kvErr('Server trả token không hợp lệ.', { kvStop: true });

            let v;
            try { v = await _kvUnwrapToken(j, lic); }
            catch (_) { throw _kvErr('Giải mã token thất bại — kiểm tra License Key.', { kvStop: true }); }
            if (!/^[0-9a-f]{32}$/.test(v)) throw _kvErr('Token giải mã không hợp lệ.', { kvStop: true });

            const ttl = (typeof j.t === 'number' && j.t > 0) ? j.t * 1000 : 5 * 60 * 1000;
            return { v: v, exp: Date.now() + ttl - 20000, uses: 0 };
        } catch (e) {
            if (e && (e.kvStop || e.kvNoGate)) throw e;
            lastErr = e;
            if (i < MAX) await new Promise(function(res) { setTimeout(res, i * 6000); });
        }
    }
    if (lastErr) lastErr.kvStop = true;
    throw lastErr || _kvErr('Không đổi được token từ server.', { kvStop: true });
}

function _kvTokValid() {
    return !!(_kvTok && Date.now() < _kvTok.exp && _kvTok.uses < _TOK_MAX_USES);
}

async function _kvGetToken(stale) {
    if (_kvLegacy) return null;
    if (_kvTokFail) throw _kvTokFail;
    if (!_kvTokValid() || (stale && _kvTok && _kvTok.v === stale)) {
        if (!_kvTokPromise) {
            _kvTokPromise = _kvTokExchange().then(function(t) {
                _kvTok = t;
            }, function(e) {
                if (e && e.kvNoGate) { _kvLegacy = true; return; }
                _kvTokFail = e;
                throw e;
            }).finally(function() { _kvTokPromise = null; });
        }
        await _kvTokPromise;
        if (_kvLegacy) return null;
    }
    _kvTok.uses++;
    return _kvTok.v;
}

const _LIC_REASON = { expired: 'đã hết hạn', banned: 'đã bị khoá', key_not_found: 'không tồn tại', missing_key: 'đang trống' };

async function _kvGetK1b(lic) {
    let cached = null;
    try { const raw = GM_getValue(_KEY_K1B, null); cached = raw ? JSON.parse(raw) : null; } catch (_) {}
    const haveCache = !!(cached && typeof cached.v === 'string' && /^[0-9a-f]{32}$/i.test(cached.v));
    if (haveCache && Date.now() - cached.t < _K1B_TTL_MS) return cached.v;

    const MAX = 4;
    let lastErr = null;
    for (let i = 1; i <= MAX; i++) {
        try {

            const r = await _gmPostJSON(SERVER_BASE + '/api/snippet-key', { key: lic }, haveCache ? 8000 : 30000);
            let j = null;
            try { j = JSON.parse(r.responseText); } catch (_) {}

            if (r.status === 403 || (j && j.error === 'invalid_key')) {
                const why = (j && j.reason && (_LIC_REASON[j.reason] || j.reason)) || 'không hợp lệ';
                throw _kvErr('License key ' + why, { kvLicense: true });
            }
            if (r.status === 429) throw _kvErr('Gọi server quá nhanh — thử lại sau ít phút.', { kvFatal: true });
            if (r.status < 200 || r.status >= 300) throw new Error('HTTP ' + r.status);
            if (!j || j.ok !== true || !/^[0-9a-f]{32}$/i.test(String(j.data || ''))) {
                throw _kvErr('Server trả khoá giải mã không hợp lệ.', { kvFatal: true });
            }
            try { GM_setValue(_KEY_K1B, JSON.stringify({ v: j.data, t: Date.now() })); } catch (_) {}
            return j.data;
        } catch (e) {
            if (e && e.kvLicense) throw e;
            lastErr = e;
            if (haveCache) break;
            if (e && e.kvFatal) throw e;
            if (i < MAX) await new Promise(function(res) { setTimeout(res, i * 6000); });
        }
    }
    if (haveCache) return cached.v;
    throw lastErr || new Error('Không lấy được khoá giải mã từ server');
}

async function _kvDecrypt(encB64, lic) {
    await _kvGetK1b(lic);
    try {

        const kb  = _hexToBytes(String(_KV_AUTO_AES_KEY).trim().toLowerCase());
        const raw = Uint8Array.from(atob(encB64.replace(/\s+/g, '')), function(c) { return c.charCodeAt(0); });
        const key = await crypto.subtle.importKey('raw', kb, { name: 'AES-CBC' }, false, ['decrypt']);
        const dec = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: raw.slice(0, 16) }, key, raw.slice(16));
        const k2  = new Uint8Array(await crypto.subtle.digest('SHA-512', kb));
        const out = new Uint8Array(dec);
        for (let i = 0; i < out.length; i++) out[i] ^= k2[i % k2.length];
        if (out[0] !== 75 || out[1] !== 86 || out[2] !== 50 || out[3] !== 58) throw new Error('bad_magic');
        return new TextDecoder().decode(out.subarray(4));
    } catch (e) {
        throw _kvErr('Giải mã thất bại — AES key không khớp với server (kiểm tra _KV_AUTO_AES_KEY / biến KV_AES_KEY trên server).', { kvDecrypt: true });
    }
}

function _kvAesGateCheck(inputKey) {

    return typeof inputKey === 'string' && inputKey.trim().toLowerCase() === String(_KV_AUTO_AES_KEY).trim().toLowerCase();
}

let _kvAccessPromise = null;
function _kvEnsureAccess() {

    const sh = (typeof _olmShared !== 'undefined' && _olmShared) ? _olmShared : null;
    if (sh && sh.kvAccess) return sh.kvAccess;
    if (!_kvAccessPromise) {
        _kvAccessPromise = _kvEnsureAccessOnce().finally(function() { _kvAccessPromise = null; if (sh) sh.kvAccess = null; });
        if (sh) sh.kvAccess = _kvAccessPromise;
    }
    return _kvAccessPromise;
}
async function _kvEnsureAccessOnce() {
    let lic = _kvGetStr('_kv_lic');
    if (!lic) {
        if (!_kvIsTopFrame()) return null;
        lic = await _kvPromptKeyUI();
        if (!lic) return null;
        try { GM_setValue('_kv_lic', lic); GM_deleteValue(_KEY_K1B); } catch (_) {}
    }
    if (OLM_USE_AES_GATE) {
        const stored = _kvGetStr('_kv_aes64');
        if (!(stored && _kvAesGateCheck(stored))) {

            const input = String(_KV_AUTO_AES_KEY || '').trim().toLowerCase();
            if (!_kvAesGateCheck(input)) {
                try { GM_setValue('_kv_aes64', ''); } catch (_) {}
                _kvToast('[KeyVault] ❌ AES Key nhúng sẵn trong loader không khớp — cập nhật _KV_AUTO_AES_KEY.');
                return null;
            }
            try { GM_setValue('_kv_aes64', input); } catch (_) {}
        }
    }
    return lic;
}

function _kvKick(reason) {
    try {

        let _recent = false;
        try {
            const last = parseInt(sessionStorage.getItem('__kv_kick_ts') || '0', 10);
            _recent = !!last && (Date.now() - last) < 8000;
            if (!_recent) sessionStorage.setItem('__kv_kick_ts', String(Date.now()));
        } catch (_) {}
        if (!_recent) {
            try { sessionStorage.setItem('__kv_modal_msg', String(reason || 'License key không hợp lệ')); } catch (_) {}
            location.reload();
            return;
        }
        _kvShowKeyMenu(reason || 'License key không hợp lệ');
    } catch (_) {}
}

function _kvShowKeyMenu(reason) {
    try {
        if (!_kvIsTopFrame()) return;
        if (document.getElementById('__kv_key_modal__')) return;
        _kvPromptKeyUI(reason || 'License key không hợp lệ').then(function(lic) {
            if (!lic) return;
            try { GM_setValue('_kv_lic', lic); GM_deleteValue(_KEY_K1B); } catch (_) {}
            location.reload();
        });
    } catch (_) {}
}

function _kvHandleError(err) {
    if (err && err.kvLicense) {
        if (_kvRevoked) return;
        _kvRevoked = true;
        try { GM_setValue('_kv_lic', ''); GM_deleteValue(_KEY_K1B); } catch (_) {}
        _kvPurgeCore();
        _kvKick(err.message);
        return;
    }
    if (err && err.kvDecrypt) { try { GM_deleteValue(_KEY_K1B); } catch (_) {} }
    if (err && err.kvDevice) { _kvShowKeyMenu(err.message); return; }
    _kvToast('[KeyVault] ' + ((err && err.message) || 'Lỗi giải mã/thực thi'), 12000, !!(err && err.kvDevice));
}

async function _kvDecryptAndInject(payload) {
    try {
        const lic = await _kvEnsureAccess();
        if (!lic) return;
        let code = await _kvDecrypt(payload, lic);
        payload = null;
        if (_kvRevoked) { code = null; return; }
        _selfDestructInject(code);
        code = null;
    } catch (err) {
        _kvHandleError(err);
    }
}

function _selfDestructInject(scriptCode) {
    if (!scriptCode) return;

    try { if (typeof _olmShared !== 'undefined' && _olmShared) _olmShared.coreInjected = true; } catch (_) {}
    const root = document.head || document.documentElement;

    try {
        const el = document.createElement('script');
        el.textContent = scriptCode;
        scriptCode = null;
        root.appendChild(el);
        el.remove();
        return;
    } catch (_) {}

    if (scriptCode) {
        try {
            const blob = new Blob([scriptCode], { type: 'application/javascript' });
            const blobUrl = URL.createObjectURL(blob);
            scriptCode = null;
            const el = document.createElement('script');
            el.src = blobUrl;
            el.onload = function() { URL.revokeObjectURL(blobUrl); this.remove(); };
            el.onerror = function() { URL.revokeObjectURL(blobUrl); this.remove(); };
            root.appendChild(el);
        } catch (_) {}
    }
}

const SERVER_BASE = 'https://serverkey-210-0nyo.onrender.com';
const SNIPPET_ID  = '';

const _KV_SILENT   = true;
const _KV_KICK_URL = 'https://olm.vn/lop-hoc-cua-toi';

const _KEY_CODE = '__olm_kv_code2__' + (SNIPPET_ID || 'auto');
const _KEY_META = '__olm_kv_meta2__' + (SNIPPET_ID || 'auto');

const _KV3      = 'KV3:';
const _KV3_INFO = 'kv-vault|v3';

function _kvIsSealed(s) { return typeof s === 'string' && s.indexOf(_KV3) === 0; }

function _bytesToB64(b) {
    let s = '';
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
    return btoa(s);
}

async function _kvVaultKey(salt) {
    const lic = _kvGetStr('_kv_lic');
    if (!lic) throw new Error('no_license');
    const enc  = new TextEncoder();
    const ikm  = enc.encode(String(lic).trim().toUpperCase() + '|' + _kvDeviceId() + '|' + String(_KV_AUTO_AES_KEY).trim().toLowerCase());
    const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
    ikm.fill(0);
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: salt, info: enc.encode(_KV3_INFO) },
        base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function _kvSeal(str) {
    const enc   = new TextEncoder();
    const body  = enc.encode(String(str));
    const padN  = crypto.getRandomValues(new Uint8Array(1))[0];
    const plain = new Uint8Array(4 + body.length + padN);
    new DataView(plain.buffer).setUint32(0, body.length);
    plain.set(body, 4);
    if (padN) plain.set(crypto.getRandomValues(new Uint8Array(padN)), 4 + body.length);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const key  = await _kvVaultKey(salt);
    const ct   = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode(_KV3_INFO) }, key, plain));
    const out  = new Uint8Array(28 + ct.length);
    out.set(salt, 0); out.set(iv, 16); out.set(ct, 28);
    body.fill(0); plain.fill(0);
    return _KV3 + _bytesToB64(out);
}

async function _kvOpen(s) {
    if (!_kvIsSealed(s)) return s;
    try {
        const raw = _b64ToBytes(s.slice(_KV3.length));
        const key = await _kvVaultKey(raw.slice(0, 16));
        const pt  = new Uint8Array(await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: raw.slice(16, 28), additionalData: new TextEncoder().encode(_KV3_INFO) }, key, raw.slice(28)));
        const n   = new DataView(pt.buffer).getUint32(0);
        const out = new TextDecoder().decode(pt.subarray(4, 4 + n));
        pt.fill(0);
        return out;
    } catch (_) { return null; }
}

async function _kvSealSafe(s) { try { return await _kvSeal(s); } catch (_) { return s; } }

async function _kvLoadCore() {
    const raw = _loadCacheCode();
    return raw ? await _kvOpen(raw) : null;
}

async function _kvLoadPart(id) {
    const r = _loadPart(id);
    if (!r || typeof r.p !== 'string') return null;
    const p = await _kvOpen(r.p);
    return p ? { c: r.c, p: p } : null;
}

function _saveCache(code, checksum, updatedAt) {
    if (_kvRevoked) return;
    try {
        GM_setValue(_KEY_CODE, code);
        GM_setValue(_KEY_META, JSON.stringify({ checksum, updatedAt, cachedAt: Date.now() }));
    } catch (_) {}
}
function _loadCacheCode() {
    try { return GM_getValue(_KEY_CODE, null); } catch (_) { return null; }
}
function _loadCacheMeta() {
    try {
        const raw = GM_getValue(_KEY_META, null);
        return raw ? JSON.parse(raw) : null;
    } catch (_) { return null; }
}

const currentHref = window.location.href;
const isTargetPage = currentHref.includes('/chu-de/')
    || currentHref.includes('/bai-kiem-tra/')
    || currentHref.includes('/video')
    || currentHref.includes('/luyen-tap');

function injectScriptToDOM(scriptCode) {

    if (typeof scriptCode === 'string' && scriptCode.indexOf(_KV_MULTI) === 0) {
        let parts = [];
        try { parts = JSON.parse(scriptCode.slice(_KV_MULTI.length)); } catch (_) {}
        scriptCode = null;
        (async function() {
            for (let i = 0; i < parts.length; i++) {
                if (_kvRevoked) break;
                const one = parts[i];
                parts[i] = null;
                if (_isEncPayload(one)) await _kvDecryptAndInject(one);
                else _selfDestructInject(one);
            }
        })();
        return;
    }

    if (_isEncPayload(scriptCode)) {
        _kvDecryptAndInject(scriptCode);
        scriptCode = null;
        return;
    }
    _selfDestructInject(scriptCode);
    scriptCode = null;
}

function _gmFetchOnce(url, tok) {
    return new Promise(function(resolve, reject) {
        GM_xmlhttpRequest({
            method: 'GET',
            url: url,
            headers: (function() {
                const h = { 'Cache-Control': 'no-cache', 'Pragma': 'no-cache' };
                if (tok) {

                    h['X-Script-Token'] = tok;
                } else {

                    const l = _kvGetStr('_kv_lic');
                    if (l) h['X-Script-Key'] = l;
                }
                return h;
            })(),
            timeout: 30000,
            onload: function(r) { resolve(r); },
            onerror: function(e) { reject(new Error('Network error: ' + (e.statusText || 'unknown'))); },
            ontimeout: function() { reject(new Error('Request timeout')); },
            onabort: function() { reject(new Error('Request aborted')); }
        });
    });
}

async function _gmFetch(url) {
    let tok = await _kvGetToken();
    let r = await _gmFetchOnce(url, tok);

    if (tok && r.status === 404 && String(r.responseText || '').indexOf('snippet_not_found') < 0) {
        tok = await _kvGetToken(tok);
        r = await _gmFetchOnce(url, tok);
    }
    return r;
}

async function _fetchJSON(url, label) {
    const MAX = 5;
    for (let i = 1; i <= MAX; i++) {
        try {
            _setStatusText(i === 1 ? ('ĐANG TẢI ' + label + '...') : ('THỬ LẠI LẦN ' + i + '/' + MAX + '...'));
            const r = await _gmFetch(url);
            if (r.status === 502 || r.status === 503) {
                const wait = i * 6;
                _setStatusText('SERVER ĐANG KHỞI ĐỘNG, CHỜ ' + wait + 'S...');
                await new Promise(res => setTimeout(res, wait * 1000));
                continue;
            }
            if (r.status === 404) throw _kvErr('HTTP 404 — snippet không tồn tại hoặc token/License Key không hợp lệ', { kvStop: true });
            if (r.status < 200 || r.status >= 300) throw new Error('HTTP ' + r.status);
            return JSON.parse(r.responseText);
        } catch (e) {
            if (i === MAX || (e && e.kvStop)) throw e;
            await new Promise(res => setTimeout(res, 5000));
        }
    }
}

let _pendingStatus = '';
function _setStatusText(msg) {
    _pendingStatus = msg;
    if (_KV_SILENT) return;
    const el = document.getElementById('ml-statusText');
    if (el) el.textContent = msg;
}

const _KV_MULTI = '\u0001KVMULTI\u0001';
const _KEY_PART = '__olm_kv_part2__';
function _loadPart(id) {
    try { const r = GM_getValue(_KEY_PART + id, null); return r ? JSON.parse(r) : null; } catch (_) { return null; }
}
function _savePart(id, checksum, payload) {
    if (_kvRevoked) return;
    try { GM_setValue(_KEY_PART + id, JSON.stringify({ c: checksum, p: payload })); } catch (_) {}

    try {
        const idx = JSON.parse(GM_getValue(_KEY_PART_IDX, '[]')) || [];
        if (idx.indexOf(id) < 0) { idx.push(id); GM_setValue(_KEY_PART_IDX, JSON.stringify(idx)); }
    } catch (_) {}
}

const _KEY_PART_IDX = '__olm_kv_pidx__';
let   _kvRevoked    = false;

function _kvPurgeCore() {
    const ids = {};

    try { (JSON.parse(GM_getValue(_KEY_PART_IDX, '[]')) || []).forEach(function(id) { ids[id] = 1; }); } catch (_) {}

    try {
        const m = _loadCacheMeta();
        if (m && typeof m.checksum === 'string') {
            m.checksum.split('|').forEach(function(s) { const id = s.split(':')[0]; if (id) ids[id] = 1; });
        }
    } catch (_) {}
    Object.keys(ids).forEach(function(id) { try { GM_deleteValue(_KEY_PART + id); } catch (_) {} });
    [_KEY_CODE, _KEY_META, _KEY_PART_IDX, _KEY_K1B, '__olm_kv_code__auto', '__olm_kv_meta__auto',
     '__olm_kv_code__', '__olm_kv_meta__', '__olm_gh_code__', '__olm_gh_meta__'].forEach(function(k) {
        try { GM_deleteValue(k); } catch (_) {}
    });
}
function _kvPack(list) { return list.length === 1 ? list[0] : _KV_MULTI + JSON.stringify(list); }
function _kvIsJsSnippet(sn) {
    if (!sn || !sn.id) return false;
    if (sn.language) return sn.language === 'javascript';
    return !/\.(lua|py|java|txt|json|md)$/i.test(String(sn.name || ''));
}

async function _kvFetchAndRun(onSuccess, onError) {

    let lic = null;
    try { lic = await _kvEnsureAccess(); } catch (_) {}
    if (!lic) { onError('Chưa có License Key.<br>Reload trang và nhập License Key để tải code.'); return; }
    try { await _kvGetK1b(lic); }
    catch (e) { if (e && e.kvLicense) { _kvHandleError(e); onError(e.message); return; } }

    try { _setStatusText('ĐANG XÁC THỰC THIẾT BỊ...'); await _kvGetToken(); }
    catch (e) { if (e && (e.kvLicense || e.kvDevice)) { _kvHandleError(e); onError(e.message); return; } }

    let targets = [];
    if (SNIPPET_ID) {
        targets = [{ id: SNIPPET_ID }];
    } else {
        try {
            _setStatusText('ĐANG LẤY DANH SÁCH FILE TỪ SERVER...');
            const r = await _gmFetch(SERVER_BASE + '/api/public/snippets');
            if (r.status >= 200 && r.status < 300) {
                const list = JSON.parse(r.responseText);
                if (Array.isArray(list)) targets = list.filter(_kvIsJsSnippet);
            }
        } catch (le) {
            const cc = await _kvLoadCore();
            if (cc) {
                _setStatusText('OFFLINE — ĐANG DÙNG CACHE...');
                onSuccess(cc, 'cache-offline');
                return;
            }
            onError((le && le.kvStop && le.message) ? le.message : 'Không kết nối được server và chưa có cache.');
            return;
        }
    }

    if (!targets.length) {
        const cc0 = await _kvLoadCore();
        if (cc0) { onSuccess(cc0, 'cache-fallback'); return; }
        onError('Server chưa có file .js nào (hoặc License Key không hợp lệ).');
        return;
    }

    _setStatusText('ĐANG KIỂM TRA ' + targets.length + ' FILE TRÊN SERVER...');
    const results = await Promise.all(targets.map(async function(t) {
        const part = await _kvLoadPart(t.id);
        let v = null;
        try {
            v = await _fetchJSON(SERVER_BASE + '/api/public/snippet/' + t.id + '/version', 'VERSION');
        } catch (e) {
            return part ? { state: 'offline', payload: part.p } : { err: e };
        }
        const ck = (v && v.checksum) || null;
        if (part && ck && part.c === ck) return { state: 'cache', payload: part.p, ck: ck, at: v && v.updatedAt };
        try {
            let cRes = await _fetchJSON(SERVER_BASE + '/api/public/snippet/' + t.id, 'CORE');
            const p = _extractCode(cRes);
            cRes = null;
            if (!p || p.trim().length < 10) throw new Error('Server trả về code rỗng.');
            _savePart(t.id, ck, await _kvSealSafe(p));
            return { state: 'updated', payload: p, ck: ck, at: v && v.updatedAt };
        } catch (e) {
            return part ? { state: 'fallback', payload: part.p, ck: ck } : { err: e };
        }
    }));

    const ok = results.filter(function(x) { return x && x.payload; });
    if (!ok.length) {
        const cc = await _kvLoadCore();
        if (cc) { _setStatusText('TẢI THẤT BẠI — DÙNG CACHE CŨ...'); onSuccess(cc, 'cache-fallback'); return; }
        const firstErr = results.find(function(x) { return x && x.err; });
        onError(((firstErr && firstErr.err && firstErr.err.message) || 'Lỗi tải code') + '<br>Không có cache dự phòng.');
        return;
    }

    const updated = ok.filter(function(x) { return x.state === 'updated'; });
    const allOffline = ok.every(function(x) { return x.state === 'offline'; });
    const packed = _kvPack(ok.map(function(x) { return x.payload; }));
    const sig = ok.map(function(x, i) { return (targets[i] && targets[i].id || i) + ':' + (x.ck || ''); }).join('|');
    const latestAt = ok.map(function(x) { return x.at; }).filter(Boolean).sort().pop() || null;
    _saveCache(await _kvSealSafe(packed), sig, latestAt);

    if (allOffline) { _setStatusText('OFFLINE — DÙNG CACHE...'); onSuccess(packed, 'cache-offline'); return; }
    if (updated.length) {
        _setStatusText('🔄 ĐÃ CẬP NHẬT ' + updated.length + '/' + ok.length + ' FILE' + (latestAt ? ': ' + new Date(latestAt).toLocaleString('vi-VN') : ''));
        onSuccess(packed, 'fresh');
        return;
    }
    _setStatusText('✔ ' + ok.length + ' FILE ĐÃ MỚI NHẤT — KHỞI ĐỘNG...');
    onSuccess(packed, 'cache-fresh');
}

(function _antiDevTools() {
    'use strict';

    try {
        if (typeof _olmShared !== 'undefined' && _olmShared) {
            if (_olmShared.dtInstalled) return;
            _olmShared.dtInstalled = true;
        }
    } catch (_) {}

    const _noop = function(){};
    let _dtHandled = false;

    function _onDevToolsDetected(source) {
        if (_dtHandled) return;
        _dtHandled = true;

        try { GM_deleteValue('__olm_kv_code__auto'); } catch(_) {}
        try { GM_deleteValue('__olm_kv_meta__auto'); } catch(_) {}
        try { GM_deleteValue(_KEY_CODE); } catch(_) {}
        try { GM_deleteValue(_KEY_META); } catch(_) {}
        try { GM_deleteValue('__olm_kv_k1b__'); } catch(_) {}

        try {
            for (const k of Object.keys(sessionStorage)) {
                if (k.includes('olm') || k.includes('tiep') || k.includes('kv')) {
                    sessionStorage.removeItem(k);
                }
            }
        } catch(_) {}

        try {
            const _dead = function() { return undefined; };
            ['log','warn','error','info','debug','table','dir','dirxml','group','groupEnd','trace','assert','count','time','timeEnd'].forEach(function(m) {
                try { console[m] = _dead; } catch(_) {}
            });
        } catch(_) {}

        try {
            window.fetch = function() { return new Promise(function(){}); };
            const _deadXHR = function() {
                return { open:_noop, send:_noop, setRequestHeader:_noop,
                         addEventListener:_noop, abort:_noop, getAllResponseHeaders:_noop };
            };
            window.XMLHttpRequest = _deadXHR;
            window.XMLHttpRequest.prototype = {};
        } catch(_) {}

        try {
            document.documentElement.innerHTML = [
                '<html><head><style>',
                '*{margin:0;padding:0;box-sizing:border-box}',
                'body{background:#000;color:#0f0;font-family:"Courier New",monospace;',
                'display:flex;align-items:center;justify-content:center;height:100vh;',
                'user-select:none}',
                'pre{font-size:13px;line-height:2;border:1px solid #0f0;',
                'padding:40px;box-shadow:0 0 30px #0f05}',
                '</style></head><body>',
                '<pre>',
                '&#9608;&#9608;&#9608; ACCESS DENIED &#9608;&#9608;&#9608;\n\n',
                'Security violation detected.\n',
                'Session terminated.\n\n',
                'Code: SEC-' + source + '-' + Date.now().toString(36).toUpperCase() + '\n\n',
                'All cached data has been purged.',
                '</pre></body></html>'
            ].join('');
        } catch(_) {}

        try {
            history.pushState(null, '', location.href);
            window.onpopstate = function() { history.pushState(null, '', location.href); };

        } catch(_) {}

        let _lockCount = 0;
        const _lockInterval = setInterval(function() {
            _lockCount++;
            try { document.title = '⛔ ACCESS DENIED'; } catch(_) {}
            try {
                window.fetch = function() { return new Promise(function(){}); };
            } catch(_) {}
            if (_lockCount > 60) clearInterval(_lockInterval);
        }, 1000);
    }

    const _DT_W_THRESHOLD = 200;
    const _isMobile = /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent);
    let _sizeOpenCount = 0;
    function _checkSize() {

        if (_isMobile) return;
        const wDiff = window.outerWidth - window.innerWidth;
        const open  = wDiff > _DT_W_THRESHOLD;
        if (open) {
            _sizeOpenCount++;

            if (_sizeOpenCount >= 3) _onDevToolsDetected('SIZE');
        } else {
            _sizeOpenCount = 0;
        }
    }
    setInterval(_checkSize, 600);

    function _checkTiming() {
        if (_isMobile) return;
        const t0 = performance.now();
        (function(){ try { (new Function('debugger'))(); } catch(_){} })();
        if (performance.now() - t0 > 200) _onDevToolsDetected('TIMING');
    }
    setInterval(_checkTiming, 1200);

    if (!_isMobile) {
        try {
            const _workerCode = [
                'var _last = Date.now();',
                'setInterval(function(){',
                '  (new Function("debugger"))();',
                '  var now = Date.now();',
                '  if(now - _last > 500) postMessage("DT_DETECTED");',
                '  _last = now;',
                '}, 150);'
            ].join('\n');
            const _blob   = new Blob([_workerCode], {type:'application/javascript'});
            const _wUrl   = URL.createObjectURL(_blob);
            const _worker = new Worker(_wUrl);
            _worker.onmessage = function(e) {
                if (e.data === 'DT_DETECTED') _onDevToolsDetected('WORKER');
            };
            URL.revokeObjectURL(_wUrl);
        } catch(_) {}
    }

    if (!_isMobile) {
        try {
            let _consoleTrapCount = 0;
            let _consoleTrapTimer = null;
            let _trap = /./;
            _trap.toString = function() {
                _consoleTrapCount++;
                clearTimeout(_consoleTrapTimer);
                _consoleTrapTimer = setTimeout(function() { _consoleTrapCount = 0; }, 2000);
                if (_consoleTrapCount >= 3) {
                    _onDevToolsDetected('CONSOLE_TRAP');
                }
                return '';
            };
        } catch(_) {}
    }

    document.addEventListener('keydown', function(e) {
        if (e.key === 'F12' || e.keyCode === 123) {
            e.preventDefault(); e.stopImmediatePropagation(); return false;
        }
        if (e.ctrlKey && e.shiftKey && ['I','i','J','j','C','c','K','k'].indexOf(e.key) !== -1) {
            e.preventDefault(); e.stopImmediatePropagation(); return false;
        }
        if (e.ctrlKey && ['U','u','S','s'].indexOf(e.key) !== -1) {
            e.preventDefault(); e.stopImmediatePropagation(); return false;
        }

        if (e.altKey && e.metaKey && (e.key === 'I' || e.key === 'i')) {
            e.preventDefault(); e.stopImmediatePropagation(); return false;
        }
    }, true);

    document.addEventListener('contextmenu', function(e) {
        e.preventDefault(); e.stopImmediatePropagation(); return false;
    }, true);

    if (!_isMobile) {
        try {
            const _fStr = Function.prototype.toString;
            const _expected = _fStr.call(_fStr).length;
            let _fnstrMismatchCount = 0;
            setInterval(function() {
                try {
                    if (_fStr.call(_fStr).length !== _expected) {
                        _fnstrMismatchCount++;
                        if (_fnstrMismatchCount >= 2) _onDevToolsDetected('FNSTR');
                    } else {
                        _fnstrMismatchCount = 0;
                    }
                } catch(_) {}
            }, 2000);
        } catch(_) {}
    }

    document.addEventListener('dragover',  function(e){ e.preventDefault(); }, true);
    document.addEventListener('drop',      function(e){ e.preventDefault(); }, true);

})();

(async function _kvMain() {
    if (typeof GM_xmlhttpRequest !== 'function' || typeof GM_getValue !== 'function'
        || typeof GM_setValue !== 'function' || typeof GM_deleteValue !== 'function') {

        _kvToast('[KeyVault] Thiếu GM_* (mods.js đang chạy ngoài sandbox userscript). Hãy cập nhật Olm_loader-github.js bản mới nhất trong Tampermonkey/Violentmonkey.', 20000, true);
        return;
    }
    const _fail = function(err) {
        _kvToast('[KeyVault] ' + String((err && err.message) || err || 'Lỗi không xác định').replace(/<br\s*\/?>/gi, ' '));
    };

    if (!_kvGetStr('_kv_lic') && _loadCacheCode()) _kvPurgeCore();

    const _coreRunning = function() { return !!(typeof _olmShared !== 'undefined' && _olmShared && _olmShared.coreInjected); };
    const cachedCore = await _kvLoadCore();
    if (cachedCore) {

        if (!_coreRunning()) injectScriptToDOM(cachedCore);
        _kvFetchAndRun(
            function() {  },
            function() {  }
        ).catch(function() {});
    } else {
        _kvFetchAndRun(function(code) { if (!_coreRunning()) injectScriptToDOM(code); }, _fail).catch(_fail);
    }
})().catch(function() {});
