/* ================================================================
  CODE KÉO & CHẠY MÃ HOÁ TỪ SERVER — KEYVAULT DECRYPT SYSTEM
  Trích xuất từ: Olm_loader-autokey.js (OLM GOD MODE v2.1)
  Tác giả: Thiên Tai Tù Tội
================================================================

TỔNG QUAN LUỒNG MÃ HOÁ:
  [v2] code gốc → XOR(SHA-512(AES_key)) → AES-256-CBC → base64 = "encCode"
  Luồng giải mã:
    1. License Key  →  AES Key Gate kiểm tra
    2. License Key  →  POST /api/snippet-key  →  k1b (xác thực key còn hạn)
    3. License Key  →  POST /api/g/x + nonce + device_id  →  token 128-bit (AES-GCM wrapped)
    4. Token 128-bit  →  X-Script-Token header  →  GET /api/public/snippet/:id
    5. Server trả encCode (base64)  →  AES-256-CBC decrypt  →  XOR SHA-512  →  "KV2:" + code
    6. injectScriptToDOM(code)  →  _selfDestructInject  →  <script> tag tự xóa
  
  SERVER: https://serverkey-210-0nyo.onrender.com
  AES KEY (cố định): 4116c5e296b0d61cf80c813997e8a7f8f0a7af52da09e475f38d5b443db50e64

  [v2.2] Key bị BAN / HẾT HẠN / KHÔNG TỒN TẠI → tự xoá file.js đã lưu trong GM storage
         (xem _kvPurgeCore) và không kéo lại code từ server cho tới khi nhập key hợp lệ.

  [v2.3] Key bị BAN / HẾT HẠN / KHÔNG TỒN TẠI → xoá file.js đã lưu rồi TỰ CHUYỂN sang trang
         "Lớp học của tôi" (_KV_KICK_URL = https://olm.vn/lop-hoc-cua-toi) — xem _kvKick.
  [v2.5] Key bị BAN / HẾT HẠN / KHÔNG TỒN TẠI ở MỌI trang olm.vn → xoá sạch file.js đã lưu + LOAD LẠI TRANG NGAY (xem _kvKick / _kvPurgeCore).

  [v2.4] Key bị BAN / HẾT HẠN / KHÔNG TỒN TẠI mà đang đứng sẵn ở trang "Lớp học của tôi" → LOAD LẠI TRANG NGAY (xem _kvKick).

  [v2.3] Kéo file.js chạy NGẦM hoàn toàn (_KV_SILENT = true): không status text, không toast, không log.
  [v2.3] VAULT v3: mỗi lần kéo, cache được MÃ HOÁ LẠI bằng khoá ngẫu nhiên mới (AES-256-GCM, khoá dẫn xuất
         từ License Key + mã thiết bị + salt mới, đệm độ dài ngẫu nhiên) — xem _kvSeal / _kvOpen.

================================================================ */

/* ============================================================
   CHUNK LOADING — XOR split/join trong memory
   Server phải trả { chunks: ["hex1","hex2",...], key: number }
   hoặc trả { code/content: "..." } như cũ (tự động fallback)
   ============================================================ */
function _xorHexDecode(hexStr, key) {
    // hexStr: chuỗi hex, key: số 0-255
    let out = '';
    for (let i = 0; i < hexStr.length; i += 2) {
        const byte = parseInt(hexStr.substr(i, 2), 16) ^ key;
        out += String.fromCharCode(byte);
    }
    return out;
}

function _assembleChunks(chunks, key) {
    // Ghép các chunk, XOR từng chunk với key, trả về code hoàn chỉnh
    let full = '';
    for (let i = 0; i < chunks.length; i++) {
        full += _xorHexDecode(chunks[i], key);
        chunks[i] = null; // Xóa ngay chunk đã dùng
    }
    return full;
}

function _extractCode(cRes) {
    // Hỗ trợ cả 2 format: chunk mới và code string cũ
    // [v1.9] Server mã hoá snippet → trả { code:null, encCode:"<base64>" }.
    //        Giữ nguyên blob mã hoá (cache cũng lưu dạng mã hoá), chỉ giải mã ngay trước khi inject.
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

/* ============================================================
   [v1.9] KEYVAULT DECRYPT — kéo & chạy code MÃ HOÁ từ server
   ------------------------------------------------------------
   Server (index.js) mã hoá snippet ngay khi upload:
     [v2] code gốc → XOR(SHA-512(key)) → AES-256-CBC(key cố định, iv) → base64 = "encCode"
   • k1a, iv, k2 : nhúng sẵn trong loader (KEY BLOCK bên dưới —
                   chính là khối khoá của Violentmonkey Loader)
   • k1b         : server chỉ trả khi License Key còn hạn
                   (POST /api/snippet-key)
   Luồng: License Key → AES Key Gate → k1b → giải mã → inject như cũ.
   Toàn bộ phần còn lại của loader giữ nguyên.
   ============================================================ */
const OLM_USE_AES_GATE = true;            // false = bỏ bước nhập AES 64-bit Key
const _K1B_TTL_MS      = 60 * 60 * 1000;  // nhớ k1b 1 giờ (0 = hỏi server mỗi lần tải trang)
const _KEY_K1B         = '__olm_kv_k1b__';

/* >>> KEY BLOCK — khi server đổi key: GET /api/admin/encryption-keys
       rồi dán đè 3 đoạn k1a_code / iv_code / k2_code vào đây <<< */
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
/* <<< HẾT KEY BLOCK <<< */

/* >>> AES GATE KEY BLOCK — lấy từ Violentmonkey Loader (ô "AES 64-bit Key") <<< */
const _kxppw9=[85,67,146,181,252,53,248,31];
const _ka1=[237,222,124,5,87,214,40,0].map((b,i)=>b^_kxppw9[i]);
const _kxrx4c=[30,157,92,14,64,233,122,13];
const _ka2=[106,21,252,89,136,31,31,45].map((b,i)=>b^_kxrx4c[i]);
const _kxj323=[148,83,95,114,243,58,18,7];
const _ka3=[78,250,43,221,53,73,103,230].map((b,i)=>b^_kxj323[i]);
const _kxsnm9=[251,209,142,140,92,19,215,139];
const _ka4=[80,33,73,114,162,111,243,7].map((b,i)=>b^_kxsnm9[i]);
const _kvAesGateKey=[..._ka1,..._ka2,..._ka3,..._ka4].map(b=>b.toString(16).padStart(2,'0')).join('');
/* <<< HẾT AES GATE KEY BLOCK <<< */

/* >>> AUTO AES KEY — loader tự dùng key này, không còn hộp thoại nhập AES 64-bit Key <<< */
const _KV_AUTO_AES_KEY = '4116c5e296b0d61cf80c813997e8a7f8f0a7af52da09e475f38d5b443db50e64';   // phải trùng biến KV_AES_KEY trên Render
/* <<< HẾT AUTO AES KEY <<< */

function _hexToBytes(h) {
    const b = new Uint8Array(h.length / 2);
    for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
    return b;
}

// Blob base64 thuần (không có ký tự của JS như ( ) ; { }) → là code đã mã hoá
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

function _kvToast(msg, ms, force) {
    if (_KV_SILENT && !force) return;   // [v2.3] chạy ngầm: không hiện toast (trừ thông báo người dùng bắt buộc phải biết: force = true)
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

/* ============================================================
   [v2.1] TOKEN 128-BIT — server mới (Vault Shield) KHÔNG còn nhận License Key ở
   /api/public/snippets, /api/public/snippet/:id/version, /api/public/snippet/:id.
   Các endpoint kéo code chỉ nhận header X-Script-Token (128-bit).
   Luồng:  License Key + nonce 128-bit + mã thiết bị  →  POST /api/g/x
           → server trả token đã mã hoá { s: salt, i: iv, d: ciphertext‖tag }
           → loader giải bằng HKDF-SHA256(License Key IN HOA) + AES-256-GCM → token 32 hex
           → gắn X-Script-Token cho mọi request kéo danh sách / version / code.
   • Token sống ~5 phút, tối đa 60 lượt → hết hạn / hết lượt thì tự đổi token mới, thử lại 1 lần.
   • Mã thiết bị (_kv_dev) tạo 1 lần rồi lưu GM storage — server dùng để giới hạn số thiết bị / key.
   • Server đời cũ chưa có /api/g/x → tự quay về cách cũ (header X-Script-Key).
   ============================================================ */
const _KEY_DEV      = '_kv_dev';
const _TOK_MAX_USES = 55;     // server cho 60 lượt / token — đổi sớm một chút cho an toàn
let _kvTok        = null;     // { v: '32hex', exp: ms, uses: n } — chỉ giữ trong RAM
let _kvTokPromise = null;     // gộp nhiều request song song vào 1 lần đổi token
let _kvTokFail    = null;     // lỗi đổi token đã chốt → không gọi lại server trong phiên trang này
let _kvLegacy     = false;    // true = server không có /api/g/x → dùng X-Script-Key như bản cũ

function _bytesToHex(b) {
    return Array.from(b, function(x) { return x.toString(16).padStart(2, '0'); }).join('');
}
function _b64ToBytes(s) {
    return Uint8Array.from(atob(String(s)), function(c) { return c.charCodeAt(0); });
}

// Mã thiết bị ổn định: 'VM-' + 32 hex (server yêu cầu 8–96 ký tự A-Z a-z 0-9 _ -)
function _kvDeviceId() {
    let d = _kvGetStr(_KEY_DEV);
    if (!/^[A-Za-z0-9_\-]{8,96}$/.test(d)) {
        d = 'VM-' + _bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
        try { GM_setValue(_KEY_DEV, d); } catch (_) {}
    }
    return d;
}

// Giải token: khoá bọc = HKDF-SHA256(ikm = License Key IN HOA, salt = s, info = "kvgate-wrap|v1"),
// AES-256-GCM(iv = i) trên (ciphertext ‖ tag) = d  →  16 byte = token 128-bit
async function _kvUnwrapToken(w, lic) {
    const enc  = new TextEncoder();
    const base = await crypto.subtle.importKey('raw', enc.encode(String(lic).trim().toUpperCase()), 'HKDF', false, ['deriveKey']);
    const wk   = await crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: _b64ToBytes(w.s), info: enc.encode('kvgate-wrap|v1') },
        base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const pt   = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: _b64ToBytes(w.i) }, wk, _b64ToBytes(w.d));
    return _bytesToHex(new Uint8Array(pt));
}

// 1 lần đổi token (có retry khi Render đang khởi động). Lỗi đã rõ (key/thiết bị/rate-limit) → dừng ngay.
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

            if (r.status === 404) throw _kvErr('no_gate', { kvNoGate: true });   // server đời cũ — không có /api/g/x
            if (r.status === 403) {
                if (j && j.error === 'device_limit') {
                    const m = /(\d+)\s*\/\s*(\d+)/.exec(String(j.message || ''));
                    throw _kvErr('Key đã dùng đủ ' + (m ? m[1] + '/' + m[2] + ' ' : '') + 'thiết bị — liên hệ admin để reset thiết bị.', { kvDevice: true, kvStop: true });
                }
                throw _kvErr('License key không hợp lệ hoặc đã hết hạn', { kvLicense: true, kvStop: true });
            }
            if (r.status === 429) throw _kvErr('Gọi server quá nhanh — thử lại sau ít phút.', { kvStop: true });
            if (r.status === 400) throw _kvErr('Server từ chối yêu cầu đổi token (' + String((j && j.error) || 'bad_request').replace(/[^\w-]/g, '') + ').', { kvStop: true });
            if (r.status < 200 || r.status >= 300) throw new Error('HTTP ' + r.status);   // 502/503: server đang khởi động → thử lại
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

// Trả token đang dùng được (tự đổi mới nếu hết hạn / hết lượt). stale = token vừa bị server từ chối → buộc đổi.
// Trả null nếu server đời cũ (không có /api/g/x). Ném lỗi (kvStop) nếu không đổi được.
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

/* k1b = ½ sau của AES key. Có cache còn hạn → dùng luôn (giữ tốc độ inject như bản cũ,
   và tránh giới hạn 20 request/phút/IP của /api/snippet-key). */
async function _kvGetK1b(lic) {
    let cached = null;
    try { const raw = GM_getValue(_KEY_K1B, null); cached = raw ? JSON.parse(raw) : null; } catch (_) {}
    const haveCache = !!(cached && typeof cached.v === 'string' && /^[0-9a-f]{32}$/i.test(cached.v));
    if (haveCache && Date.now() - cached.t < _K1B_TTL_MS) return cached.v;

    const MAX = 4;
    let lastErr = null;
    for (let i = 1; i <= MAX; i++) {
        try {
            // Có k1b cũ thì chỉ chờ tối đa 8s rồi dùng tạm — không để trang đứng chờ Render khởi động
            const r = await _gmPostJSON(SERVER_BASE + '/api/snippet-key', { key: lic }, haveCache ? 8000 : 30000);
            let j = null;
            try { j = JSON.parse(r.responseText); } catch (_) {}

            if (r.status === 403 || (j && j.error === 'invalid_key')) {
                const why = (j && j.reason && (_LIC_REASON[j.reason] || j.reason)) || 'không hợp lệ';
                throw _kvErr('License key ' + why, { kvLicense: true });
            }
            if (r.status === 429) throw _kvErr('Gọi server quá nhanh — thử lại sau ít phút.', { kvFatal: true });
            if (r.status < 200 || r.status >= 300) throw new Error('HTTP ' + r.status); // 502/503: server đang khởi động
            if (!j || j.ok !== true || !/^[0-9a-f]{32}$/i.test(String(j.data || ''))) {
                throw _kvErr('Server trả khoá giải mã không hợp lệ.', { kvFatal: true });
            }
            try { GM_setValue(_KEY_K1B, JSON.stringify({ v: j.data, t: Date.now() })); } catch (_) {}
            return j.data;
        } catch (e) {
            if (e && e.kvLicense) throw e;      // license sai / hết hạn / bị khoá → dừng hẳn
            lastErr = e;
            if (haveCache) break;               // có k1b cũ → dùng tạm, khỏi chờ
            if (e && e.kvFatal) throw e;
            if (i < MAX) await new Promise(function(res) { setTimeout(res, i * 6000); });
        }
    }
    if (haveCache) return cached.v;             // offline / server ngủ → dùng k1b đã nhớ (giống 'cache-offline')
    throw lastErr || new Error('Không lấy được khoá giải mã từ server');
}

async function _kvDecrypt(encB64, lic) {
    await _kvGetK1b(lic);   // vẫn xác thực License Key với server (giữ nguyên như cũ)
    try {
        // [v2] Chỉ cần AES key cố định _KV_AUTO_AES_KEY — server đổi/nạp file thế nào cũng giải mã được.
        // Blob: IV(16) || AES-256-CBC( XOR_SHA512(key)( "KV2:" + code ) )
        const kb  = _hexToBytes(String(_KV_AUTO_AES_KEY).trim().toLowerCase());
        const raw = Uint8Array.from(atob(encB64.replace(/\s+/g, '')), function(c) { return c.charCodeAt(0); });
        const key = await crypto.subtle.importKey('raw', kb, { name: 'AES-CBC' }, false, ['decrypt']);
        const dec = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: raw.slice(0, 16) }, key, raw.slice(16)); // Layer 2: AES-256-CBC
        const k2  = new Uint8Array(await crypto.subtle.digest('SHA-512', kb));
        const out = new Uint8Array(dec);
        for (let i = 0; i < out.length; i++) out[i] ^= k2[i % k2.length];                                        // Layer 1: XOR
        if (out[0] !== 75 || out[1] !== 86 || out[2] !== 50 || out[3] !== 58) throw new Error('bad_magic');   // "KV2:"
        return new TextDecoder().decode(out.subarray(4));
    } catch (e) {
        throw _kvErr('Giải mã thất bại — AES key không khớp với server (kiểm tra _KV_AUTO_AES_KEY / biến KV_AES_KEY trên server).', { kvDecrypt: true });
    }
}

function _kvAesGateCheck(inputKey) {
    // [v2.0] So khớp với AES key nhúng sẵn (_KV_AUTO_AES_KEY) — khối _kvAesGateKey cũ không còn dùng
    return typeof inputKey === 'string' && inputKey.trim().toLowerCase() === String(_KV_AUTO_AES_KEY).trim().toLowerCase();
}

// License Key (nhập 1 lần, lưu lại) → AES 64-bit Key Gate. Trả về license key, hoặc null nếu bị chặn.
let _kvAccessPromise = null;
function _kvEnsureAccess() {
    if (!_kvAccessPromise) {   // tránh bật 2 hộp thoại cùng lúc nếu có 2 lần inject chồng nhau
        _kvAccessPromise = _kvEnsureAccessOnce().finally(function() { _kvAccessPromise = null; });
    }
    return _kvAccessPromise;
}
async function _kvEnsureAccessOnce() {
    let lic = _kvGetStr('_kv_lic');
    if (!lic) {
        lic = _kvPrompt('🔑 KeyVault — Nhập License Key của bạn:');
        if (!lic) {
            _kvToast('[KeyVault] ⛔ Yêu cầu License Key — liên hệ admin để mua key. Reload trang để thử lại.', 12000, true);
            return null;
        }
        try { GM_setValue('_kv_lic', lic); GM_deleteValue(_KEY_K1B); } catch (_) {}
    }
    if (OLM_USE_AES_GATE) {
        const stored = _kvGetStr('_kv_aes64');
        if (!(stored && _kvAesGateCheck(stored))) {
            // [AUTO-KEY] Không hỏi người dùng nữa — tự dùng AES Key nhúng sẵn, xử lý ngầm
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

/* ============================================================
   [v2.3] KEY BỊ BAN / HẾT HẠN / KHÔNG TỒN TẠI → TỰ CHUYỂN SANG "LỚP HỌC CỦA TÔI"
   ------------------------------------------------------------
   Gọi từ _kvHandleError sau khi đã xoá License Key + file.js đã lưu (_kvPurgeCore).
   • location.replace → trang cũ không nằm trong lịch sử, nút Back không quay lại được.
   • Đã đứng sẵn ở trang đích thì KHÔNG chuyển nữa (tránh vòng lặp load liên tục) —
     chỉ báo lý do để người dùng nhập key khác.
   ============================================================ */
function _kvKick(reason) {
    try {
        // [v2.5] Key bị BAN / HẾT HẠN / KHÔNG TỒN TẠI ở BẤT KỲ trang nào của olm.vn → LOAD LẠI TRANG NGAY
        //        (không còn chuyển sang "Lớp học của tôi" nữa). File.js đã lưu đã bị xoá sạch ở _kvHandleError
        //        (_kvPurgeCore) và License Key đã bị xoá → sau khi reload sẽ hỏi nhập key mới, không tự chạy lại.
        //        Chốt an toàn: nếu vừa reload vì lý do này trong 8 giây gần nhất thì không reload nữa, chỉ báo
        //        (tránh vòng lặp reload vô hạn nếu xoá key thất bại).
        let _recent = false;
        try {
            const last = parseInt(sessionStorage.getItem('__kv_kick_ts') || '0', 10);
            _recent = !!last && (Date.now() - last) < 8000;
            if (!_recent) sessionStorage.setItem('__kv_kick_ts', String(Date.now()));
        } catch (_) {}
        if (!_recent) { location.reload(); return; }
        _kvToast('[KeyVault] ' + (reason || 'License key không hợp lệ'), 8000, true);
    } catch (_) {}
}

function _kvHandleError(err) {
    if (err && err.kvLicense) {   // license sai/hết hạn/bị khoá → xoá để lần sau hỏi lại
        if (_kvRevoked) return;   // [NEW] luồng khác đã xử lý rồi (tránh xoá + báo 2 lần)
        _kvRevoked = true;        // [NEW] từ đây không ghi lại cache trong phiên trang này
        try { GM_setValue('_kv_lic', ''); GM_deleteValue(_KEY_K1B); } catch (_) {}
        _kvPurgeCore();           // [NEW] xoá luôn file.js đã lưu → không tự chạy / tự kéo lại nữa
        _kvKick(err.message);     // [v2.3] key bị ban / hết hạn / không tồn tại → tự chuyển sang trang "Lớp học của tôi" trên olm.vn (xem _kvKick)
        return;
    }
    if (err && err.kvDecrypt) { try { GM_deleteValue(_KEY_K1B); } catch (_) {} }
    _kvToast('[KeyVault] ' + ((err && err.message) || 'Lỗi giải mã/thực thi'), 12000, !!(err && err.kvDevice));   // [v2.3] chỉ lỗi "hết thiết bị" mới báo (người dùng cần liên hệ admin); còn lại im lặng
}

async function _kvDecryptAndInject(payload) {
    try {
        const lic = await _kvEnsureAccess();
        if (!lic) return;
        let code = await _kvDecrypt(payload, lic);
        payload = null;
        if (_kvRevoked) { code = null; return; }   // [NEW] key vừa bị từ chối ở luồng khác → không chạy file.js nữa
        _selfDestructInject(code);   // từ đây giữ nguyên cơ chế inject tự huỷ như cũ
        code = null;
    } catch (err) {
        _kvHandleError(err);
    }
}

/* ============================================================
   CODE TỰ HỦY — inject xong là xóa sạch mọi dấu vết
   textContent là primary (không bị CSP blob-src chặn trên OLM)
   ============================================================ */
function _selfDestructInject(scriptCode) {
    if (!scriptCode) return;
    // [NEW] loader tự cập nhật mods.js mỗi 2 phút → báo "core đã chạy trên trang này" để lần chạy lại không nạp đôi
    try { if (typeof _olmShared !== 'undefined' && _olmShared) _olmShared.coreInjected = true; } catch (_) {}
    const root = document.head || document.documentElement;

    // Primary: textContent — luôn hoạt động, không phụ thuộc blob-src CSP
    try {
        const el = document.createElement('script');
        el.textContent = scriptCode;
        scriptCode = null;
        root.appendChild(el);
        el.remove(); // Xóa tag ngay sau khi browser đã parse và chạy
        return;
    } catch (_) {}

    // Fallback: Blob URL (nếu textContent bị chặn vì inline-script CSP)
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

/* ============================================================
   CẤU HÌNH — Chỉ cần sửa 2 dòng này nếu đổi server / snippet
   ============================================================ */
const SERVER_BASE = 'https://serverkey-210-0nyo.onrender.com';  // URL server KeyVault
const SNIPPET_ID  = '';                                   // ID snippet core trên server
                                                         // Để trống '' → tự động lấy snippet đầu tiên (auto-endpoint)

/* [v2.3] */
const _KV_SILENT   = true;                                // true = kéo & giải mã file.js NGẦM hoàn toàn (không status text, không toast, không log) · false = như bản cũ
const _KV_KICK_URL = 'https://olm.vn/lop-hoc-cua-toi';    // key bị ban / hết hạn / không tồn tại → tự chuyển sang trang này

/* ============================================================
   CACHE KEYS
   ============================================================ */
const _KEY_CODE = '__olm_kv_code2__' + (SNIPPET_ID || 'auto');   // v2: bỏ cache blob cũ (key cũ)
const _KEY_META = '__olm_kv_meta2__' + (SNIPPET_ID || 'auto');

/* ============================================================
   [v2.3] VAULT v3 — MÃ HOÁ LẠI CACHE MỖI LẦN KÉO
   ------------------------------------------------------------
   Blob server trả về (encCode) vẫn giải mã đúng như cũ. Thêm 1 lớp bọc CỤC BỘ khi LƯU cache:
     • Mỗi lần kéo / lưu → salt 16 byte + IV 12 byte NGẪU NHIÊN MỚI → cùng 1 file.js nhưng blob nằm
       trong GM storage khác hẳn nhau ở mỗi lần.
     • Khoá = HKDF-SHA256(License Key IN HOA | mã thiết bị | AES key nhúng, salt mới) → AES-256-GCM.
       Chép cache sang máy khác / đổi License Key → không mở được → tự kéo lại từ server.
     • Đệm ngẫu nhiên 0–255 byte → không đoán được độ dài code từ độ dài blob.
     • Định dạng:  "KV3:" + base64( salt16 ‖ iv12 ‖ AES-GCM( len32 ‖ payload ‖ pad ) )
   Không có crypto.subtle (trang http) → _kvSealSafe trả nguyên bản (như cũ), không làm hỏng luồng.
   Cache đời cũ (chưa seal) vẫn đọc được; lần kéo kế tiếp sẽ tự lưu lại dạng seal.
   ============================================================ */
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

// Mở lớp seal. Cache đời cũ (không có tiền tố KV3:) → trả nguyên. Sai key / sai máy / hỏng → null.
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

// Đọc cache gói chính (đã mở lớp seal) — null nếu chưa có / không mở được
async function _kvLoadCore() {
    const raw = _loadCacheCode();
    return raw ? await _kvOpen(raw) : null;
}

// Đọc cache 1 file (đã mở lớp seal) → { c: checksum, p: payload } hoặc null
async function _kvLoadPart(id) {
    const r = _loadPart(id);
    if (!r || typeof r.p !== 'string') return null;
    const p = await _kvOpen(r.p);
    return p ? { c: r.c, p: p } : null;
}

/* ============================================================
   HELPERS: lưu/đọc cache bằng GM_setValue / GM_getValue
   ============================================================ */
function _saveCache(code, checksum, updatedAt) {
    if (_kvRevoked) return;   // [NEW] key đã bị từ chối → không ghi lại file.js
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

/* ============================================================
   KIỂM TRA TRANG MỤC TIÊU
   ============================================================ */
const currentHref = window.location.href;
const isTargetPage = currentHref.includes('/chu-de/')
    || currentHref.includes('/bai-kiem-tra/')
    || currentHref.includes('/video')
    || currentHref.includes('/luyen-tap');

/* ============================================================
   INJECT SCRIPT VÀO DOM CỦA OLM — dùng self-destruct
   ============================================================ */
function injectScriptToDOM(scriptCode) {
    // [v2.0] Gói nhiều file .js → giải mã & inject lần lượt từng file (giữ nguyên thứ tự trên server)
    if (typeof scriptCode === 'string' && scriptCode.indexOf(_KV_MULTI) === 0) {
        let parts = [];
        try { parts = JSON.parse(scriptCode.slice(_KV_MULTI.length)); } catch (_) {}
        scriptCode = null;
        (async function() {
            for (let i = 0; i < parts.length; i++) {
                if (_kvRevoked) break;   // [NEW] key vừa bị server từ chối → dừng, không chạy / không hỏi lại key cho các file còn lại
                const one = parts[i];
                parts[i] = null;
                if (_isEncPayload(one)) await _kvDecryptAndInject(one);
                else _selfDestructInject(one);
            }
        })();
        return;
    }
    // [v1.9] Blob mã hoá → giải mã bằng License Key rồi mới inject (code thường vẫn inject thẳng như cũ)
    if (_isEncPayload(scriptCode)) {
        _kvDecryptAndInject(scriptCode);
        scriptCode = null;
        return;
    }
    _selfDestructInject(scriptCode);
    scriptCode = null; // Đảm bảo biến caller cũng null
}

/* ============================================================
   FETCH HELPER — dùng GM_xmlhttpRequest để bypass CORS hoàn toàn
   timeout 30s, retry 5 lần, xử lý 502/503 cold-start
   ============================================================ */
function _gmFetchOnce(url, tok) {
    return new Promise(function(resolve, reject) {
        GM_xmlhttpRequest({
            method: 'GET',
            url: url,
            headers: (function() {
                const h = { 'Cache-Control': 'no-cache', 'Pragma': 'no-cache' };
                if (tok) {
                    // [v2.1] Server mới: chỉ nhận token 128-bit, không nhận License Key ở kho code
                    h['X-Script-Token'] = tok;
                } else {
                    // Server đời cũ (không có /api/g/x): giữ nguyên cách cũ
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
    // 404 trống = token hết hạn / hết lượt / đổi IP (còn "snippet_not_found" = file thật sự không có)
    if (tok && r.status === 404 && String(r.responseText || '').indexOf('snippet_not_found') < 0) {
        tok = await _kvGetToken(tok);   // đổi token mới rồi thử lại đúng 1 lần
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
            if (r.status === 404) throw _kvErr('HTTP 404 — snippet không tồn tại hoặc token/License Key không hợp lệ', { kvStop: true }); // [v2.1] không retry 404 (server tính strike theo IP)
            if (r.status < 200 || r.status >= 300) throw new Error('HTTP ' + r.status);
            return JSON.parse(r.responseText);
        } catch (e) {
            if (i === MAX || (e && e.kvStop)) throw e;   // [v2.1] lỗi đã rõ (token/key/thiết bị/404) → không retry
            await new Promise(res => setTimeout(res, 5000));
        }
    }
}

/* ============================================================
   HELPER ĐỂ CẬP NHẬT STATUS TEXT TRONG LOADER MATRIX
   ============================================================ */
let _pendingStatus = '';
function _setStatusText(msg) {
    _pendingStatus = msg;
    if (_KV_SILENT) return;   // [v2.3] chạy ngầm: không ghi gì lên giao diện loader
    const el = document.getElementById('ml-statusText');
    if (el) el.textContent = msg;
}

/* ============================================================
   MAIN LOADER — KeyVault Smart Cache Engine:
   1) Auto-endpoint: lấy snippet đầu tiên từ /api/public/snippets (nếu không có SNIPPET_ID)
   2) Version check nhẹ (/version) → so sánh checksum với cache
   3) Nếu đã mới nhất → chạy cache, skip download
   4) Nếu có bản mới → tải code → lưu cache → chạy
   5) Fallback về cache nếu mất mạng
   ============================================================ */
/* ------------------------------------------------------------
   [v2.0] AUTO KÉO TOÀN BỘ FILE .js TRÊN SERVER
   - Không còn chỉ lấy snippet đầu tiên: lấy HẾT danh sách /api/public/snippets
     (bỏ qua file Lua/Python/Java/txt), mỗi file có cache + checksum riêng.
   - Chỉ tải lại file nào đổi checksum; file không đổi chạy thẳng từ cache.
   - Nhiều file được gói thành 1 chuỗi (_KV_MULTI) để các hàm cache/inject cũ dùng y nguyên.
   - SNIPPET_ID khác rỗng → vẫn chỉ kéo đúng 1 file như trước.
   - [v2.1] Mọi request danh sách / version / code đều đi kèm X-Script-Token (xem khối TOKEN 128-BIT).
   ------------------------------------------------------------ */
const _KV_MULTI = '\u0001KVMULTI\u0001';
const _KEY_PART = '__olm_kv_part2__';
function _loadPart(id) {
    try { const r = GM_getValue(_KEY_PART + id, null); return r ? JSON.parse(r) : null; } catch (_) { return null; }
}
function _savePart(id, checksum, payload) {
    if (_kvRevoked) return;   // [NEW] key đã bị từ chối → không ghi lại file.js
    try { GM_setValue(_KEY_PART + id, JSON.stringify({ c: checksum, p: payload })); } catch (_) {}
    // [NEW] nhớ id từng file đã cache để _kvPurgeCore xoá sạch được
    try {
        const idx = JSON.parse(GM_getValue(_KEY_PART_IDX, '[]')) || [];
        if (idx.indexOf(id) < 0) { idx.push(id); GM_setValue(_KEY_PART_IDX, JSON.stringify(idx)); }
    } catch (_) {}
}

/* ============================================================
   [NEW] XOÁ file.js ĐÃ LƯU KHI KEY BỊ BAN / HẾT HẠN / KHÔNG TỒN TẠI
   ------------------------------------------------------------
   Khi SERVER trả 403 / invalid_key (banned · expired · key_not_found) → xoá toàn bộ file.js
   đang nằm trong GM storage: gói cache chính, từng file (part), khoá k1b và cache đời cũ.
   Không còn cache + License Key đã bị xoá → lần tải sau không chạy được gì từ cache và
   cũng không kéo lại code từ server cho tới khi nhập một License Key hợp lệ.
   Chỉ xoá khi server nói rõ key không hợp lệ — mất mạng / 429 / 502 / 503 thì GIỮ NGUYÊN cache.
   ============================================================ */
const _KEY_PART_IDX = '__olm_kv_pidx__';   // danh sách id các file đã cache
let   _kvRevoked    = false;               // true = key vừa bị server từ chối → không ghi lại cache trong phiên trang này

function _kvPurgeCore() {
    const ids = {};
    // id từng file: từ danh sách mới...
    try { (JSON.parse(GM_getValue(_KEY_PART_IDX, '[]')) || []).forEach(function(id) { ids[id] = 1; }); } catch (_) {}
    // ...và từ meta của cache bản cũ (checksum có dạng "id:ck|id:ck")
    try {
        const m = _loadCacheMeta();
        if (m && typeof m.checksum === 'string') {
            m.checksum.split('|').forEach(function(s) { const id = s.split(':')[0]; if (id) ids[id] = 1; });
        }
    } catch (_) {}
    Object.keys(ids).forEach(function(id) { try { GM_deleteValue(_KEY_PART + id); } catch (_) {} });
    [_KEY_CODE, _KEY_META, _KEY_PART_IDX, _KEY_K1B, '__olm_kv_code__auto', '__olm_kv_meta__auto',
     '__olm_kv_code__', '__olm_kv_meta__', '__olm_gh_code__', '__olm_gh_meta__'].forEach(function(k) {   // [v2.5] + các key cache đời cũ
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
    // 0) License Key (server mới bắt buộc key để kéo danh sách / code)
    let lic = null;
    try { lic = await _kvEnsureAccess(); } catch (_) {}
    if (!lic) { onError('Chưa có License Key.<br>Reload trang và nhập License Key để tải code.'); return; }
    try { await _kvGetK1b(lic); }
    catch (e) { if (e && e.kvLicense) { _kvHandleError(e); onError(e.message); return; } }
    // [v2.1] Đổi License Key → token 128-bit (server mới chỉ nhận X-Script-Token) + đăng ký mã thiết bị.
    //        Key sai / hết thiết bị → dừng & báo rõ. Lỗi mạng tạm thời → đi tiếp (sẽ dùng cache nếu có).
    try { _setStatusText('ĐANG XÁC THỰC THIẾT BỊ...'); await _kvGetToken(); }
    catch (e) { if (e && (e.kvLicense || e.kvDevice)) { _kvHandleError(e); onError(e.message); return; } }

    // 1) Danh sách file cần kéo
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

    // 2) Mỗi file: version check → cache hoặc tải mới (song song)
    _setStatusText('ĐANG KIỂM TRA ' + targets.length + ' FILE TRÊN SERVER...');
    const results = await Promise.all(targets.map(async function(t) {
        const part = await _kvLoadPart(t.id);   // [v2.3] mở lớp seal (không mở được → coi như chưa có cache, kéo lại)
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
            _savePart(t.id, ck, await _kvSealSafe(p));   // [v2.3] mỗi lần kéo → mã hoá lại bằng khoá ngẫu nhiên mới
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
    _saveCache(await _kvSealSafe(packed), sig, latestAt);   // [v2.3] seal lại cả gói mỗi lần kéo (salt / IV mới)

    if (allOffline) { _setStatusText('OFFLINE — DÙNG CACHE...'); onSuccess(packed, 'cache-offline'); return; }
    if (updated.length) {
        _setStatusText('🔄 ĐÃ CẬP NHẬT ' + updated.length + '/' + ok.length + ' FILE' + (latestAt ? ': ' + new Date(latestAt).toLocaleString('vi-VN') : ''));
        onSuccess(packed, 'fresh');
        return;
    }
    _setStatusText('✔ ' + ok.length + ' FILE ĐÃ MỚI NHẤT — KHỞI ĐỘNG...');
    onSuccess(packed, 'cache-fresh');
}

/* ============================================================
   ANTI-DEBUG + ANTI-DEVTOOLS — 8 LỚP BẢO VỆ NÂNG CAO
   ============================================================ */
(function _antiDevTools() {
    'use strict';

    // [NEW] Loader tự chạy lại mods.js khi có bản mới trên GitHub → chỉ cài lớp bảo vệ 1 lần / trang
    //       (tránh chồng thêm setInterval / Worker / listener sau mỗi lần cập nhật)
    try {
        if (typeof _olmShared !== 'undefined' && _olmShared) {
            if (_olmShared.dtInstalled) return;
            _olmShared.dtInstalled = true;
        }
    } catch (_) {}

    const _noop = function(){};
    let _dtHandled = false;

    /* ----------------------------------------------------------
       XỬ LÝ KHI PHÁT HIỆN DEVTOOLS
       - Xóa cache GM ngay lập tức
       - Xóa DOM
       - Chặn mọi network / navigation
       - Override console để không leak thêm gì
    ---------------------------------------------------------- */
    function _onDevToolsDetected(source) {
        if (_dtHandled) return;
        _dtHandled = true;

        // 1. Xóa toàn bộ cache GM ngay lập tức
        try { GM_deleteValue('__olm_kv_code__auto'); } catch(_) {}
        try { GM_deleteValue('__olm_kv_meta__auto'); } catch(_) {}
        try { GM_deleteValue(_KEY_CODE); } catch(_) {}
        try { GM_deleteValue(_KEY_META); } catch(_) {}
        try { GM_deleteValue('__olm_kv_k1b__'); } catch(_) {}

        // 2. Xóa sessionStorage / localStorage liên quan
        try {
            for (const k of Object.keys(sessionStorage)) {
                if (k.includes('olm') || k.includes('tiep') || k.includes('kv')) {
                    sessionStorage.removeItem(k);
                }
            }
        } catch(_) {}

        // 3. Override console để không leak thêm log nào
        try {
            const _dead = function() { return undefined; };
            ['log','warn','error','info','debug','table','dir','dirxml','group','groupEnd','trace','assert','count','time','timeEnd'].forEach(function(m) {
                try { console[m] = _dead; } catch(_) {}
            });
        } catch(_) {}

        // 4. Chặn mọi network request tiếp theo (freeze fetch + XHR)
        try {
            window.fetch = function() { return new Promise(function(){}); };
            const _deadXHR = function() {
                return { open:_noop, send:_noop, setRequestHeader:_noop,
                         addEventListener:_noop, abort:_noop, getAllResponseHeaders:_noop };
            };
            window.XMLHttpRequest = _deadXHR;
            window.XMLHttpRequest.prototype = {};
        } catch(_) {}

        // 5. Xóa DOM và thay bằng màn hình giả
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

        // 6. Vô hiệu hóa back/forward để chống xem source (bỏ onbeforeunload
        //    vì nó gây popup "rời trang?" phiền phức khi navigate bình thường)
        try {
            history.pushState(null, '', location.href);
            window.onpopstate = function() { history.pushState(null, '', location.href); };
            // KHÔNG dùng onbeforeunload — gây false alert cho người dùng bình thường
        } catch(_) {}

        // 7. Liên tục overwrite để chống restore
        let _lockCount = 0;
        const _lockInterval = setInterval(function() {
            _lockCount++;
            try { document.title = '⛔ ACCESS DENIED'; } catch(_) {}
            try {
                window.fetch = function() { return new Promise(function(){}); };
            } catch(_) {}
            if (_lockCount > 60) clearInterval(_lockInterval); // dừng sau 1 phút
        }, 1000);
    }

    /* ----------------------------------------------------------
       LỚP 1: KÍCH THƯỚC CỬA SỔ (nhanh nhất, check thường xuyên)
       FIX: Mobile browser UI (address bar + status bar + tab bar)
       thường chiếm 80-200px chiều cao → phải bỏ qua hDiff trên mobile.
       Chỉ check wDiff (chiều ngang) vì DevTools dock-right mới có wDiff lớn.
       Thêm: cần ≥3 lần liên tiếp vượt ngưỡng để tránh false positive nhất thời.
    ---------------------------------------------------------- */
    const _DT_W_THRESHOLD = 200; // Chỉ check chiều NGANG — dock-right DevTools
    const _isMobile = /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent);
    let _sizeOpenCount = 0;
    function _checkSize() {
        // Trên mobile: bỏ qua hoàn toàn check kích thước (browser chrome quá lớn)
        if (_isMobile) return;
        const wDiff = window.outerWidth - window.innerWidth;
        const open  = wDiff > _DT_W_THRESHOLD;
        if (open) {
            _sizeOpenCount++;
            // Cần 3 lần liên tiếp (1.8 giây) để xác nhận, tránh nhất thời
            if (_sizeOpenCount >= 3) _onDevToolsDetected('SIZE');
        } else {
            _sizeOpenCount = 0;
        }
    }
    setInterval(_checkSize, 600);

    /* ----------------------------------------------------------
       LỚP 2: TIMING CỦA debugger STATEMENT
       DevTools mở → pause tại debugger → dt > ngưỡng
       FIX: Mobile CPU chậm có thể vượt 80ms bình thường.
       - Tăng ngưỡng lên 200ms (chỉ bị chặn khi thực sự pause tại breakpoint)
       - Bỏ qua trên mobile để tránh hoàn toàn false positive
    ---------------------------------------------------------- */
    function _checkTiming() {
        if (_isMobile) return; // CPU mobile quá chậm, bỏ qua
        const t0 = performance.now();
        (function(){ try { (new Function('debugger'))(); } catch(_){} })();
        if (performance.now() - t0 > 200) _onDevToolsDetected('TIMING');
    }
    setInterval(_checkTiming, 1200);

    /* ----------------------------------------------------------
       LỚP 3: DEBUGGER LOOP LIÊN TỤC TRONG WEB WORKER
       Worker chạy vòng lặp debugger → nếu DevTools mở, Worker bị block
       → Worker gửi heartbeat chậm → phát hiện
       FIX: Bỏ qua trên mobile (tốn pin, CPU chậm → false positive).
       Tăng ngưỡng heartbeat từ 200ms → 500ms để an toàn hơn trên desktop chậm.
    ---------------------------------------------------------- */
    if (!_isMobile) {
        try {
            const _workerCode = [
                'var _last = Date.now();',
                'setInterval(function(){',
                '  (new Function("debugger"))();',
                '  var now = Date.now();',
                '  if(now - _last > 500) postMessage("DT_DETECTED");',
                '  _last = now;',
                '}, 150);' // Giảm tần suất từ 100 → 150ms để ít tốn CPU hơn
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

    /* ----------------------------------------------------------
       LỚP 4: OVERRIDE console.log VIA GETTER TRAP
       Khi DevTools mở, trình duyệt tự gọi getter của object được log
       → dùng để phát hiện
       FIX: Kỹ thuật này không đáng tin — browser extension, React DevTools,
       và một số thư viện có thể trigger nó mà không liên quan đến DevTools.
       Thêm debounce 2s: chỉ kích hoạt nếu được trigger nhiều lần liên tiếp
       (DevTools thực sự sẽ trigger liên tục khi console tab mở).
    ---------------------------------------------------------- */
    if (!_isMobile) {
        try {
            let _consoleTrapCount = 0;
            let _consoleTrapTimer = null;
            let _trap = /./;
            _trap.toString = function() {
                _consoleTrapCount++;
                clearTimeout(_consoleTrapTimer);
                _consoleTrapTimer = setTimeout(function() { _consoleTrapCount = 0; }, 2000);
                if (_consoleTrapCount >= 3) { // Cần 3 lần trigger trong 2s mới xác nhận
                    _onDevToolsDetected('CONSOLE_TRAP');
                }
                return '';
            };
        } catch(_) {}
    }

    /* ----------------------------------------------------------
       LỚP 5: CHẶN PHÍM TẮT MỞ DEVTOOLS
    ---------------------------------------------------------- */
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
        // Alt+Cmd+I (Mac)
        if (e.altKey && e.metaKey && (e.key === 'I' || e.key === 'i')) {
            e.preventDefault(); e.stopImmediatePropagation(); return false;
        }
    }, true);

    /* ----------------------------------------------------------
       LỚP 6: CHẶN CONTEXT MENU (chuột phải → inspect)
    ---------------------------------------------------------- */
    document.addEventListener('contextmenu', function(e) {
        e.preventDefault(); e.stopImmediatePropagation(); return false;
    }, true);

    /* ----------------------------------------------------------
       LỚP 7: PHÁT HIỆN QUA toString CỦA FUNCTION
       DevTools hiện native code khác → so sánh length
       FIX: Bỏ qua trên mobile. Thêm: cần 2 lần liên tiếp để xác nhận
       tránh trường hợp polyfill hay extension làm thay đổi một lần nhất thời.
    ---------------------------------------------------------- */
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
                        _fnstrMismatchCount = 0; // reset nếu trở lại bình thường
                    }
                } catch(_) {}
            }, 2000);
        } catch(_) {}
    }

    /* ----------------------------------------------------------
       LỚP 8: CHẶN DRAG & DROP FILE ĐỂ TRÁNH SOURCE MAP
    ---------------------------------------------------------- */
    document.addEventListener('dragover',  function(e){ e.preventDefault(); }, true);
    document.addEventListener('drop',      function(e){ e.preventDefault(); }, true);

})();

/* ============================================================
   [FIX] ĐIỂM KHỞI CHẠY (ENTRY POINT)
   File gốc chỉ KHAI BÁO hàm, không có dòng nào gọi chúng → tải về xong không có gì chạy.
   Loader (Olm_loader-github.js) đã lo phần animation nên ở đây chạy thẳng luồng KeyVault
   (giống MAIN FLOW của loader gốc):
     • Có cache  → inject cache ngay (giải mã bằng License Key), cập nhật cache ngầm
     • Chưa cache → License Key → token → kéo code mã hoá từ server → giải mã → inject
   File này PHẢI chạy trong sandbox userscript (cần GM_*) — loader bản mới đã lo việc đó.
   ============================================================ */
(async function _kvMain() {
    if (typeof GM_xmlhttpRequest !== 'function' || typeof GM_getValue !== 'function'
        || typeof GM_setValue !== 'function' || typeof GM_deleteValue !== 'function') {
        // Loader bản cũ inject thẳng mods.js vào trang → không có GM_* → dừng sớm, báo rõ nguyên nhân
        _kvToast('[KeyVault] Thiếu GM_* (mods.js đang chạy ngoài sandbox userscript). Hãy cập nhật Olm_loader-github.js bản mới nhất trong Tampermonkey/Violentmonkey.', 20000, true);
        return;
    }
    const _fail = function(err) {
        _kvToast('[KeyVault] ' + String((err && err.message) || err || 'Lỗi không xác định').replace(/<br\s*\/?>/gi, ' '));
    };
    // [NEW] Không còn License Key (vd: key đã bị ban ở bản cũ nhưng cache còn sót) → xoá luôn file.js đã lưu
    if (!_kvGetStr('_kv_lic') && _loadCacheCode()) _kvPurgeCore();
    // [NEW] Loader chạy lại mods.js mới mỗi 2 phút: core đã chạy trên trang thì KHÔNG nạp lại (tránh chạy đôi)
    const _coreRunning = function() { return !!(typeof _olmShared !== 'undefined' && _olmShared && _olmShared.coreInjected); };
    const cachedCore = await _kvLoadCore();   // [v2.3] cache đã seal → mở ra; không mở được (đổi key / đổi máy) → coi như chưa có cache
    if (cachedCore) {
        // Chạy cache ngay lập tức, cập nhật ngầm
        if (!_coreRunning()) injectScriptToDOM(cachedCore);
        _kvFetchAndRun(
            function() { /* đã inject cache rồi — không inject lại để tránh double-run; bản mới đã được lưu cho lần sau */ },
            function() { /* lỗi tải bản mới — cache cũ vẫn chạy, không cần báo */ }
        ).catch(function() {});
    } else {
        _kvFetchAndRun(function(code) { if (!_coreRunning()) injectScriptToDOM(code); }, _fail).catch(_fail);
    }
})().catch(function() {});
