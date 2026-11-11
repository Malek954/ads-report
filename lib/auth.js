// Server-side auth for the client report (Cloudflare Pages Functions).
// Nothing secret lives in this file. Secrets are Pages env secrets:
//   AUTH_USERS  JSON { username: { a, name, cur, type?, pages?, s, h } }
//               a = ad account id, s = salt (b64), h = PBKDF2-SHA256 hash (b64)
//   SESSION_KEY random 32+ byte key (b64) used to sign session cookies
// KV binding AUTH_KV holds failed-login counters (rate limiting).

export const COOKIE = '__Host-ir_session';
export const SESSION_TTL = 7 * 24 * 3600;      // 7 days
const PBKDF2_ITER = 100000;                    // Workers maximum

const enc = new TextEncoder();
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const b64url = s => s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = s => s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);

export function users(env) {
  try { return JSON.parse(env.AUTH_USERS || '{}'); } catch { return {}; }
}

// Constant-time comparison of two equal-purpose byte strings
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

async function pbkdf2(password, saltBytes) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: PBKDF2_ITER }, key, 256));
}

// Always runs the full hash, even for unknown users, so timing reveals nothing
const DUMMY = { s: 'AAAAAAAAAAAAAAAAAAAAAA==', h: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' };
export async function verifyPassword(user, password) {
  const rec = user || DUMMY;
  const got = await pbkdf2(String(password || ''), unb64(rec.s));
  return safeEqual(got, unb64(rec.h)) && !!user;
}

async function hmacKey(env) {
  if (!env.SESSION_KEY || env.SESSION_KEY.length < 40) throw new Error('SESSION_KEY missing');
  return crypto.subtle.importKey('raw', unb64(env.SESSION_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

// Session = signed {u, a, f, exp}. f = fingerprint of the password hash,
// so changing a password logs that client out everywhere.
export async function makeSession(env, username, user) {
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(btoa(JSON.stringify({ u: username, a: user.a, f: user.h.slice(0, 12), exp: now + SESSION_TTL })));
  const sig = b64url(b64(await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(payload))));
  return `${payload}.${sig}`;
}

export async function readSession(request, env) {
  const raw = (request.headers.get('cookie') || '').split(/;\s*/).find(c => c.startsWith(COOKIE + '='));
  if (!raw) return null;
  const [payload, sig] = raw.slice(COOKIE.length + 1).split('.');
  if (!payload || !sig) return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(env), unb64(unb64url(sig)), enc.encode(payload));
    if (!ok) return null;
    const s = JSON.parse(atob(unb64url(payload)));
    if (!s.exp || s.exp < Date.now() / 1000) return null;
    const u = users(env)[s.u];                    // user removed = session dead
    if (!u || u.a !== s.a || u.h.slice(0, 12) !== s.f) return null;
    return { user: s.u, account: u.a, rec: u };
  } catch { return null; }
}

export function sessionCookie(value, maxAge = SESSION_TTL) {
  return `${COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

export function publicAccount(rec) {
  return { id: rec.a, name: rec.name, currency: rec.cur, type: rec.type || null, pages: rec.pages || [] };
}

export function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), {
    status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...extra }
  });
}

// ── Failed-login throttle (KV). Fails closed if KV is missing. ──
const IP_LIMIT = 8, IP_WINDOW = 900;          // 8 misses per IP per 15 min
const USER_LIMIT = 20, USER_WINDOW = 3600;    // 20 misses per username per hour

export async function throttleCheck(env, ip, username) {
  if (!env.AUTH_KV) return false;
  const [a, b] = await Promise.all([
    env.AUTH_KV.get('fail:ip:' + ip), env.AUTH_KV.get('fail:u:' + username.toLowerCase())]);
  return (+a || 0) < IP_LIMIT && (+b || 0) < USER_LIMIT;
}
export async function throttleFail(env, ip, username) {
  if (!env.AUTH_KV) return;
  const ki = 'fail:ip:' + ip, ku = 'fail:u:' + username.toLowerCase();
  const [a, b] = await Promise.all([env.AUTH_KV.get(ki), env.AUTH_KV.get(ku)]);
  await Promise.all([
    env.AUTH_KV.put(ki, String((+a || 0) + 1), { expirationTtl: IP_WINDOW }),
    env.AUTH_KV.put(ku, String((+b || 0) + 1), { expirationTtl: USER_WINDOW })]);
}
export async function throttleClear(env, ip) {
  if (env.AUTH_KV) await env.AUTH_KV.delete('fail:ip:' + ip);
}
