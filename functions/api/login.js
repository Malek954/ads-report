import { users, verifyPassword, makeSession, sessionCookie, publicAccount, json,
         throttleCheck, throttleFail, throttleClear } from '../../lib/auth.js';

export async function onRequestPost({ request, env }) {
  const url = new URL(request.url);
  // Same-origin only (blocks cross-site login posts)
  if (request.headers.get('origin') !== url.origin) return json({ error: 'Bad request.' }, 403);
  if (!env.AUTH_KV || !env.SESSION_KEY) return json({ error: 'Sign-in is not configured.' }, 503);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Bad request.' }, 400); }
  const typed = String(body.username || '').trim().slice(0, 64);
  const password = String(body.password || '').slice(0, 256);
  if (!typed || !password) return json({ error: 'Enter your username and password.' }, 400);

  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  if (!(await throttleCheck(env, ip, typed))) {
    return json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429, { 'retry-after': '900' });
  }

  const all = users(env);
  const username = Object.keys(all).find(k => k.toLowerCase() === typed.toLowerCase()) || null;
  const rec = username ? all[username] : null;
  const ok = await verifyPassword(rec, password);
  if (!ok) {
    await throttleFail(env, ip, typed);
    return json({ error: 'Wrong username or password.' }, 401);
  }
  await throttleClear(env, ip);
  const token = await makeSession(env, username, rec);
  return json({ user: username, account: publicAccount(rec) }, 200, { 'set-cookie': sessionCookie(token) });
}
