import { sessionCookie, json } from '../../lib/auth.js';

export async function onRequestPost({ request }) {
  if (request.headers.get('origin') !== new URL(request.url).origin) return json({ error: 'Bad request.' }, 403);
  return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) });
}
