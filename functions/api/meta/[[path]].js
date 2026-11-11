// Meta API proxy (read-only). The token lives ONLY in server secrets and never
// reaches the browser. The middleware has already checked the session; this
// file only serves the signed-in client's OWN ad account.
//
// /api/meta/act_<id>/(insights|ads|adsets)  ->  graph.facebook.com/v19.0/...

import { json } from '../../../lib/auth.js';

const ALLOWED_PARAMS = new Set(['fields', 'level', 'time_increment', 'time_range', 'date_preset', 'limit',
  'after', 'filtering', 'breakdowns', 'action_attribution_windows', 'effective_status', 'sort', 'time_ranges',
  'use_unified_attribution_setting']);

export async function onRequestGet({ request, env, params, data }) {
  const session = data.session;
  const segs = Array.isArray(params.path) ? params.path : [params.path];
  const subPath = '/' + segs.join('/');

  const m = subPath.match(/^\/act_(\d+)\/(insights|ads|adsets)\/?$/);
  if (!session || !m || m[1] !== session.account) {
    return json({ error: { message: 'Endpoint not allowed.' } }, 403);
  }

  const TOKEN = env.META_TOKEN;
  if (!TOKEN) return json({ error: { message: 'Server token is not configured.' } }, 500);

  // Forward only known read parameters; never a client-supplied token
  const inUrl = new URL(request.url);
  const clean = new URLSearchParams();
  for (const [k, v] of inUrl.searchParams) if (ALLOWED_PARAMS.has(k)) clean.append(k, v);
  const upstream = new URLSearchParams(clean);
  upstream.set('access_token', TOKEN);

  let r, body;
  try {
    r = await fetch(`https://graph.facebook.com/v19.0${subPath}?${upstream.toString()}`);
    body = await r.text();
  } catch (e) {
    return json({ error: { message: 'Upstream fetch failed.' } }, 502);
  }

  let j;
  try { j = JSON.parse(body); } catch { return json({ error: { message: 'Bad upstream response.' } }, 502); }
  if (j.error) return json({ error: { message: 'Meta API error ' + (j.error.code || '') } }, r.status);

  // Meta's paging links embed the token: rebuild "next" as a token-free proxy URL
  if (j.paging) {
    const hadNext = !!j.paging.next, after = j.paging.cursors && j.paging.cursors.after;
    delete j.paging.next; delete j.paging.previous;
    if (hadNext && after) {
      const nq = new URLSearchParams(clean); nq.set('after', after);
      j.paging.next = `/api/meta${subPath}?${nq.toString()}`;
    }
  }
  const out = JSON.stringify(j);
  if (out.includes(TOKEN) || out.includes('access_token')) return json({ error: { message: 'Blocked.' } }, 502);
  return new Response(out, { status: r.status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
}
