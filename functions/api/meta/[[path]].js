// Secure Meta API proxy for Cloudflare Pages Functions.
// The access token lives ONLY in the server env var META_TOKEN and is
// never sent to the browser.
//
// Handles /api/meta/*  ->  https://graph.facebook.com/v19.0/*  (+ token)

// Only the accounts that have a report login
const ALLOWED = new Set(['401990560846482','2638156416541971','1757389631850436','1561863647870277','1223465486666247','386280680659578']);

export async function onRequest(context) {
  const { request, env, params } = context;

  // params.path is the catch-all after /api/meta/  e.g. ['act_123','insights']
  const segs = Array.isArray(params.path) ? params.path : [params.path];
  const subPath = '/' + segs.join('/');

  // Only allow read-style calls — insights + the ads list (for live status)
  const m = subPath.match(/^\/act_(\d+)\/(insights|ads)\/?$/);
  if (!m || !ALLOWED.has(m[1])) {
    return json({ error: { message: 'Endpoint not allowed.' } }, 403);
  }

  // The SSD account lives in a different app, so it uses its own token.
  const SSD_ACCT = '1757389631850436';
  const TOKEN = subPath.includes('act_' + SSD_ACCT)
    ? (env.META_TOKEN_SSD || env.META_TOKEN)
    : env.META_TOKEN;
  if (!TOKEN) {
    return json({ error: { message: 'Server token is not configured.' } }, 500);
  }

  const inUrl = new URL(request.url);
  inUrl.searchParams.delete('access_token');
  const params2 = new URLSearchParams(inUrl.search);
  params2.delete('access_token');      // ignore any client-supplied token
  params2.set('access_token', TOKEN);  // inject the real one server-side

  const target = `https://graph.facebook.com/v19.0${subPath}?${params2.toString()}`;

  try {
    const r = await fetch(target);
    let body = await r.text();
    // Meta's paging.next/previous URLs embed the server token: drop them.
    // The browser pages with cursors (&after=), so nothing is lost.
    try {
      const j = JSON.parse(body);
      if (j && j.paging) {
        const hadNext = !!j.paging.next, after = j.paging.cursors && j.paging.cursors.after;
        delete j.paging.next; delete j.paging.previous;
        if (hadNext && after) {
          // Rebuild "next" as a token-free URL back through this proxy
          const nq = new URLSearchParams(inUrl.search);
          nq.delete('access_token'); nq.delete('before'); nq.set('after', after);
          j.paging.next = `/api/meta${subPath}?${nq.toString()}`;
        }
      }
      body = JSON.stringify(j);
    } catch (e) { body = '{"error":{"message":"Bad upstream response."}}'; }
    if (body.includes(TOKEN) || /access_token/.test(body)) {
      return json({ error: { message: 'Blocked.' } }, 502);
    }
    return new Response(body, {
      status: r.status,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }
    });
  } catch (e) {
    return json({ error: { message: 'Upstream fetch failed.' } }, 502);
  }
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}
