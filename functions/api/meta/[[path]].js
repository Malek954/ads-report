// Secure Meta API proxy for Cloudflare Pages Functions.
// The access token lives ONLY in the server env var META_TOKEN and is
// never sent to the browser.
//
// Handles /api/meta/*  ->  https://graph.facebook.com/v19.0/*  (+ token)

export async function onRequest(context) {
  const { request, env, params } = context;

  // params.path is the catch-all after /api/meta/  e.g. ['act_123','insights']
  const segs = Array.isArray(params.path) ? params.path : [params.path];
  const subPath = '/' + segs.join('/');

  // Only allow read-style insight calls — never expose write endpoints
  if (!/^\/act_\d+\/insights\/?$/.test(subPath)) {
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
  const params2 = inUrl.searchParams;
  params2.delete('access_token');      // ignore any client-supplied token
  params2.set('access_token', TOKEN);  // inject the real one server-side

  const target = `https://graph.facebook.com/v19.0${subPath}?${params2.toString()}`;

  try {
    const r = await fetch(target);
    const body = await r.text();
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
