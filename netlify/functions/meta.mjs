// Secure Meta API proxy — the access token lives ONLY in the server environment
// variable META_TOKEN and is never sent to the browser.
//
// The dashboard calls e.g.  /api/meta/act_123/insights?level=ad&...
// and this function forwards it to graph.facebook.com with the token attached.

export default async (req) => {
  const inUrl = new URL(req.url);
  // Everything after /api/meta becomes the Graph API path (e.g. /act_123/insights)
  const subPath = inUrl.pathname.replace(/^\/api\/meta/, '');

  // Only allow read-style calls — insights + the ads list (for live status)
  if (!/^\/act_\d+\/(insights|ads)\/?$/.test(subPath)) {
    return new Response(
      JSON.stringify({ error: { message: 'Endpoint not allowed.' } }),
      { status: 403, headers: { 'content-type': 'application/json' } }
    );
  }

  // The SSD account lives in a different app, so it uses its own token.
  const SSD_ACCT = '1757389631850436';
  const TOKEN = subPath.includes('act_' + SSD_ACCT)
    ? (process.env.META_TOKEN_SSD || process.env.META_TOKEN)
    : process.env.META_TOKEN;
  if (!TOKEN) {
    return new Response(
      JSON.stringify({ error: { message: 'Server token is not configured.' } }),
      { status: 500, headers: { 'content-type': 'application/json' } }
    );
  }

  const params = inUrl.searchParams;
  params.delete('access_token');         // ignore any token a client tries to pass
  params.set('access_token', TOKEN);     // inject the real one server-side

  const target = `https://graph.facebook.com/v19.0${subPath}?${params.toString()}`;

  try {
    const r = await fetch(target);
    const body = await r.text();
    return new Response(body, {
      status: r.status,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }
    });
  } catch (e) {
    return new Response(
      JSON.stringify({ error: { message: 'Upstream fetch failed.' } }),
      { status: 502, headers: { 'content-type': 'application/json' } }
    );
  }
};

// Netlify Functions v2 routing — handles all /api/meta/* requests
export const config = { path: '/api/meta/*' };
