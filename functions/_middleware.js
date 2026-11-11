// Runs before every request. Default deny: only listed paths are served,
// and everything except the sign-in page needs a valid signed session.
import { readSession, json } from '../lib/auth.js';

const PUBLIC = new Set(['/login', '/login.js', '/login.css', '/brand-logo.png', '/api/login', '/favicon.ico']);
const APP    = new Set(['/', '/index.html', '/api/me', '/api/logout']);
// Brand pages: only users whose account lists the page may open it
const BRAND_PAGE = /^\/(plan-[a-z0-9-]+|seasonality)(\.html)?$/;

const CSP_APP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'", "object-src 'none'"
].join('; ');
const CSP_LOGIN = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
                  "frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

function harden(res, isLogin) {
  const r = new Response(res.body, res);
  const h = r.headers;
  h.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('X-Frame-Options', 'DENY');
  h.set('Referrer-Policy', 'no-referrer');
  h.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()');
  h.set('Cross-Origin-Opener-Policy', 'same-origin');
  h.set('Cross-Origin-Resource-Policy', 'same-origin');
  h.set('X-Robots-Tag', 'noindex, nofollow, noarchive');
  h.set('Content-Security-Policy', isLogin ? CSP_LOGIN : CSP_APP);
  const ct = h.get('content-type') || '';
  if (ct.includes('html') || ct.includes('json')) h.set('Cache-Control', 'no-store');
  h.delete('Access-Control-Allow-Origin');
  return r;
}

function notFound() { return new Response('Not found', { status: 404, headers: { 'content-type': 'text/plain' } }); }

export async function onRequest(ctx) {
  const { request, env, next } = ctx;
  const url = new URL(request.url);
  let path = url.pathname.replace(/\/{2,}/g, '/');
  if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);
  if (path === '/login.html') path = '/login';

  // Only GET/HEAD anywhere, plus POST to the two auth endpoints
  const m = request.method;
  if (!(m === 'GET' || m === 'HEAD' || (m === 'POST' && (path === '/api/login' || path === '/api/logout')))) {
    return harden(new Response('Method not allowed', { status: 405 }), false);
  }

  if (PUBLIC.has(path)) {
    // Already signed in? Skip the sign-in page.
    if (path === '/login' && await readSession(request, env)) return harden(Response.redirect(url.origin + '/', 302), true);
    return harden(await next(), true);
  }

  const isApiMeta = path.startsWith('/api/meta/');
  const isBrand = BRAND_PAGE.test(path);
  if (!APP.has(path) && !isApiMeta && !isBrand) return harden(notFound(), true);

  const session = await readSession(request, env);
  if (!session) {
    if (path.startsWith('/api/')) return harden(json({ error: { message: 'Not signed in.' } }, 401), false);
    return harden(Response.redirect(url.origin + '/login', 302), true);
  }

  if (isBrand) {
    const page = path.slice(1).replace(/\.html$/, '') + '.html';
    if (!(session.rec.pages || []).includes(page)) return harden(notFound(), true);
  }

  ctx.data.session = session;      // used by /api/meta and /api/me
  return harden(await next(), false);
}
