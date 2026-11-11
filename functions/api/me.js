import { publicAccount, json } from '../../lib/auth.js';

// The middleware already verified the session; return only this user's account
export async function onRequestGet({ data }) {
  const s = data.session;
  return json({ user: s.user, account: publicAccount(s.rec) });
}
