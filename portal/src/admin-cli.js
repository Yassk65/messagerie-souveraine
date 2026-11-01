// CLI uses the same mandatory password + TOTP + cookie + proof as the browser.
const { createNodeDPoPClientIdentity } = require('./dpop');
async function main() {
  const target = process.argv[2];
  if (!target || !process.env.ADMIN_PASSWORD || !process.env.ADMIN_TOTP) throw new Error('Identifiant cible, ADMIN_PASSWORD et ADMIN_TOTP requis.');
  const identity = createNodeDPoPClientIdentity();
  const base = 'http://127.0.0.1:3000'; let token, cookie;
  async function request(path, body, protectedRequest = false) {
    const response = await fetch(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': 'FasoSouverain-Administration',
      ...(protectedRequest ? { Authorization: `Bearer ${token}`, Cookie: cookie, 'X-Faso-DPoP': identity.signRequest('POST', path) } : {}) }, body: JSON.stringify(body) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || data.error);
    return { data, response };
  }
  const { data: first } = await request('/api/auth/login-step1', { username: process.env.ADMIN_USERNAME || 'admin', password: process.env.ADMIN_PASSWORD });
  if (first.isFirstSetup) throw new Error('Configurez le second facteur de cet administrateur dans le navigateur avant d’utiliser la CLI.');
  const login = await request('/api/auth/login-step2', { challengeId: first.challengeId, totpCode: process.env.ADMIN_TOTP, dpopPublicJwk: identity.publicJwk, enableCookieBind: true });
  token = login.data.portalToken; cookie = login.response.headers.getSetCookie().map(c => c.split(';')[0]).join('; ');
  try { await request('/api/admin/revoke', { localpart: target }, true); console.log(`Compte ${target} révoqué.`); }
  finally { await request('/api/auth/logout', {}, true).catch(() => {}); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
