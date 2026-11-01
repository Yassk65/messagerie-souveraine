const test = require('node:test');
const assert = require('node:assert/strict');
const { allowedPath } = require('../portal/src/gateway');
const { SynapseEngine } = require('../portal/src/synapse');
const { EmbeddedMatrixEngine } = require('../portal/src/matrix_engine');
const { SovereignPortalApp } = require('../portal/src/server');
const { generateTOTP } = require('../portal/src/totp');
const { verifyPortalToken } = require('../portal/src/receipts');
const { PostgresStore } = require('../portal/src/store');

test('Passerelle : refuser connexion directe, administration, invitations et événements en clair', () => {
  const uid = '@agent:localhost';
  for (const [method, path] of [
    ['POST', '/_matrix/client/v3/login'], ['POST', '/_matrix/client/v3/createRoom'],
    ['PUT', '/_matrix/client/v3/rooms/!r:localhost/send/m.room.message/1'],
    ['PUT', '/_matrix/client/v3/rooms/!r:localhost/state/m.room.encryption'],
    ['POST', '/_matrix/client/v3/rooms/!r:localhost/invite'], ['GET', '/_synapse/admin/v2/users'],
    ['PUT', '/_matrix/client/v3/user/@other:localhost/account_data/m.secret_storage.key.id'],
  ]) assert.equal(allowedPath(method, path, uid), false, path);
  for (const [method, path] of [
    ['GET', '/_matrix/client/v3/sync'], ['POST', '/_matrix/client/v3/keys/upload'],
    ['PUT', '/_matrix/client/v3/rooms/!r:localhost/send/m.room.encrypted/1'],
    ['PUT', '/_matrix/client/v3/user/%40agent%3Alocalhost/account_data/m.secret_storage.key.id'],
    ['GET', '/_matrix/client/v1/media/download/localhost/mediaid'], ['POST', '/_matrix/media/v3/upload'],
  ]) assert.equal(allowedPath(method, path, uid), true, path);
});

test('Le fonctionnement normal utilise Synapse et ne bascule jamais sur le simulateur', async () => {
  const app = new SovereignPortalApp();
  assert.ok(app.matrix instanceof SynapseEngine);
  assert.equal(app.directory.size, 0);
  await assert.rejects(app.matrix.login('agent', 'password'), { status: 503 });
  const response = await app.dispatchTestRequest('GET', '/api/demo/accounts');
  assert.equal(response.status, 404);
});

test('Les jetons Synapse et secrets TOTP restent hors des profils et jetons publics', async () => {
  const app = new SovereignPortalApp({ matrix: new EmbeddedMatrixEngine(), signingKey: 'test' });
  const first = await (await app.dispatchTestRequest('POST', '/api/auth/login-step1', { body: { username: 'admin', password: 'Demo-Fictif-2026!' } })).json();
  const login = await (await app.dispatchTestRequest('POST', '/api/auth/login-step2', { body: { challengeId: first.challengeId, totpCode: generateTOTP(first.totpSecret) } })).json();
  assert.equal(login.matrixAccessToken, undefined);
  assert.equal(verifyPortalToken(login.portalToken, 'test').matrixAccessToken, undefined);
  const me = await (await app.dispatchTestRequest('GET', '/api/me', { headers: { Authorization: `Bearer ${login.portalToken}` } })).json();
  assert.equal(me.agent.totpSecret, undefined);
  const logout = await app.dispatchTestRequest('POST', '/api/auth/logout', { headers: { Authorization: `Bearer ${login.portalToken}` } });
  assert.equal(logout.status, 200);
  assert.equal((await app.dispatchTestRequest('GET', '/api/me', { headers: { Authorization: `Bearer ${login.portalToken}` } })).status, 401);
});

test('Le registre est chiffré et toute modification est détectée', () => {
  const store = new PostgresStore('postgresql://unused', 'a'.repeat(32));
  const payload = store.seal({ totpSecret: 'secret-test', matrixAccessToken: 'private-token' });
  assert.equal(payload.includes(Buffer.from('secret-test')), false);
  assert.equal(payload.includes(Buffer.from('private-token')), false);
  assert.equal(store.open(payload).totpSecret, 'secret-test');
  const tampered = Buffer.from(payload); tampered[tampered.length - 1] ^= 1;
  assert.throws(() => store.open(tampered));
});

test('Un agent ne peut pas masquer une classification interdite dans le contenu chiffré transmis', async () => {
  const app = new SovereignPortalApp({ matrix: new EmbeddedMatrixEngine() });
  const first = await (await app.dispatchTestRequest('POST', '/api/auth/login-step1', { body: { username: 'ibrahim.sawadogo', password: 'Demo-Fictif-2026!' } })).json();
  const login = await (await app.dispatchTestRequest('POST', '/api/auth/login-step2', { body: { challengeId: first.challengeId, totpCode: generateTOTP(first.totpSecret) } })).json();
  const response = await app.dispatchTestRequest('POST', '/api/rooms/any/send-encrypted', { headers: { Authorization: `Bearer ${login.portalToken}` }, body: { content: { faso_meta: { classification: 'CONFIDENTIEL' } }, faso_meta: { classification: 'NORMAL' } } });
  assert.equal(response.status, 403);
});
