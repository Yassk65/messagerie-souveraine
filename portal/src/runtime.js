const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const { PostgresStore } = require('./store');
const { DEFAULT_DEMO_AGENTS } = require('./roles');

async function bootstrapAdmin(app) {
  const url = app.synapseUrl;
  const secret = fs.readFileSync(process.env.SYNAPSE_REGISTRATION_SECRET_FILE || '/run/bootstrap/registration-secret', 'utf8').trim();
  const password = fs.readFileSync(process.env.SYNAPSE_SERVICE_PASSWORD_FILE || '/run/bootstrap/service-password', 'utf8').trim();
  const username = 'faso_portal_service';
  const nonceResponse = await fetch(url + '/_synapse/admin/v1/register');
  if (!nonceResponse.ok) throw new Error('Initialisation Synapse indisponible');
  const { nonce } = await nonceResponse.json();
  const mac = crypto.createHmac('sha1', secret).update([nonce, username, password, 'admin'].join('\0')).digest('hex');
  const registration = await fetch(url + '/_synapse/admin/v1/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ nonce, username, password, admin: true, mac }) });
  if (!registration.ok && (await registration.json()).errcode !== 'M_USER_IN_USE') throw new Error('Création du compte de service impossible');
  const response = await fetch(url + '/_matrix/client/v3/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: 'm.login.password', identifier: { type: 'm.id.user', user: username }, password, device_id: 'FASO_SERVICE' }) });
  if (!response.ok) throw new Error('Authentification du compte de service impossible');
  app.matrix.adminToken = (await response.json()).access_token;
}

async function start() {
  const secretsDir = process.env.PORTAL_SECRETS_DIR || '/run/bootstrap';
  const signingKey = process.env.PORTAL_SIGNING_KEY || fs.readFileSync(path.join(secretsDir, 'portal-signing-key'), 'utf8').trim();
  const storageKey = process.env.PORTAL_STORAGE_KEY || fs.readFileSync(path.join(secretsDir, 'portal-storage-key'), 'utf8').trim();
  if (!process.env.DATABASE_URL || !process.env.SYNAPSE_INTERNAL_URL) throw new Error('DATABASE_URL et SYNAPSE_INTERNAL_URL requis. Utilisez Docker Compose.');
  const { SovereignPortalApp } = require('./server');
  const app = new SovereignPortalApp({ signingKey });
  const store = new PostgresStore(process.env.DATABASE_URL, storageKey);
  let available = false;
  for (let attempt = 0; attempt < 60; attempt++) {
    try { if ((await fetch(app.synapseUrl + '/health', { signal: AbortSignal.timeout(2000) })).ok) { available = true; break; } } catch {}
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  if (!available) throw new Error('Synapse indisponible après une minute.');
  await bootstrapAdmin(app);
  await app.initialize(store);
  if (process.env.SYNAPSE_AUDIT_DATABASE_URL) {
    const provision = new Pool({ connectionString: process.env.SYNAPSE_AUDIT_DATABASE_URL });
    const password = crypto.createHmac('sha256', storageKey).update('faso-audit-role').digest('hex');
    const role = 'faso_portal_audit';
    const { rows } = await provision.query('SELECT 1 FROM pg_roles WHERE rolname=$1', [role]);
    if (!rows.length) await provision.query(`CREATE ROLE ${role} LOGIN PASSWORD '${password}'`);
    await provision.query(`GRANT CONNECT ON DATABASE synapse TO ${role}`);
    await provision.query(`GRANT USAGE ON SCHEMA public TO ${role}`);
    await provision.query(`GRANT SELECT ON events TO ${role}`);
    await provision.end();
    const auditUrl = new URL(process.env.SYNAPSE_AUDIT_DATABASE_URL); auditUrl.username = role; auditUrl.password = password;
    app.matrix.auditPool = new Pool({ connectionString: auditUrl.toString(), options: '-c default_transaction_read_only=on' });
  }
  const password = process.env.DEMO_PASSWORD || 'Demo-Fictif-2026!';
  if (app.demoMode) {
    for (const agent of DEFAULT_DEMO_AGENTS) if (app.directory.get(agent.localpart)?.status === 'ACTIVE') await app.matrix.registerUser(agent.localpart, password, false);
  } else if (!app.directory.size) {
    const bootstrapPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD;
    if (!bootstrapPassword || bootstrapPassword.length < 12) throw new Error('BOOTSTRAP_ADMIN_PASSWORD (12 caractères minimum) requis au premier démarrage hors démo.');
    await app.matrix.registerUser('admin', bootstrapPassword, false);
    const agent = DEFAULT_DEMO_AGENTS[0];
    app.directory.set('admin', { ...agent, userId: `@admin:${app.serverName}`, totpSecret: null, totpEnrolled: false, enrolledAt: new Date().toISOString() });
  }
  await store.save(app.snapshot());
  const server = app.createHttpServer();
  server.listen(Number(process.env.PORTAL_PORT || 3000), '0.0.0.0', () => console.log('[FasoSouverain] http://localhost:3000 · Synapse connecté'));
  const stop = () => server.close(async () => { await store.close(); await app.matrix.auditPool?.end(); process.exit(0); });
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
  return { app, server, store };
}
module.exports = { start, bootstrapAdmin };
