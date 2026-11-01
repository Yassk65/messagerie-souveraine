// Run inside the portal container via stdin; credentials never leave that container.
const assert = require('node:assert/strict');
const fs = require('fs');
const crypto = require('crypto');
const { PostgresStore } = require('./src/store');
const { Pool } = require('pg');
async function main() {
  if (process.env.DEMO_MODE !== 'true') throw new Error('Ce test est réservé à la démonstration.');
  const key = fs.readFileSync('/run/bootstrap/portal-storage-key', 'utf8').trim();
  const store = new PostgresStore(process.env.DATABASE_URL, key);
  try {
    const { rows } = await store.pool.query('SELECT payload,schema_version FROM portal_registry WHERE id=1');
    assert.equal(rows[0].schema_version, 1);
    const registry = store.open(rows[0].payload);
    const agent = registry.directory.find(([name]) => name === 'admin')[1];
    assert.equal(rows[0].payload.includes(Buffer.from(agent.totpSecret)), false);
    const sessions = registry.serverSessions.map(([, s]) => s).filter(s => s.localpart === 'admin' && s.expiresAt > Date.now());
    assert.ok(sessions.length, 'Connectez le compte admin de démonstration avant ce contrôle interne.');
    const token = sessions.at(-1).matrixAccessToken;
    const roomId = registry.roomMappings[0][1];
    async function request(path, method = 'GET', body) {
      return fetch(process.env.SYNAPSE_INTERNAL_URL + path, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    }
    const base = '/_matrix/client/v3/rooms/' + encodeURIComponent(roomId);
    const clear = await request(base + '/send/m.room.message/' + crypto.randomUUID(), 'PUT', { msgtype: 'm.text', body: 'Fictitious security acceptance probe' });
    assert.equal(clear.status, 403, 'The Synapse module itself must reject plaintext, independent of the gateway');
    const disable = await request(base + '/state/m.room.encryption', 'PUT', {});
    assert.equal(disable.status, 403, 'Encryption cannot be removed');
    const state = await (await request(base + '/state')).json();
    const event = state.find(e => e.type === 'm.room.encryption');
    const redact = await request(base + '/redact/' + encodeURIComponent(event.event_id) + '/' + crypto.randomUUID(), 'PUT', { reason: 'Security acceptance probe' });
    assert.equal(redact.status, 403, 'Encryption state cannot be redacted');
    console.log('PASS actual Synapse module: plaintext, encryption removal and redaction rejected');
    console.log('PASS persisted encrypted PostgreSQL registry');
    const auditUrl = new URL(process.env.SYNAPSE_AUDIT_DATABASE_URL);
    auditUrl.username = 'faso_portal_audit'; auditUrl.password = crypto.createHmac('sha256', key).update('faso-audit-role').digest('hex');
    const audit = new Pool({ connectionString: auditUrl.toString() });
    try {
      const counts = await audit.query("SELECT type,count(*)::integer AS count FROM events WHERE type IN ('m.room.message','m.room.encrypted') GROUP BY type");
      assert.equal(counts.rows.find(row => row.type === 'm.room.message')?.count || 0, 0);
      assert.ok(counts.rows.find(row => row.type === 'm.room.encrypted')?.count > 0);
      await assert.rejects(audit.query('DELETE FROM events WHERE false'), error => error.code === '42501');
      console.log('PASS real encrypted events in Synapse PostgreSQL and read-only audit role');
    } finally { await audit.end(); }
  } finally { await store.pool.end(); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
