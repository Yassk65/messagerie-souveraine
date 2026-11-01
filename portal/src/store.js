const crypto = require('crypto');
const { Pool } = require('pg');

class PostgresStore {
  constructor(connectionString, secret) {
    if (!secret || secret.length < 32) throw new Error('PORTAL_STORAGE_KEY doit contenir au moins 32 caractères.');
    this.key = crypto.createHash('sha256').update(secret).digest();
    this.pool = new Pool({ connectionString });
  }
  seal(value) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    const data = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), data]);
  }
  open(data) {
    const cipher = crypto.createDecipheriv('aes-256-gcm', this.key, data.subarray(0, 12));
    cipher.setAuthTag(data.subarray(12, 28));
    return JSON.parse(Buffer.concat([cipher.update(data.subarray(28)), cipher.final()]).toString());
  }
  async init() {
    // Dedicated connection holds a singleton lock: two writers cannot clobber this registry.
    this.lock = await this.pool.connect();
    const result = await this.lock.query('SELECT pg_try_advisory_lock(2262026) AS acquired');
    if (!result.rows[0].acquired) throw new Error('Un autre portail utilise déjà cette base.');
    await this.pool.query(require('fs').readFileSync(require('path').join(__dirname, 'migrations/001_registry.sql'), 'utf8'));
    const { rows } = await this.pool.query('SELECT payload FROM portal_registry WHERE id = 1');
    return rows[0] ? this.open(rows[0].payload) : null;
  }
  async save(value) {
    await this.pool.query('INSERT INTO portal_registry (id,payload) VALUES (1,$1) ON CONFLICT (id) DO UPDATE SET payload=EXCLUDED.payload, updated_at=now()', [this.seal(value)]);
  }
  async close() { this.lock?.release(); await this.pool.end(); }
}
module.exports = { PostgresStore };
