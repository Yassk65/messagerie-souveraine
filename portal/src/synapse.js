const crypto = require('crypto');

class SynapseEngine {
  constructor({ url, serverName, adminToken }) {
    this.url = url;
    this.serverName = serverName;
    this.adminToken = adminToken;
    this.tokens = new Map();
    this.roomMappings = new Map();
  }

  async request(path, method = 'GET', body, token = this.adminToken) {
    if (!this.url || !token && !path.endsWith('/login')) {
      throw Object.assign(new Error('Configuration Synapse manquante.'), { status: 503 });
    }
    let response;
    try {
      response = await fetch(this.url + path, {
        method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(40000),
      });
    } catch {
      throw Object.assign(new Error('Synapse est indisponible. Réessayez la connexion.'), { status: 503 });
    }
    const data = await response.json();
    if (!response.ok) throw Object.assign(new Error(data.error || 'Erreur Synapse'), { status: response.status, code: data.errcode });
    return data;
  }

  async login(localpart, password, deviceId) {
    const result = await this.request('/_matrix/client/v3/login', 'POST', {
      type: 'm.login.password', identifier: { type: 'm.id.user', user: localpart }, password,
      ...(deviceId ? { device_id: deviceId } : {}), initial_device_display_name: 'FasoSouverain · Navigateur',
    }, null);
    this.tokens.set(result.access_token, { userId: result.user_id, deviceId: result.device_id });
    return result;
  }

  verifyAccessToken(token) { return this.tokens.get(token); }
  tokenFor(userId) {
    for (const [token, session] of this.tokens) if (session.userId === userId) return token;
    throw Object.assign(new Error('Session Matrix absente'), { status: 401 });
  }

  async registerUser(localpart, password, isAdmin = false) {
    const userId = `@${localpart}:${this.serverName}`;
    // Retrying an interrupted enrollment must not reset an existing account's password.
    try { return await this.request(`/_synapse/admin/v2/users/${encodeURIComponent(userId)}`); }
    catch (error) { if (error.status !== 404) throw error; }
    return this.request(`/_synapse/admin/v2/users/${encodeURIComponent(userId)}`, 'PUT', {
      password, admin: isAdmin, deactivated: false,
    });
  }

  async deactivateUser(localpart) {
    const userId = `@${localpart}:${this.serverName}`;
    const rooms = await this.request(`/_synapse/admin/v1/users/${encodeURIComponent(userId)}/joined_rooms`);
    await this.request(`/_synapse/admin/v1/deactivate/${encodeURIComponent(userId)}`, 'POST', { erase: false });
    let count = 0;
    for (const [token, session] of this.tokens) if (session.userId === userId) { this.tokens.delete(token); count++; }
    return { user_id: userId, deactivated: true, revoked_sessions: count, rooms_removed: rooms.joined_rooms.length };
  }

  async getRoomsForUser(userId) {
    const token = this.tokenFor(userId);
    const { joined_rooms: ids } = await this.request('/_matrix/client/v3/joined_rooms', 'GET', undefined, token);
    return Promise.all(ids.map(async (roomId) => {
      const state = await this.request(`/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/state`, 'GET', undefined, token);
      const value = (type) => state.find(e => e.type === type)?.content || {};
      return { room_id: roomId, name: value('m.room.name').name || 'Conversation privée', topic: value('m.room.topic').topic || '',
        ministry: value('bf.faso.room').ministry || '', isDirect: !!value('bf.faso.room').isDirect,
        encryption: value('m.room.encryption').algorithm,
        members: state.filter(e => e.type === 'm.room.member' && e.content.membership === 'join').map(e => e.state_key) };
    }));
  }

  async createEncryptedRoom(creatorId, { name, topic, ministry, inviteLocalparts = [], isDirect = false, mappingKey, recovering = false }) {
    const key = mappingKey || `room:${crypto.randomUUID()}`;
    const token = this.tokenFor(creatorId);
    if (this.roomMappings.has(key)) {
      const roomId = this.roomMappings.get(key);
      try {
        await this.request(`/_matrix/client/v3/join/${encodeURIComponent(roomId)}`, 'POST', {}, token);
        const encryption = await this.request(`/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/state/m.room.encryption`, 'GET', undefined, token);
        if (encryption.algorithm !== 'm.megolm.v1.aes-sha2') throw Object.assign(new Error('Salon incomplet'), { status: 404 });
        return { room_id: roomId, existing: true };
      } catch (error) { if (![403, 404].includes(error.status)) throw error; this.roomMappings.delete(key); }
    }
    // Deterministic alias makes retry after a process crash idempotent on Synapse too.
    const alias = 'faso_' + crypto.createHash('sha256').update(key).digest('hex').slice(0, 32);
    let result;
    try {
      result = await this.request('/_matrix/client/v3/createRoom', 'POST', {
        name, topic, room_alias_name: alias, visibility: 'private', preset: 'private_chat', is_direct: isDirect,
        invite: inviteLocalparts.map(lp => `@${lp}:${this.serverName}`),
        initial_state: [
          { type: 'm.room.encryption', state_key: '', content: { algorithm: 'm.megolm.v1.aes-sha2' } },
          { type: 'bf.faso.room', state_key: '', content: { ministry, isDirect } },
          { type: 'm.room.history_visibility', state_key: '', content: { history_visibility: 'joined' } },
        ],
        power_level_content_override: { invite: 100, kick: 100, ban: 100, state_default: 100 },
      }, token);
    } catch (error) {
      if (error.code !== 'M_ROOM_IN_USE') throw error;
      result = await this.request(`/_matrix/client/v3/directory/room/${encodeURIComponent(`#${alias}:${this.serverName}`)}`, 'GET', undefined, token);
      try {
        await this.request(`/_matrix/client/v3/join/${encodeURIComponent(result.room_id)}`, 'POST', {}, token);
        const encryption = await this.request(`/_matrix/client/v3/rooms/${encodeURIComponent(result.room_id)}/state/m.room.encryption`, 'GET', undefined, token);
        if (encryption.algorithm !== 'm.megolm.v1.aes-sha2') throw Object.assign(new Error('Salon incomplet'), { status: 404 });
      } catch (joinError) {
        if (recovering || ![403, 404].includes(joinError.status)) throw joinError;
        // A failed Synapse room creation can reserve an alias before creating events.
        await this.request(`/_matrix/client/v3/directory/room/${encodeURIComponent(`#${alias}:${this.serverName}`)}`, 'DELETE');
        return this.createEncryptedRoom(creatorId, { name, topic, ministry, inviteLocalparts, isDirect, mappingKey: key, recovering: true });
      }
    }
    this.roomMappings.set(key, result.room_id);
    return result;
  }

  getOrCreateDirectRoom(creatorId, target, name) {
    return this.createEncryptedRoom(creatorId, { name, topic: 'Conversation privée chiffrée', ministry: 'DIRECT', isDirect: true,
      inviteLocalparts: [target], mappingKey: `dm:${[creatorId, `@${target}:${this.serverName}`].sort().join('|')}` });
  }

  async getRoomEvents(userId, roomId) {
    const result = await this.request(`/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/messages?dir=b&limit=100`, 'GET', undefined, this.tokenFor(userId));
    return result.chunk.reverse();
  }

  async sendEncryptedEvent(userId, roomId, type, content) {
    if (type !== 'm.room.encrypted' || content.algorithm !== 'm.megolm.v1.aes-sha2' || !content.ciphertext || content.body || content.plaintext) {
      throw Object.assign(new Error('Seuls les événements Matrix chiffrés sont autorisés.'), { status: 400 });
    }
    return this.request(`/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/send/m.room.encrypted/${crypto.randomUUID()}`, 'PUT', content, this.tokenFor(userId));
  }

  async inspectServerBlindness() {
    // Actual SQL inspection, no invented certification or hard-coded zero count.
    if (!this.auditPool) return { status: 'UNAVAILABLE', message: 'Inspection SQL indisponible' };
    const { rows } = await this.auditPool.query("SELECT type, count(*)::integer AS count FROM events WHERE type IN ('m.room.message','m.room.encrypted') GROUP BY type");
    const counts = Object.fromEntries(rows.map(row => [row.type, row.count]));
    return { status: counts['m.room.message'] ? 'VIOLATION_DETECTED' : 'BLIND_OK', clear_text_events_count: counts['m.room.message'] || 0, event_types_summary: counts };
  }
}

module.exports = { SynapseEngine };
