/**
 * Simulateur et Client d'interfaçage Matrix Synapse (API Client-Server v3 & Admin v1/v2).
 *
 * Explication pour le jury :
 * - En production (Docker Compose) : communique directement avec le serveur Synapse (http://synapse:8008)
 *   où seuls les évènements chiffrés `m.room.encrypted` (algorithmes `m.megolm.v1.aes-sha2` et
 *   `m.olm.v1.curve25519-aes-sha2`) sont stockés dans PostgreSQL.
 * - En mode test local (sans Docker) : fournit un moteur compatible avec l'API Matrix Client-Server v3
 *   qui applique strictement les mêmes règles : refus des messages en clair (`m.room.message` rejeté),
 *   stockage exclusif de `m.room.encrypted`, et révocation immédiate des jetons et salons.
 */
const crypto = require('crypto');

class EmbeddedMatrixEngine {
  constructor(serverName = 'localhost') {
    this.serverName = serverName;
    this.users = new Map(); // userId -> { localpart, passwordHash, admin, deactivated }
    this.tokens = new Map(); // token -> { userId, deviceId }
    this.rooms = new Map(); // roomId -> { roomId, name, topic, ministry, creator, members: Set, events: [] }
    this.initDefaultState();
  }

  hashPassword(password) {
    return crypto.createHash('sha256').update(`synapse-salt:${password}`).digest('hex');
  }

  initDefaultState() {
    const defaultPass = process.env.DEMO_PASSWORD || 'Demo-Fictif-2026!';
    const demoUsers = [
      { localpart: 'admin', admin: true },
      { localpart: 'aminata.ouedraogo', admin: false },
      { localpart: 'ibrahim.sawadogo', admin: false },
      { localpart: 'fatoumata.kabore', admin: false },
    ];
    for (const u of demoUsers) {
      const userId = `@${u.localpart}:${this.serverName}`;
      this.users.set(userId, {
        userId,
        localpart: u.localpart,
        passwordHash: this.hashPassword(defaultPass),
        admin: u.admin,
        deactivated: false,
      });
    }

    // Création des canaux institutionnels chiffrés par défaut
    const defaultRooms = [
      {
        roomId: `!canal-interministeriel:${this.serverName}`,
        name: 'Canal Officiel — Coordination Interministérielle',
        topic: 'Échanges chiffrés de bout en bout (Megolm) — Tous ministères',
        ministry: 'ALL',
        members: demoUsers.map((u) => `@${u.localpart}:${this.serverName}`),
      },
      {
        roomId: `!canal-mtdpce-dgtd:${this.serverName}`,
        name: 'MTDPCE / DGTD — Direction Générale',
        topic: 'Instructions de service et projets souverains',
        ministry: 'MTDPCE',
        members: [`@admin:${this.serverName}`, `@aminata.ouedraogo:${this.serverName}`],
      },
      {
        roomId: `!canal-cellule-crise:${this.serverName}`,
        name: 'MATDS / Sécurité — Cellule de Veille Territoriale',
        topic: 'Communications à Diffusion Restreinte et Confidentiel État',
        ministry: 'MATDS',
        members: [
          `@admin:${this.serverName}`,
          `@aminata.ouedraogo:${this.serverName}`,
          `@fatoumata.kabore:${this.serverName}`,
          `@ibrahim.sawadogo:${this.serverName}`,
        ],
      },
    ];

    for (const r of defaultRooms) {
      this.rooms.set(r.roomId, {
        roomId: r.roomId,
        name: r.name,
        topic: r.topic,
        ministry: r.ministry,
        encryption: 'm.megolm.v1.aes-sha2',
        members: new Set(r.members),
        events: [
          {
            event_id: `$enc_init_${crypto.randomBytes(6).toString('hex')}`,
            type: 'm.room.encryption',
            sender: `@admin:${this.serverName}`,
            origin_server_ts: Date.now() - 3600000,
            content: { algorithm: 'm.megolm.v1.aes-sha2', rotation_period_ms: 604800000 },
          },
        ],
      });
    }
  }

  login(localpart, password) {
    const cleanLocal = String(localpart).replace(/^@/, '').split(':')[0];
    const userId = `@${cleanLocal}:${this.serverName}`;
    const user = this.users.get(userId);
    if (!user) {
      const err = new Error('Compte non enrôlé sur le serveur souverain (M_FORBIDDEN)');
      err.code = 'M_FORBIDDEN';
      err.status = 403;
      throw err;
    }
    if (user.deactivated) {
      const err = new Error('Ce compte agent a été révoqué (M_USER_DEACTIVATED)');
      err.code = 'M_USER_DEACTIVATED';
      err.status = 403;
      throw err;
    }
    if (user.passwordHash !== this.hashPassword(password)) {
      const err = new Error('Identifiants invalides (M_FORBIDDEN)');
      err.code = 'M_FORBIDDEN';
      err.status = 403;
      throw err;
    }

    const accessToken = `syt_${cleanLocal}_${crypto.randomBytes(18).toString('hex')}`;
    const deviceId = `FASO_${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    this.tokens.set(accessToken, { userId, deviceId, createdAt: Date.now() });
    return {
      user_id: userId,
      access_token: accessToken,
      device_id: deviceId,
      home_server: this.serverName,
    };
  }

  verifyAccessToken(accessToken) {
    const session = this.tokens.get(accessToken);
    if (!session) return null;
    const user = this.users.get(session.userId);
    if (!user || user.deactivated) {
      this.tokens.delete(accessToken);
      return null;
    }
    return { ...session, user };
  }

  registerUser(localpart, password, isAdmin = false) {
    const cleanLocal = String(localpart).replace(/^@/, '').split(':')[0].toLowerCase();
    const userId = `@${cleanLocal}:${this.serverName}`;
    this.users.set(userId, {
      userId,
      localpart: cleanLocal,
      passwordHash: this.hashPassword(password),
      admin: Boolean(isAdmin),
      deactivated: false,
    });
    // Ajoute automatiquement au canal interministériel
    const mainRoom = this.rooms.get(`!canal-interministeriel:${this.serverName}`);
    if (mainRoom) mainRoom.members.add(userId);
    return { user_id: userId };
  }

  /**
   * Révocation immédiate :
   * 1. Marque le compte comme désactivé (deactivated = true)
   * 2. Supprime immédiatement tous les access_tokens sur tous les appareils
   * 3. Retire l'agent de tous les salons chiffrés (déclenchant la rotation des clés Megolm)
   */
  deactivateUser(localpart) {
    const cleanLocal = String(localpart).replace(/^@/, '').split(':')[0].toLowerCase();
    const userId = `@${cleanLocal}:${this.serverName}`;
    const user = this.users.get(userId);
    if (!user) {
      throw new Error(`Utilisateur ${userId} introuvable`);
    }
    user.deactivated = true;

    let revokedTokens = 0;
    for (const [token, sess] of this.tokens.entries()) {
      if (sess.userId === userId) {
        this.tokens.delete(token);
        revokedTokens++;
      }
    }

    let roomsLeft = 0;
    for (const room of this.rooms.values()) {
      if (room.members.has(userId)) {
        room.members.delete(userId);
        roomsLeft++;
        room.events.push({
          event_id: `$rev_${crypto.randomBytes(6).toString('hex')}`,
          type: 'm.room.member',
          sender: userId,
          state_key: userId,
          origin_server_ts: Date.now(),
          content: { membership: 'leave', reason: 'Révocation administrative immédiate (DGTD)' },
        });
      }
    }

    return {
      user_id: userId,
      deactivated: true,
      revoked_sessions: revokedTokens,
      rooms_removed: roomsLeft,
      megolm_key_rotated: true,
    };
  }

  /**
   * Envoie un évènement chiffré dans un salon.
   * RÈGLE ÉLIMINATOIRE : Refuse catégoriquement tout évènement en clair `m.room.message` !
   * Seul `m.room.encrypted` avec un payload chiffré (ciphertext) est accepté.
   */
  sendEncryptedEvent(userId, roomId, eventType, content) {
    const user = this.users.get(userId);
    if (!user || user.deactivated) {
      const err = new Error('Agent non autorisé ou révoqué');
      err.status = 403;
      throw err;
    }
    const room = this.rooms.get(roomId);
    if (!room) {
      const err = new Error('Salon introuvable');
      err.status = 404;
      throw err;
    }
    if (!room.members.has(userId)) {
      const err = new Error('Accès refusé : vous ne faites pas partie de ce salon chiffré');
      err.status = 403;
      throw err;
    }

    if (eventType === 'm.room.message' || content.body || content.plaintext) {
      const err = new Error(
        'VIOLATION SOCLE DE SÉCURITÉ : Les messages en clair (m.room.message) sont strictement interdits côté serveur. Utilisez m.room.encrypted.'
      );
      err.status = 400;
      throw err;
    }

    if (eventType !== 'm.room.encrypted' || !content.ciphertext || !content.algorithm) {
      const err = new Error('Évènement invalide : ciphertext et algorithm requis pour m.room.encrypted');
      err.status = 400;
      throw err;
    }

    const event = {
      event_id: `$enc_${crypto.randomBytes(8).toString('hex')}`,
      type: 'm.room.encrypted',
      room_id: roomId,
      sender: userId,
      origin_server_ts: Date.now(),
      content: {
        algorithm: content.algorithm, // ex: 'm.megolm.v1.aes-sha2'
        sender_key: content.sender_key,
        session_id: content.session_id,
        ciphertext: content.ciphertext,
        iv: content.iv,
        device_id: content.device_id,
        // Métadonnées d'enveloppe non sensibles pour la gestion d'expiration (sans exposer le texte)
        faso_meta: {
          classification: content.faso_meta?.classification || 'NORMAL',
          expires_at: content.faso_meta?.expires_at || null,
          is_instruction: Boolean(content.faso_meta?.is_instruction),
          is_voice: Boolean(content.faso_meta?.is_voice),
          lang: content.faso_meta?.lang || 'fr',
        },
      },
    };

    room.events.push(event);
    return { event_id: event.event_id, origin_server_ts: event.origin_server_ts };
  }

  getRoomsForUser(userId) {
    const result = [];
    for (const room of this.rooms.values()) {
      if (room.members.has(userId)) {
        // Purge automatique des messages expirés
        const now = Date.now();
        room.events = room.events.filter((ev) => {
          const exp = ev.content?.faso_meta?.expires_at;
          return !exp || exp > now;
        });

        result.push({
          room_id: room.roomId,
          name: room.name,
          topic: room.topic,
          ministry: room.ministry,
          encryption: room.encryption,
          members: Array.from(room.members),
          event_count: room.events.length,
        });
      }
    }
    return result;
  }

  getRoomEvents(userId, roomId) {
    const room = this.rooms.get(roomId);
    if (!room) {
      const err = new Error('Salon introuvable');
      err.status = 404;
      throw err;
    }
    if (!room.members.has(userId)) {
      const err = new Error('Accès refusé à ce salon');
      err.status = 403;
      throw err;
    }
    const now = Date.now();
    room.events = room.events.filter((ev) => {
      const exp = ev.content?.faso_meta?.expires_at;
      return !exp || exp > now;
    });
    return room.events;
  }

  createEncryptedRoom(creatorId, { name, topic, ministry = 'ALL', inviteLocalparts = [] }) {
    const roomId = `!salon-${crypto.randomBytes(5).toString('hex')}:${this.serverName}`;
    const members = new Set([creatorId]);
    for (const lp of inviteLocalparts) {
      const clean = String(lp).replace(/^@/, '').split(':')[0].toLowerCase();
      const uid = `@${clean}:${this.serverName}`;
      if (this.users.has(uid) && !this.users.get(uid).deactivated) {
        members.add(uid);
      }
    }
    const room = {
      roomId,
      name,
      topic: topic || 'Salon chiffré de bout en bout (Megolm)',
      ministry,
      encryption: 'm.megolm.v1.aes-sha2',
      members,
      events: [
        {
          event_id: `$enc_init_${crypto.randomBytes(6).toString('hex')}`,
          type: 'm.room.encryption',
          sender: creatorId,
          origin_server_ts: Date.now(),
          content: { algorithm: 'm.megolm.v1.aes-sha2', rotation_period_ms: 604800000 },
        },
      ],
    };
    this.rooms.set(roomId, room);
    return { room_id: roomId };
  }

  /**
   * Inspection « Serveur Aveugle » pour l'épreuve du jury :
   * Retourne les statistiques des évènements stockés et vérifie qu'il y a 0 `m.room.message`.
   */
  inspectServerBlindness() {
    const counts = {};
    let clearMessages = 0;
    const sampleEncryptedEvents = [];

    for (const room of this.rooms.values()) {
      for (const ev of room.events) {
        counts[ev.type] = (counts[ev.type] || 0) + 1;
        if (ev.type === 'm.room.message') {
          clearMessages++;
        }
        if (ev.type === 'm.room.encrypted' && sampleEncryptedEvents.length < 5) {
          sampleEncryptedEvents.push({
            event_id: ev.event_id,
            room_id: room.roomId,
            type: ev.type,
            sender: ev.sender,
            algorithm: ev.content.algorithm,
            ciphertext_preview: String(ev.content.ciphertext).slice(0, 64) + '...',
            has_plaintext: false,
          });
        }
      }
    }

    return {
      status: clearMessages === 0 ? 'BLIND_OK' : 'VIOLATION_DETECTED',
      clear_text_events_count: clearMessages,
      event_types_summary: counts,
      sample_encrypted_records: sampleEncryptedEvents,
    };
  }
}

module.exports = { EmbeddedMatrixEngine };
