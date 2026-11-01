import * as sdk from 'matrix-js-sdk';
import { decodeRecoveryKey } from 'matrix-js-sdk/lib/crypto-api/recovery-key';
import { encryptAttachment, decryptAttachment } from 'matrix-encrypt-attachment';

export class SecureMessenger {
  constructor(session, transport, ui) {
    this.session = session; this.transport = transport; this.ui = ui;
    this.cryptoPrefix = `faso:${encodeURIComponent(session.agent.userId)}:${session.deviceId}`;
    this.envelopes = new Map(); this.secretKeys = new Map(); this.objectUrls = new Set();
  }
  async start() {
    const uid = this.session.agent.userId;
    if (navigator.locks) {
      await new Promise((resolve, reject) => {
        navigator.locks.request(`faso-crypto:${uid}:${this.session.deviceId}`, { ifAvailable: true }, lock => {
          if (!lock) { reject(new Error('Cet appareil est déjà ouvert dans un autre onglet. Utilisez cet onglet ou déconnectez-le.')); return; }
          return new Promise(release => { this.releaseLock = release; resolve(); });
        }).catch(reject);
      });
    }
    this.client = sdk.createClient({
      baseUrl: location.origin + '/matrix', userId: uid, deviceId: this.session.deviceId,
      accessToken: 'portal-session', verificationMethods: ['m.sas.v1'],
      fetchFn: async (url, options = {}) => {
        const headers = new Headers(options.headers);
        const txn = decodeURIComponent(new URL(url).pathname.split('/').at(-1));
        if (this.envelopes.has(txn) && options.body) {
          const payload = JSON.parse(options.body);
          payload.faso_meta = this.envelopes.get(txn);
          options = { ...options, body: JSON.stringify(payload) };
        }
        headers.delete('Authorization');
        return this.transport(url, { ...options, headers });
      },
      cryptoCallbacks: {
        cacheSecretStorageKey: (id, info, key) => this.secretKeys.set(id, key),
        getSecretStorageKey: async ({ keys }) => {
          const id = Object.keys(keys)[0];
          if (!this.secretKeys.has(id)) {
            const encoded = await this.ui.ask('Clé de récupération', 'Saisissez votre clé de récupération Matrix.', true);
            if (!encoded) return null;
            try { this.secretKeys.set(id, decodeRecoveryKey(encoded.trim())); }
            catch { throw new Error('Clé de récupération invalide. Vérifiez les caractères et les espaces.'); }
          }
          return [id, this.secretKeys.get(id)];
        },
      },
    });
    this.client.on('sync', state => this.ui.connection(state));
    this.client.on('Room.timeline', () => this.ui.changed());
    this.client.on('Event.decrypted', () => this.ui.changed());
    this.client.on('RoomMember.membership', async (event, member) => {
      if (member.userId === uid && member.membership === 'invite') {
        try { await this.client.joinRoom(member.roomId); } catch (e) { this.ui.error(e); }
      }
    });
    this.client.on('crypto.verificationRequestReceived', request => this.verification(request).catch(e => this.ui.error(e)));
    for (const name of ['crypto.keyBackupStatus', 'crypto.keyBackupDecryptionKeyCached', 'userTrustStatusChanged', 'crypto.devicesUpdated']) this.client.on(name, () => this.ui.trustChanged?.());
    await this.client.initRustCrypto({ cryptoDatabasePrefix: this.cryptoPrefix });
    await this.client.startClient({ initialSyncLimit: 50, lazyLoadMembers: false });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.client.off('sync', listener); reject(new Error('Synchronisation Matrix trop longue. Réessayez.')); }, 45000);
      const listener = state => { if (state === 'PREPARED') { clearTimeout(timer); this.client.off('sync', listener); resolve(); } };
      this.client.on('sync', listener);
    });
    for (const room of this.client.getRooms()) if (room.getMyMembership() === 'invite') await this.client.joinRoom(room.roomId);
  }

  rooms() { return this.client.getRooms().filter(r => r.getMyMembership() === 'join'); }
  events(roomId) { return this.client.getRoom(roomId)?.getLiveTimeline().getEvents() || []; }
  async send(roomId, { text, file, voice, meta }) {
    let content = { msgtype: 'm.text', body: text || '', faso_meta: meta };
    if (file) {
      if (file.size > 14 * 1024 * 1024) throw new Error('Fichier trop volumineux (14 Mo maximum).');
      const encrypted = await encryptAttachment(await file.arrayBuffer());
      const response = await this.transport('/matrix/_matrix/media/v3/upload', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: new Blob([encrypted.data], { type: 'application/octet-stream' }) });
      if (!response.ok) throw new Error('Téléversement du fichier chiffré impossible.');
      const uploaded = await response.json();
      content = { ...content, msgtype: voice ? 'm.audio' : file.type.startsWith('image/') ? 'm.image' : 'm.file', body: file.name,
        filename: file.name, info: { mimetype: file.type, size: file.size }, file: { ...encrypted.info, url: uploaded.content_uri } };
    }
    const txn = 'faso_' + crypto.randomUUID();
    this.envelopes.set(txn, meta);
    try { return await this.client.sendEvent(roomId, 'm.room.message', content, txn); }
    finally { this.envelopes.delete(txn); }
  }

  async attachment(content) {
    const [server, id] = content.file.url.slice('mxc://'.length).split('/');
    const response = await this.transport(`/matrix/_matrix/client/v1/media/download/${encodeURIComponent(server)}/${encodeURIComponent(id)}`);
    if (!response.ok) throw new Error('Téléchargement impossible.');
    const data = await decryptAttachment(await response.arrayBuffer(), content.file);
    const url = URL.createObjectURL(new Blob([data], { type: content.info?.mimetype || 'application/octet-stream' }));
    this.objectUrls.add(url); return url;
  }

  async setupRecovery() {
    const cryptoApi = this.client.getCrypto();
    if (await cryptoApi.isSecretStorageReady()) throw new Error('Une sauvegarde existe déjà. Utilisez « Restaurer les clés ».');
    await cryptoApi.bootstrapCrossSigning({ authUploadDeviceSigningKeys: async makeRequest => {
      try { await makeRequest({}); }
      catch (error) {
        if (error.httpStatus !== 401) throw error;
        const password = await this.ui.ask('Confirmer votre identité', 'Mot de passe du compte pour activer la signature des appareils.', true);
        if (!password) throw new Error('Configuration annulée.');
        await makeRequest({ type: 'm.login.password', identifier: { type: 'm.id.user', user: this.session.agent.userId }, password, session: error.data?.session });
      }
    } });
    const key = await cryptoApi.createRecoveryKeyFromPassphrase();
    await this.ui.showKey(key.encodedPrivateKey);
    await cryptoApi.bootstrapSecretStorage({ setupNewSecretStorage: true, setupNewKeyBackup: true, createSecretStorageKey: async () => key });
    await cryptoApi.checkKeyBackupAndEnable();
    return 'Sauvegarde chiffrée activée. Conservez votre clé hors de cet appareil.';
  }

  async restore() {
    this.secretKeys.clear();
    await this.client.getCrypto().bootstrapCrossSigning({});
    await this.client.getCrypto().loadSessionBackupPrivateKeyFromSecretStorage();
    const result = await this.client.getCrypto().restoreKeyBackup();
    this.ui.changed(); return `${result.imported || 0} session(s) cryptographique(s) restaurée(s).`;
  }

  async verification(request) {
    if (!request.initiatedByMe && !await this.ui.confirm('Vérification d’appareil', `Accepter la vérification avec ${request.otherUserId} / ${request.otherDeviceId || ''} ?`)) {
      await request.cancel(); return;
    }
    if (!request.initiatedByMe) await request.accept();
    this.ui.notice('Demande envoyée. Ouvrez l’autre appareil pour comparer les codes.');
    const verifier = await new Promise((resolve, reject) => {
      const changed = async () => {
        try {
          if (request.phase === 5 || request.phase === 6) { request.off('change', changed); reject(new Error('Vérification terminée ou annulée.')); }
          else if (request.verifier) { request.off('change', changed); resolve(request.verifier); }
          else if (request.phase === 3 && request.initiatedByMe) { request.off('change', changed); resolve(await request.startVerification('m.sas.v1')); }
        } catch (error) { reject(error); }
      };
      request.on('change', changed); changed();
    });
    verifier.on('show_sas', async callbacks => {
      const sas = callbacks.sas.emoji?.map(([emoji, name]) => `${emoji} ${name}`).join(' · ') || callbacks.sas.decimal?.join(' — ');
      if (await this.ui.confirm('Comparer sur les deux appareils', sas)) await callbacks.confirm(); else callbacks.mismatch();
    });
    await verifier.verify(); this.ui.notice('Appareil vérifié.'); this.ui.changed();
  }
  async verifyDevice(deviceId) { await this.verification(await this.client.getCrypto().requestDeviceVerification(this.session.agent.userId, deviceId)); }
  async trust() { return this.client.getCrypto().getDeviceVerificationStatus(this.session.agent.userId, this.session.deviceId); }
  stop() { this.client?.stopClient(); this.releaseLock?.(); this.releaseLock = null; this.secretKeys.clear(); for (const url of this.objectUrls) URL.revokeObjectURL(url); this.objectUrls.clear(); }
  async wipe() { this.stop(); await this.client?.clearStores({ cryptoDatabasePrefix: this.cryptoPrefix }); }
}
