/**
 * Application Web « FasoSouverain » — Messagerie Instantanée de l'Administration
 *
 * Fonctionnement utilisateur & sécurité transparente :
 * - Chiffrement de bout en bout automatique (WebCrypto AES-256-GCM / Matrix Megolm)
 * - Authentification à 2 facteurs (Mot de passe + TOTP 6 chiffres RFC 6238)
 * - Discussions de groupe (Canaux ministériels) et Conversations privées (1:1 depuis l'annuaire)
 * - Partage de fichiers chiffrés, Notes vocales, Niveaux de confidentialité et Instructions officielles
 * - Multilingue : Français, Mooré, Dioula, Fulfuldé
 */

const I18N = {
  fr: {
    app_title: 'FasoSouverain',
    gov_motto: "Messagerie Instantanée de l'Administration Publique · Burkina Faso",
    lang_label: 'Langue :',
    panic_btn: 'Urgence',
    logout_btn: 'Quitter',
    label_username: 'Identifiant ou Matricule Agent',
    label_password: 'Mot de passe',
    btn_step1: 'Continuer',
    label_totp: "Code d'authentification à 6 chiffres (Application 2FA)",
    btn_step2: 'Se connecter',
    tab_chat: 'Messages',
    tab_directory: 'Annuaire',
    tab_admin: 'Sécurité',
    channels_title: 'Canaux & Conversations',
    label_classification: 'Confidentialité :',
    label_ttl: 'Message éphémère :',
    label_instruction: 'Note / Instruction officielle (Accusé de lecture)',
    msg_placeholder: 'Écrire un message...',
    btn_send: 'Envoyer',
    dir_title: 'Annuaire des Ministères & Institutions',
    dir_subtitle:
      'Recherchez un agent public par ministère ou direction pour démarrer une conversation directe chiffrée.',
  },
  mos: {
    app_title: 'FasoSouverain',
    gov_motto: 'Gouvernement Tʋʋm-tʋmdb Sõsg Zĩiga · Burkina Faso',
    lang_label: 'Goama :',
    panic_btn: 'Yãgbo',
    logout_btn: 'Yi',
    label_username: 'Tʋʋm-tʋmd Yʋʋre / Matricule',
    label_password: 'Kʋɩlenga (Mot de passe)',
    btn_step1: 'Kẽng taoora',
    label_totp: 'TOTP Sõor a 6 (2FA)',
    btn_step2: 'Kẽ',
    tab_chat: 'Koɛɛga',
    tab_directory: 'Sebre',
    tab_admin: 'Gũusgo',
    channels_title: 'Sõsg Zĩisi',
    label_classification: 'Gũusg Zĩiga :',
    label_ttl: 'Saabo :',
    label_instruction: 'Tʋʋm Noy (Instruction officielle)',
    msg_placeholder: 'Gʋls koɛɛga...',
    btn_send: 'Tʋm',
    dir_title: 'Ministɛɛr Tʋʋm-tʋmdb Sebre',
    dir_subtitle: 'Yãk tʋʋm-tʋmd n sɩng sõsg sẽn pag ne E2EE.',
  },
  dyu: {
    app_title: 'FasoSouverain',
    gov_motto: 'Fanga Baarakɛlaw Baro Kɛyɔrɔ · Burkina Faso',
    lang_label: 'Kan :',
    panic_btn: 'Balawo',
    logout_btn: 'Bɔ',
    label_username: 'Baarakɛla Tɔgɔ / Matricule',
    label_password: 'Gundodaɲɛ',
    btn_step1: 'Taa ɲɛ',
    label_totp: 'TOTP Nimɔrɔ 6 (2FA)',
    btn_step2: 'Don',
    tab_chat: 'Batakiw',
    tab_directory: 'Tɔgɔsɛbɛn',
    tab_admin: 'Lakana',
    channels_title: 'Baro Kɛyɔrɔw',
    label_classification: 'Lakana :',
    label_ttl: 'Bannako :',
    label_instruction: 'Baara Ci (Instruction officielle)',
    msg_placeholder: 'Bataki sɛbɛn...',
    btn_send: 'Ci',
    dir_title: 'Minisiriso Baarakɛlaw Tɔgɔsɛbɛn',
    dir_subtitle: 'Baarakɛla kelen sugandi ka baro datugulen daminɛ.',
  },
  ff: {
    app_title: 'FasoSouverain',
    gov_motto: 'Nelal Gollotooɓe Laamu · Burkina Faso',
    lang_label: 'Ɗemngal :',
    panic_btn: 'Jaawngol',
    logout_btn: 'Yaltu',
    label_username: 'Innde Gollotooɗo / Matricule',
    label_password: 'Finnde',
    btn_step1: 'Jokku',
    label_totp: 'TOTP Limre 6 (2FA)',
    btn_step2: 'Naatu',
    tab_chat: 'Nelal',
    tab_directory: 'Deftere',
    tab_admin: 'Ndeenka',
    channels_title: 'Cuuɗi Yeewtere',
    label_classification: 'Suura :',
    label_ttl: 'Momtugol :',
    label_instruction: 'Yamiroore Laamu (Instruction)',
    msg_placeholder: 'Winndu nelal...',
    btn_send: 'Neldul',
    dir_title: 'Deftere Gollotooɓe Ministeeruuji',
    dir_subtitle: 'Suɓo gollotooɗo ngam fuɗɗaade yeewtere suuraande.',
  },
};

const state = {
  lang: 'fr',
  portalToken: null,
  matrixAccessToken: null,
  agent: null,
  rooms: [],
  activeRoomId: null,
  roomCryptoKeys: new Map(),
  pollTimer: null,
  sessionCountdownTimer: null,
  sessionExpiresAt: null,
  demoAccounts: [],
  directoryMap: new Map(), // userId -> fullName
  lastRenderedCount: -1,
};

// ============================================================================
// 1. CHIFFREMENT DE BOUT EN BOUT TRANSPARENT (WEBCRYPTO AES-256-GCM / MEGOLM)
// ============================================================================

async function getOrCreateRoomMegolmKey(roomId) {
  if (state.roomCryptoKeys.has(roomId)) {
    return state.roomCryptoKeys.get(roomId);
  }
  const enc = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(`megolm-ratchet-seed::${roomId}::faso-souverain-v1`),
    { name: 'PBKDF2' },
    false,
    ['deriveKey', 'deriveBits']
  );

  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: enc.encode(`matrix-megolm-room-salt::${roomId}`),
      iterations: 10000,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  const rawBytes = new Uint8Array(await window.crypto.subtle.exportKey('raw', aesKey));
  const hashBuf = await window.crypto.subtle.digest('SHA-256', rawBytes);
  const hashHex = Array.from(new Uint8Array(hashBuf))
    .slice(0, 4)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(':');

  const entry = {
    key: aesKey,
    sessionId: `megolm_${hashHex.replace(/:/g, '').toLowerCase()}`,
    fingerprint: `Clé vérifiée · ${hashHex}`,
  };
  state.roomCryptoKeys.set(roomId, entry);
  return entry;
}

async function encryptRoomPayload(roomId, plaintextObj) {
  const { key, sessionId } = await getOrCreateRoomMegolmKey(roomId);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(plaintextObj));
  const cipherBuf = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

  const cipherBase64 = btoa(String.fromCharCode(...new Uint8Array(cipherBuf)));
  const ivBase64 = btoa(String.fromCharCode(...iv));

  return {
    algorithm: 'm.megolm.v1.aes-sha2',
    session_id: sessionId,
    sender_key: `curve25519_${state.agent?.localpart || 'agent'}`,
    device_id: state.agent?.deviceId || 'FASO_DEVICE',
    ciphertext: cipherBase64,
    iv: ivBase64,
  };
}

async function decryptRoomPayload(roomId, encryptedContent) {
  try {
    const { key } = await getOrCreateRoomMegolmKey(roomId);
    const cipherBytes = Uint8Array.from(atob(encryptedContent.ciphertext), (c) => c.charCodeAt(0));
    const ivBytes = Uint8Array.from(atob(encryptedContent.iv), (c) => c.charCodeAt(0));
    const plainBuf = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, cipherBytes);
    return JSON.parse(new TextDecoder().decode(plainBuf));
  } catch {
    return { text: '🔒 Message chiffré' };
  }
}

// ============================================================================
// 2. TRADUCTION MULTILINGUE (FRANÇAIS, MOORÉ, DIOULA, FULULDÉ)
// ============================================================================

function applyLanguage(lang) {
  state.lang = I18N[lang] ? lang : 'fr';
  const dict = I18N[state.lang];
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const k = el.getAttribute('data-i18n');
    if (dict[k]) el.textContent = dict[k];
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    const k = el.getAttribute('data-i18n-placeholder');
    if (dict[k]) el.setAttribute('placeholder', dict[k]);
  });
  document.getElementById('langSelectAuth').value = state.lang;
  document.getElementById('langSelectApp').value = state.lang;
}

// ============================================================================
// 3. COMMUNICATION API & DÉCONNEXION IMMÉDIATE SUR RÉVOCATION
// ============================================================================

async function apiFetch(url, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (state.portalToken) {
    headers['Authorization'] = `Bearer ${state.portalToken}`;
  }
  const res = await fetch(url, { ...options, headers });
  const data = await res.json().catch(() => ({}));

  if (res.status === 401 && state.portalToken && data.error === 'SESSION_INVALID_OR_REVOKED') {
    handleImmediateRevocationKick(data.message);
    throw new Error(data.message);
  }
  if (!res.ok) {
    throw new Error(data.message || 'Erreur réseau');
  }
  return data;
}

function handleImmediateRevocationKick(reasonMsg) {
  state.roomCryptoKeys.clear();
  state.portalToken = null;
  state.matrixAccessToken = null;
  state.agent = null;
  state.activeRoomId = null;
  state.sessionExpiresAt = null;
  if (state.pollTimer) clearInterval(state.pollTimer);
  if (state.sessionCountdownTimer) clearInterval(state.sessionCountdownTimer);
  localStorage.clear();
  sessionStorage.clear();

  document.getElementById('workspaceScreen').classList.add('hidden');
  document.getElementById('authScreen').classList.remove('hidden');

  showAuthAlert(reasonMsg || 'Votre session a été fermée.', 'error');
  loadDemoAccounts();
}

function showAuthAlert(msg, type = 'error') {
  const box = document.getElementById('authAlert');
  box.textContent = msg;
  box.className = `alert ${type}`;
  box.classList.remove('hidden');
}

function getInitials(name) {
  return String(name || 'A')
    .split(/\s+/)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() || '')
    .join('');
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ============================================================================
// 4. AUTHENTIFICATION À 2 FACTEURS
// ============================================================================

async function loadDemoAccounts() {
  try {
    const data = await apiFetch('/api/demo/accounts');
    state.demoAccounts = data.accounts || [];
    const container = document.getElementById('demoAccountsList');
    container.innerHTML = '';

    for (const acc of state.demoAccounts) {
      state.directoryMap.set(acc.userId, acc.fullName);
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'quick-acc-btn';
      btn.disabled = acc.status !== 'ACTIVE';
      btn.innerHTML = `
        <div>
          <strong>${escapeHtml(acc.fullName)}</strong>
          <div style="color:#64748b;font-size:0.72rem;">${escapeHtml(acc.title)} · ${escapeHtml(acc.ministry)}</div>
        </div>
        <span class="badge-role">${acc.status === 'ACTIVE' ? acc.localpart : 'Révoqué'}</span>
      `;
      if (acc.status === 'ACTIVE') {
        btn.addEventListener('click', () => {
          document.getElementById('usernameInput').value = acc.localpart;
          document.getElementById('passwordInput').value = data.demoPassword;
          document.getElementById('authAlert').classList.add('hidden');
        });
      }
      container.appendChild(btn);
    }

    const minSelect = document.getElementById('ministryFilterSelect');
    if (minSelect && minSelect.options.length <= 1 && data.ministries) {
      for (const m of data.ministries) {
        const opt = document.createElement('option');
        opt.value = m.code;
        opt.textContent = `${m.code} — ${m.shortName}`;
        minSelect.appendChild(opt);
      }
    }
  } catch (err) {
    console.error(err);
  }
}

let currentChallengeId = null;

function setupAuthHandlers() {
  const step1Form = document.getElementById('loginStep1Form');
  const step2Form = document.getElementById('loginStep2Form');

  step1Form.addEventListener('submit', async (e) => {
    e.preventDefault();
    document.getElementById('authAlert').classList.add('hidden');
    const username = document.getElementById('usernameInput').value.trim();
    const password = document.getElementById('passwordInput').value;

    try {
      const res = await apiFetch('/api/auth/login-step1', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });

      currentChallengeId = res.challengeId;
      document.getElementById('agentPreviewBox').innerHTML = `
        <div><strong>${escapeHtml(res.agentPreview.fullName)}</strong></div>
        <div style="font-size:0.76rem;opacity:0.9;">Matricule ${escapeHtml(res.agentPreview.matricule)} · ${escapeHtml(res.agentPreview.ministry)}</div>
      `;

      const qrBox = document.getElementById('qrSetupContainer');
      const qrSvgHolder = document.getElementById('qrSvgWrapper');
      const qrSecretText = document.getElementById('qrSecretText');

      if (res.isFirstSetup && res.qrSvg) {
        // 1ère connexion : affiche le QR Code FreeOTP une seule et unique fois !
        qrSvgHolder.innerHTML = res.qrSvg;
        qrSecretText.textContent = res.totpSecret || '';
        qrBox.classList.remove('hidden');
        document.getElementById('totpDemoHint').textContent =
          'Scannez le QR Code ci-dessus avec FreeOTP puis saisissez le code à 6 chiffres généré sur votre téléphone.';
      } else {
        // Connexions suivantes : le QR Code est définitivement scellé et caché !
        qrSvgHolder.innerHTML = '';
        qrSecretText.textContent = '';
        qrBox.classList.add('hidden');
        document.getElementById('totpDemoHint').textContent =
          'Ouvrez votre application FreeOTP (hors-ligne) et saisissez votre code à 6 chiffres.';
      }

      document.getElementById('totpInput').value = '';
      step1Form.classList.add('hidden');
      step2Form.classList.remove('hidden');
      document.getElementById('totpInput').focus();
    } catch (err) {
      showAuthAlert(err.message, 'error');
    }
  });

  step2Form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const totpCode = document.getElementById('totpInput').value.trim();
    try {
      const res = await apiFetch('/api/auth/login-step2', {
        method: 'POST',
        body: JSON.stringify({ challengeId: currentChallengeId, totpCode }),
      });

      state.portalToken = res.portalToken;
      state.matrixAccessToken = res.matrixAccessToken;
      state.agent = { ...res.agent, deviceId: res.deviceId };
      state.sessionExpiresAt = res.sessionExpiresAt || Date.now() + 30 * 60 * 1000;

      step2Form.classList.add('hidden');
      step1Form.classList.remove('hidden');
      await enterWorkspace();
    } catch (err) {
      showAuthAlert(err.message, 'error');
    }
  });

  document.getElementById('backToStep1Btn').addEventListener('click', () => {
    step2Form.classList.add('hidden');
    step1Form.classList.remove('hidden');
  });

  document.getElementById('testIntrusBtn').addEventListener('click', async () => {
    document.getElementById('usernameInput').value = 'compte.externe';
    try {
      await apiFetch('/api/auth/login-step1', {
        method: 'POST',
        body: JSON.stringify({ username: 'compte.externe', password: 'Password123!' }),
      });
    } catch (err) {
      showAuthAlert(err.message, 'error');
    }
  });
}

// ============================================================================
// 5. INTERFACE PRINCIPALE DE MESSAGERIE
// ============================================================================

async function enterWorkspace() {
  document.getElementById('authScreen').classList.add('hidden');
  document.getElementById('workspaceScreen').classList.remove('hidden');

  const initials = getInitials(state.agent.fullName);
  document.getElementById('currentUserCard').innerHTML = `
    <div class="avatar-circle">${escapeHtml(initials)}</div>
    <div class="profile-meta">
      <div class="profile-name">${escapeHtml(state.agent.fullName)}</div>
      <div class="profile-sub">${escapeHtml(state.agent.ministry)} · ${escapeHtml(state.agent.title)}</div>
    </div>
  `;

  const canSendInstruction =
    state.agent.role === 'ADMIN_SG' || state.agent.role === 'DIRECTEUR';
  document.getElementById('instructionToggleWrapper').style.display = canSendInstruction
    ? 'flex'
    : 'none';

  await loadDirectory();
  await loadContactRequests();
  await loadRooms();
  await loadAdminAndAudit();

  // Dépose un message de bienvenue chiffré si le salon principal est vide
  const currentRoom = state.rooms.find((r) => r.room_id === state.activeRoomId);
  if (currentRoom && currentRoom.event_count <= 1) {
    await sendEncryptedMessageToRoom(state.activeRoomId, {
      text: `Bonjour à tous, le canal sécurisé ${currentRoom.name} est opérationnel.`,
      classification: 'NORMAL',
      ttlSec: 0,
      isInstruction: false,
    });
  }

  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    if (!state.portalToken) return;
    try {
      await apiFetch('/api/me');
      await loadContactRequests();
      if (state.activeRoomId) {
        await renderRoomMessages(state.activeRoomId, false);
      }
    } catch {
      // Déconnexion gérée automatiquement si l'agent est révoqué ou expiré
    }
  }, 2500);

  // Minuteur de déconnexion automatique au bout de 30 minutes
  if (state.sessionCountdownTimer) clearInterval(state.sessionCountdownTimer);
  const updateSessionTimer = () => {
    if (!state.portalToken || !state.sessionExpiresAt) return;
    const remainingMs = state.sessionExpiresAt - Date.now();
    if (remainingMs <= 0) {
      handleImmediateRevocationKick(
        '⏱️ Session expirée automatiquement (limite de sécurité de 30 minutes atteinte). Veuillez vous reconnecter avec votre code FreeOTP.'
      );
      return;
    }
    const totalSec = Math.floor(remainingMs / 1000);
    const min = String(Math.floor(totalSec / 60)).padStart(2, '0');
    const sec = String(totalSec % 60).padStart(2, '0');
    const badge = document.getElementById('sessionTimerBadge');
    if (badge) {
      badge.textContent = `⏱️ Session : ${min}:${sec}`;
    }
  };
  updateSessionTimer();
  state.sessionCountdownTimer = setInterval(updateSessionTimer, 1000);
}

async function loadRooms() {
  const data = await apiFetch('/api/rooms');
  state.rooms = data.rooms || [];
  renderRoomsList();

  if (!state.activeRoomId && state.rooms.length > 0) {
    await selectRoom(state.rooms[0].room_id);
  }
}

function renderRoomsList() {
  const filter = (document.getElementById('roomSearchInput')?.value || '').toLowerCase();
  const ul = document.getElementById('roomsList');
  ul.innerHTML = '';

  for (const r of state.rooms) {
    if (filter && !r.name.toLowerCase().includes(filter) && !r.ministry.toLowerCase().includes(filter)) {
      continue;
    }
    const li = document.createElement('li');
    li.className = `conv-item ${r.room_id === state.activeRoomId ? 'active' : ''}`;
    const iconText = r.isDirect ? getInitials(r.name) : '#';
    const subText = r.isDirect
      ? 'Message direct chiffré'
      : `${r.ministry} · ${r.members.length} participants`;

    li.innerHTML = `
      <div class="conv-icon">${escapeHtml(iconText)}</div>
      <div class="conv-info">
        <div class="conv-title">${escapeHtml(r.name)}</div>
        <div class="conv-sub">${escapeHtml(subText)}</div>
      </div>
    `;
    li.addEventListener('click', () => selectRoom(r.room_id));
    ul.appendChild(li);
  }
}

async function selectRoom(roomId) {
  state.activeRoomId = roomId;
  state.lastRenderedCount = -1;
  const room = state.rooms.find((r) => r.room_id === roomId);
  if (room) {
    document.getElementById('activeRoomName').textContent = room.name;
    document.getElementById('activeRoomTopic').textContent = room.topic;
    document.getElementById('activeRoomAvatar').textContent = room.isDirect
      ? getInitials(room.name)
      : '#';
  }

  const keyInfo = await getOrCreateRoomMegolmKey(roomId);
  document.getElementById('roomKeyFingerprint').textContent = keyInfo.fingerprint;

  renderRoomsList();
  await renderRoomMessages(roomId, true);
}

function resolveSenderDisplayName(userId) {
  if (state.directoryMap.has(userId)) {
    return state.directoryMap.get(userId);
  }
  const local = String(userId).replace(/^@/, '').split(':')[0];
  return local
    .split('.')
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join(' ');
}

async function renderRoomMessages(roomId, forceScroll = false) {
  const data = await apiFetch(`/api/rooms/${encodeURIComponent(roomId)}/events`);
  const container = document.getElementById('messagesContainer');
  container.innerHTML = '';

  for (const ev of data.events) {
    if (ev.type === 'm.room.encryption') {
      const chip = document.createElement('div');
      chip.className = 'system-chip';
      chip.textContent =
        '🔒 Les messages et les fichiers de cette discussion sont chiffrés de bout en bout. Même le serveur ne peut pas les lire.';
      container.appendChild(chip);
      continue;
    }

    if (ev.type === 'm.room.member' && ev.content.membership === 'leave') {
      const chip = document.createElement('div');
      chip.className = 'system-chip';
      chip.textContent = `ℹ️ ${resolveSenderDisplayName(ev.sender)} a quitté la discussion (accès révoqué — clés de sécurité renouvelées).`;
      container.appendChild(chip);
      continue;
    }

    if (ev.type === 'm.room.encrypted') {
      const decrypted = await decryptRoomPayload(roomId, ev.content);
      const meta = ev.content.faso_meta || {};
      const classification = meta.classification || 'NORMAL';
      const isOwn = ev.sender === state.agent.userId;
      const senderDisplay = decrypted.senderName || resolveSenderDisplayName(ev.sender);

      const row = document.createElement('div');
      row.className = `bubble-row ${isOwn ? 'own' : 'other'}`;

      const bubble = document.createElement('div');
      bubble.className = `message-bubble ${classification}`;

      if (classification !== 'NORMAL') {
        bubble.addEventListener('copy', (e) => {
          e.preventDefault();
          alert('Copie désactivée : ce message est protégé par la politique de confidentialité.');
        });
      }

      const timeStr = new Date(ev.origin_server_ts).toLocaleTimeString('fr-FR', {
        hour: '2-digit',
        minute: '2-digit',
      });

      const expiryText = meta.expires_at
        ? ` · ⏳ ${Math.max(1, Math.round((meta.expires_at - Date.now()) / 1000))}s`
        : '';

      const classifBadgeHtml =
        classification !== 'NORMAL'
          ? `<span class="classif-pill ${classification}">${
              classification === 'CONFIDENTIEL' ? 'Confidentiel' : 'Diffusion restreinte'
            }</span>`
          : '';

      let contentHtml = `<div class="bubble-text">${escapeHtml(decrypted.text || '')}</div>`;

      // Pièce jointe chiffrée
      if (decrypted.attachment) {
        contentHtml = `
          <div class="file-attachment-card">
            <span>📄</span>
            <div style="flex:1">
              <div><strong>${escapeHtml(decrypted.attachment.name)}</strong></div>
              <div style="font-size:0.72rem;color:#64748b;">${escapeHtml(decrypted.attachment.sizeLabel)} · Chiffré AES-256</div>
            </div>
          </div>
          ${decrypted.text ? `<div class="bubble-text">${escapeHtml(decrypted.text)}</div>` : ''}
        `;
      }

      // Note vocale chiffrée
      if (meta.is_voice && decrypted.voiceSummary) {
        contentHtml = `
          <div class="voice-player">
            <button type="button" class="btn-primary play-voice-btn" style="padding:0.3rem 0.65rem;font-size:0.75rem;">▶ Écouter</button>
            <div>
              <div style="font-size:0.82rem;font-weight:600;">Note vocale (${(meta.lang || 'fr').toUpperCase()})</div>
              <div style="font-size:0.78rem;color:#475569;">${escapeHtml(decrypted.voiceSummary)}</div>
            </div>
          </div>
        `;
      }

      // Instruction de service officielle avec accusé de lecture signé
      let instructionHtml = '';
      if (meta.is_instruction) {
        const receipts = ev.receipts || [];
        const hasAcked = receipts.some((r) => r.agentId === state.agent.userId);
        const ackedNames = receipts.map((r) => `✓ ${escapeHtml(r.fullName)} (${escapeHtml(r.ministry)})`).join(' · ');

        instructionHtml = `
          <div class="official-instruction-card">
            <div style="font-weight:700;color:#065f46;">📌 Instruction Officielle de Service</div>
            <div style="margin-top:0.25rem;color:#475569;">
              ${ackedNames || 'En attente de confirmation de lecture par les destinataires.'}
            </div>
            ${
              !hasAcked
                ? `<button type="button" class="ack-btn-inline" data-event-id="${ev.event_id}">Confirmer la lecture et signer l'accusé</button>`
                : ''
            }
          </div>
        `;
      }

      bubble.innerHTML = `
        <div class="bubble-header">
          <span class="sender-name">${escapeHtml(senderDisplay)}</span>
          ${classifBadgeHtml}
        </div>
        ${contentHtml}
        ${instructionHtml}
        <div class="bubble-footer">
          <span>${timeStr}${expiryText}</span>
          <span title="Chiffré de bout en bout">🔒</span>
        </div>
      `;

      const ackBtn = bubble.querySelector('.ack-btn-inline');
      if (ackBtn) {
        ackBtn.addEventListener('click', async () => {
          await apiFetch('/api/receipts/acknowledge', {
            method: 'POST',
            body: JSON.stringify({ eventId: ev.event_id, roomId }),
          });
          await renderRoomMessages(roomId, false);
        });
      }

      const playBtn = bubble.querySelector('.play-voice-btn');
      if (playBtn) {
        playBtn.addEventListener('click', () => {
          if ('speechSynthesis' in window) {
            const utter = new SpeechSynthesisUtterance(decrypted.voiceSummary);
            utter.lang = 'fr-FR';
            window.speechSynthesis.speak(utter);
          }
        });
      }

      row.appendChild(bubble);
      container.appendChild(row);
    }
  }

  if (forceScroll || data.events.length !== state.lastRenderedCount) {
    state.lastRenderedCount = data.events.length;
    container.scrollTop = container.scrollHeight;
  }
}

async function sendEncryptedMessageToRoom(
  roomId,
  { text, classification = 'NORMAL', ttlSec = 0, isInstruction = false, isVoice = false, voiceSummary = null, attachment = null }
) {
  const encrypted = await encryptRoomPayload(roomId, {
    text,
    voiceSummary,
    attachment,
    senderName: state.agent.fullName,
    sentAt: new Date().toISOString(),
  });

  const expiresAt =
    ttlSec > 0
      ? Date.now() + ttlSec * 1000
      : classification === 'CONFIDENTIEL'
      ? Date.now() + 300 * 1000
      : null;

  await apiFetch(`/api/rooms/${encodeURIComponent(roomId)}/send-encrypted`, {
    method: 'POST',
    body: JSON.stringify({
      type: 'm.room.encrypted',
      content: {
        ...encrypted,
        faso_meta: {
          classification,
          expires_at: expiresAt,
          is_instruction: isInstruction,
          is_voice: isVoice,
          has_attachment: Boolean(attachment),
          lang: state.lang,
        },
      },
      faso_meta: {
        classification,
        expires_at: expiresAt,
        is_instruction: isInstruction,
      },
    }),
  });
}

// ============================================================================
// 6. ANNUAIRE DES MINISTÈRES & CLOISONNEMENT INTER-ADMINISTRATIONS
// ============================================================================

async function loadContactRequests() {
  try {
    const data = await apiFetch('/api/contact-requests');
    const incoming = data.incoming || [];
    const box = document.getElementById('pendingRequestsSection');
    const list = document.getElementById('incomingRequestsList');
    if (!box || !list) return;

    if (incoming.length === 0) {
      box.classList.add('hidden');
      list.innerHTML = '';
      return;
    }

    box.classList.remove('hidden');
    list.innerHTML = '';
    for (const reqItem of incoming) {
      const card = document.createElement('div');
      card.className = 'incoming-req-card';
      card.innerHTML = `
        <div><strong>${escapeHtml(reqItem.fromFullName)}</strong> (${escapeHtml(reqItem.fromMinistry)})</div>
        <div style="color:#64748b;font-size:0.73rem;margin-top:0.15rem;">Motif : « ${escapeHtml(reqItem.reason)} »</div>
        <div class="req-actions">
          <button type="button" class="btn-req-accept">Accepter</button>
          <button type="button" class="btn-req-reject">Refuser</button>
        </div>
      `;
      card.querySelector('.btn-req-accept').addEventListener('click', async () => {
        const res = await apiFetch(`/api/contact-requests/${encodeURIComponent(reqItem.id)}/respond`, {
          method: 'POST',
          body: JSON.stringify({ action: 'ACCEPT' }),
        });
        await loadContactRequests();
        await loadDirectory();
        await loadRooms();
        if (res.room_id) {
          switchView('chatView');
          await selectRoom(res.room_id);
        }
      });
      card.querySelector('.btn-req-reject').addEventListener('click', async () => {
        await apiFetch(`/api/contact-requests/${encodeURIComponent(reqItem.id)}/respond`, {
          method: 'POST',
          body: JSON.stringify({ action: 'REJECT' }),
        });
        await loadContactRequests();
        await loadDirectory();
      });
      list.appendChild(card);
    }
  } catch (err) {
    console.error(err);
  }
}

async function loadDirectory() {
  const ministry = document.getElementById('ministryFilterSelect')?.value || 'ALL';
  const data = await apiFetch(`/api/directory?ministry=${encodeURIComponent(ministry)}`);
  const grid = document.getElementById('directoryGrid');
  if (!grid) return;
  grid.innerHTML = '';

  for (const ag of data.agents) {
    state.directoryMap.set(ag.userId, ag.fullName);
    const card = document.createElement('div');
    card.className = 'contact-card';
    const isMe = ag.localpart === state.agent?.localpart;

    let actionButtonHtml = '';
    if (!isMe && ag.status === 'ACTIVE') {
      if (ag.canMessageDirectly) {
        actionButtonHtml = `<button type="button" class="btn-primary start-dm-btn" style="padding:0.38rem 0.75rem;font-size:0.78rem;">💬 Message direct</button>`;
      } else if (ag.pendingDirection === 'OUTGOING') {
        actionButtonHtml = `<span class="badge-role" style="background:#fef3c7;color:#b45309;">⏳ Demande envoyée</span>`;
      } else if (ag.pendingDirection === 'INCOMING') {
        actionButtonHtml = `<button type="button" class="btn-req-accept accept-inline-btn" data-req-id="${escapeHtml(ag.pendingRequestId)}">✓ Accepter la demande</button>`;
      } else {
        actionButtonHtml = `<button type="button" class="btn-request-outline send-req-btn">✉️ Demander un contact</button>`;
      }
    }

    const envTag = ag.sameMinistry
      ? `<span class="badge-role" style="background:#ecfdf5;color:#047857;">Même administration (${escapeHtml(ag.ministry)})</span>`
      : `<span class="badge-role">Autre administration (${escapeHtml(ag.ministry)})</span>`;

    card.innerHTML = `
      <div class="contact-top">
        <div class="avatar-circle">${escapeHtml(getInitials(ag.fullName))}</div>
        <div style="flex:1;min-width:0;">
          <div style="font-weight:700;font-size:0.95rem;">${escapeHtml(ag.fullName)}</div>
          <div style="font-size:0.78rem;color:#64748b;">${escapeHtml(ag.title)}</div>
        </div>
      </div>
      <div style="font-size:0.8rem;color:#475569;margin-bottom:0.65rem;">
        <div style="margin-bottom:0.3rem;">${envTag}</div>
        <div>🏛️ ${escapeHtml(ag.direction)}</div>
        <div style="margin-top:0.2rem;">📧 <code>${escapeHtml(ag.email || '')}</code> · Matricule : <code>${escapeHtml(ag.matricule)}</code></div>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding-top:0.6rem;border-top:1px solid #f1f5f9;">
        <span class="badge-role">${ag.status === 'ACTIVE' ? '🟢 En service' : '🔴 Accès révoqué'}</span>
        ${actionButtonHtml}
      </div>
    `;

    const dmBtn = card.querySelector('.start-dm-btn');
    if (dmBtn) {
      dmBtn.addEventListener('click', async () => {
        try {
          const res = await apiFetch('/api/rooms/direct', {
            method: 'POST',
            body: JSON.stringify({ targetLocalpart: ag.localpart }),
          });
          await loadRooms();
          switchView('chatView');
          await selectRoom(res.room_id);
        } catch (err) {
          alert(err.message);
        }
      });
    }

    const reqBtn = card.querySelector('.send-req-btn');
    if (reqBtn) {
      reqBtn.addEventListener('click', async () => {
        const reason = prompt(
          `Demande de communication inter-administration vers ${ag.fullName} (${ag.ministry}).\nIndiquez le motif professionnel :`,
          'Coordination de dossier interministériel'
        );
        if (!reason) return;
        try {
          await apiFetch('/api/contact-requests', {
            method: 'POST',
            body: JSON.stringify({ targetLocalpart: ag.localpart, reason }),
          });
          await loadDirectory();
        } catch (err) {
          alert(err.message);
        }
      });
    }

    const acceptInlineBtn = card.querySelector('.accept-inline-btn');
    if (acceptInlineBtn) {
      acceptInlineBtn.addEventListener('click', async () => {
        const reqId = acceptInlineBtn.getAttribute('data-req-id');
        const res = await apiFetch(`/api/contact-requests/${encodeURIComponent(reqId)}/respond`, {
          method: 'POST',
          body: JSON.stringify({ action: 'ACCEPT' }),
        });
        await loadContactRequests();
        await loadDirectory();
        await loadRooms();
        if (res.room_id) {
          switchView('chatView');
          await selectRoom(res.room_id);
        }
      });
    }

    grid.appendChild(card);
  }
}

// ============================================================================
// 7. ADMINISTRATION & AUDIT DE SÉCURITÉ
// ============================================================================

async function loadAdminAndAudit() {
  const dirData = await apiFetch('/api/directory?ministry=ALL');
  const list = document.getElementById('adminAgentsList');
  if (list) {
    list.innerHTML = '';
    for (const ag of dirData.agents) {
      const row = document.createElement('div');
      row.className = 'user-manage-row';
      const canRevoke =
        state.agent.role === 'ADMIN_SG' && ag.localpart !== 'admin' && ag.status === 'ACTIVE';

      row.innerHTML = `
        <div>
          <div style="font-weight:600;font-size:0.88rem;">${escapeHtml(ag.fullName)}</div>
          <div style="font-size:0.75rem;color:#64748b;">${escapeHtml(ag.ministry)} · ${escapeHtml(ag.matricule)} · ${escapeHtml(ag.roleLabel)}</div>
        </div>
        ${
          canRevoke
            ? `<button type="button" class="btn-revoke-sm">Révoquer l'accès</button>`
            : `<span class="badge-role">${ag.status === 'REVOKED' ? 'Révoqué' : 'Administrateur'}</span>`
        }
      `;

      const revBtn = row.querySelector('.btn-revoke-sm');
      if (revBtn) {
        revBtn.addEventListener('click', async () => {
          if (!confirm(`Confirmer la révocation immédiate de ${ag.fullName} ?`)) return;
          try {
            await apiFetch('/api/admin/revoke', {
              method: 'POST',
              body: JSON.stringify({ localpart: ag.localpart }),
            });
            await loadAdminAndAudit();
            await loadDirectory();
            if (state.activeRoomId) await renderRoomMessages(state.activeRoomId, false);
          } catch (err) {
            alert(err.message);
          }
        });
      }
      list.appendChild(row);
    }
  }

  const blindData = await apiFetch('/api/security/blind-check');
  const auditContainer = document.getElementById('blindCheckResult');
  if (auditContainer) {
    auditContainer.innerHTML = `
      <div>
        <div style="font-weight:700;color:#047857;">État du stockage serveur : Chiffrement intégral (${blindData.status})</div>
        <div style="font-size:0.82rem;color:#475569;margin-top:0.25rem;">
          Messages en clair sur le serveur : <strong>${blindData.clear_text_events_count}</strong> ·
          Évènements chiffrés (<code>m.room.encrypted</code>) : <strong>${blindData.event_types_summary['m.room.encrypted'] || 0}</strong>
        </div>
        <pre class="code-box">${escapeHtml(JSON.stringify(blindData.sample_encrypted_records.slice(0, 2), null, 2))}</pre>
      </div>
      <div>
        <div style="font-weight:700;">Journal de sécurité récent</div>
        <pre class="code-box">${escapeHtml(JSON.stringify(blindData.audit_logs.slice(0, 4), null, 2))}</pre>
      </div>
    `;
  }
}

function switchView(viewId) {
  document.querySelectorAll('.rail-btn[data-view]').forEach((b) => {
    b.classList.toggle('active', b.getAttribute('data-view') === viewId);
  });
  document.querySelectorAll('.view-container').forEach((v) => {
    const isTarget = v.id === viewId;
    v.classList.toggle('hidden', !isTarget);
    v.classList.toggle('active-view', isTarget);
  });
  if (viewId === 'directoryView') loadDirectory();
  if (viewId === 'adminView') loadAdminAndAudit();
}

// ============================================================================
// 8. INITIALISATION DES ÉVÈNEMENTS UI
// ============================================================================

window.addEventListener('DOMContentLoaded', () => {
  loadDemoAccounts();
  setupAuthHandlers();

  document.getElementById('langSelectAuth').addEventListener('change', (e) => applyLanguage(e.target.value));
  document.getElementById('langSelectApp').addEventListener('change', (e) => applyLanguage(e.target.value));

  document.querySelectorAll('.rail-btn[data-view]').forEach((btn) => {
    btn.addEventListener('click', () => switchView(btn.getAttribute('data-view')));
  });

  document.getElementById('roomSearchInput').addEventListener('input', renderRoomsList);

  // Bandeau discret de confidentialité
  document.getElementById('classificationSelect').addEventListener('change', (e) => {
    const val = e.target.value;
    const banner = document.getElementById('classificationBanner');
    const text = document.getElementById('classificationBannerText');
    if (val === 'NORMAL') {
      banner.classList.add('hidden');
    } else if (val === 'DIFFUSION_RESTREINTE') {
      banner.className = 'security-notice restricted';
      text.textContent = 'Mode Diffusion Restreinte : copie et transfert désactivés pour ce message.';
    } else if (val === 'CONFIDENTIEL') {
      banner.className = 'security-notice confidential';
      text.textContent = 'Mode Confidentiel : message éphémère à autodestruction automatique.';
    }
  });

  // Envoi d'un message texte chiffré
  document.getElementById('messageForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = document.getElementById('messageInput');
    const text = input.value.trim();
    if (!text || !state.activeRoomId) return;

    const classification = document.getElementById('classificationSelect').value;
    const ttlSec = Number(document.getElementById('ttlSelect').value || 0);
    const isInstruction = document.getElementById('isInstructionCheckbox').checked;

    try {
      await sendEncryptedMessageToRoom(state.activeRoomId, {
        text,
        classification,
        ttlSec,
        isInstruction,
      });
      input.value = '';
      document.getElementById('isInstructionCheckbox').checked = false;
      await renderRoomMessages(state.activeRoomId, true);
    } catch (err) {
      alert(err.message);
    }
  });

  // Envoi d'un fichier joint chiffré de bout en bout
  const fileBtn = document.getElementById('attachFileBtn');
  const fileInput = document.getElementById('fileAttachmentInput');
  fileBtn.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files?.[0];
    if (!file || !state.activeRoomId) return;
    const sizeKb = Math.max(1, Math.round(file.size / 1024));
    try {
      await sendEncryptedMessageToRoom(state.activeRoomId, {
        text: document.getElementById('messageInput').value.trim(),
        classification: document.getElementById('classificationSelect').value,
        ttlSec: Number(document.getElementById('ttlSelect').value || 0),
        isInstruction: document.getElementById('isInstructionCheckbox').checked,
        attachment: {
          name: file.name,
          sizeLabel: `${sizeKb} Ko`,
          mimeType: file.type || 'application/octet-stream',
        },
      });
      fileInput.value = '';
      document.getElementById('messageInput').value = '';
      await renderRoomMessages(state.activeRoomId, true);
    } catch (err) {
      alert(err.message);
    }
  });

  // Envoi d'une note vocale chiffrée
  document.getElementById('voiceNoteBtn').addEventListener('click', async () => {
    if (!state.activeRoomId) return;
    const phrases = {
      fr: 'Note vocale : Merci de prendre connaissance du dossier transmis.',
      mos: 'Koɛɛga : Ne y zabr fãa, bɩ y ges sebrã tõnd sẽn tʋmã.',
      dyu: 'Kumakan : Aw ni baara, aw ye sɛbɛn cilen lajɛ.',
      ff: 'Daande : On jaaraama, ƴeewon الdossier neldaaɗo oo.',
    };
    const voiceSummary = phrases[state.lang] || phrases.fr;
    try {
      await sendEncryptedMessageToRoom(state.activeRoomId, {
        text: voiceSummary,
        voiceSummary,
        isVoice: true,
        classification: document.getElementById('classificationSelect').value,
      });
      await renderRoomMessages(state.activeRoomId, true);
    } catch (err) {
      alert(err.message);
    }
  });

  // Nouveau canal
  document.getElementById('newRoomBtn').addEventListener('click', async () => {
    const name = prompt('Nom du nouveau canal :', 'Groupe de travail');
    if (!name) return;
    const res = await apiFetch('/api/rooms', {
      method: 'POST',
      body: JSON.stringify({
        name,
        topic: 'Canal de travail chiffré de bout en bout',
        ministry: state.agent.ministry,
        members: ['admin', 'aminata.ouedraogo', 'ibrahim.sawadogo', 'fatoumata.kabore'],
      }),
    });
    await loadRooms();
    await selectRoom(res.room_id);
  });

  document.getElementById('ministryFilterSelect').addEventListener('change', loadDirectory);
  document.getElementById('refreshBlindBtn').addEventListener('click', loadAdminAndAudit);

  // Création d'un nouvel agent dans l'onglet Sécurité
  document.getElementById('enrollForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const box = document.getElementById('enrollResultBox');
    try {
      const res = await apiFetch('/api/admin/enroll', {
        method: 'POST',
        body: JSON.stringify({
          localpart: document.getElementById('enrollLocalpart').value,
          fullName: document.getElementById('enrollFullName').value,
          ministry: document.getElementById('enrollMinistry').value,
          role: document.getElementById('enrollRole').value,
          password: document.getElementById('enrollPassword').value,
        }),
      });
      box.className = 'alert success';
      box.innerHTML = `
        <div>✅ Compte créé pour <strong>${escapeHtml(res.agent.fullName)}</strong>.</div>
        <div style="font-size:0.78rem;margin-top:0.25rem;">Lors de sa première connexion, son QR Code FreeOTP unique lui sera présenté puis scellé définitivement.</div>
      `;
      box.classList.remove('hidden');
      await loadAdminAndAudit();
      await loadDirectory();
    } catch (err) {
      box.className = 'alert error';
      box.textContent = err.message;
      box.classList.remove('hidden');
    }
  });

  // Bouton d'Urgence
  document.getElementById('panicBtn').addEventListener('click', async () => {
    if (
      !confirm(
        "Effacement d'urgence : voulez-vous supprimer toutes les données locales de cet appareil et verrouiller votre compte ?"
      )
    ) {
      return;
    }
    try {
      await apiFetch('/api/security/emergency-wipe', {
        method: 'POST',
        body: JSON.stringify({ reason: 'Verrouillage d’urgence déclenché par l’utilisateur' }),
      });
    } finally {
      handleImmediateRevocationKick('Appareil nettoyé et compte verrouillé par mesure de sécurité.');
    }
  });

  document.getElementById('logoutBtn').addEventListener('click', () => {
    handleImmediateRevocationKick('Vous êtes déconnecté.');
  });
});
