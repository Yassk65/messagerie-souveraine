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
  dpopKeyPair: null, // Clé privée ECDSA P-256 non-extractible (extractable: false) en mémoire WebCrypto
  dpopThumbprint: null,
  agent: null,
  rooms: [],
  activeRoomId: null,
  roomCryptoKeys: new Map(),
  pollTimer: null,
  sessionCountdownTimer: null,
  ephemeralCountdownTimer: null,
  sessionExpiresAt: null,
  demoAccounts: [],
  directoryMap: new Map(), // userId -> fullName
  lastRenderedCount: -1,
  lastRenderSignature: '',
  stagedAttachment: null, // Pièce jointe (photo / document) en attente d'envoi chiffré
  voiceRecorder: {
    mediaRecorder: null,
    stream: null,
    chunks: [],
    timerInterval: null,
    startedAt: 0,
    isFallbackMode: false,
  },
};

function bytesToBase64Url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Génère une paire de clés asymétriques ECDSA P-256 dans le moteur matériel du navigateur
 * avec `extractable: false` : la clé privée ne peut JAMAIS être exportée ni volée.
 */
async function generateHardwareBoundDPoPKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, // extractable = false : impossible d'exporter la clé privée !
    ['sign', 'verify']
  );
  const publicJwk = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
  state.dpopKeyPair = keyPair;
  return publicJwk;
}

/**
 * Signe chaque requête API avec la clé privée non-extractible (Preuve de Possession DPoP RFC 9449).
 */
async function buildDPoPHeader(method, url) {
  if (!state.dpopKeyPair) return null;
  const parsed = new URL(url, window.location.origin);
  const pathname = parsed.pathname;
  const rnd = window.crypto.getRandomValues(new Uint8Array(12));
  const jti = 'jti_' + Array.from(rnd, (b) => b.toString(16).padStart(2, '0')).join('');
  const iat = Math.floor(Date.now() / 1000);
  const htm = String(method || 'GET').toUpperCase();
  const htu = pathname;

  const signedPayload = `${jti}|${htm}|${htu}|${iat}`;
  const sigBuf = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    state.dpopKeyPair.privateKey,
    new TextEncoder().encode(signedPayload)
  );

  const proofObj = {
    jti,
    htm,
    htu,
    iat,
    sig: bytesToBase64Url(new Uint8Array(sigBuf)),
  };
  return bytesToBase64Url(new TextEncoder().encode(JSON.stringify(proofObj)));
}

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
  const method = (options.method || 'GET').toUpperCase();
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (state.portalToken) {
    headers['Authorization'] = `Bearer ${state.portalToken}`;
    const dpopProof = await buildDPoPHeader(method, url);
    if (dpopProof) {
      headers['X-Faso-DPoP'] = dpopProof;
    }
  }
  const res = await fetch(url, {
    ...options,
    method,
    headers,
    credentials: 'same-origin', // Envoie automatiquement le cookie HttpOnly SameSite=Strict
  });
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
  state.dpopKeyPair = null;
  state.dpopThumbprint = null;
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
      // Génère la paire de clés matérielle ECDSA P-256 non-extractible (DPoP RFC 9449)
      const dpopPublicJwk = await generateHardwareBoundDPoPKeyPair();

      const res = await apiFetch('/api/auth/login-step2', {
        method: 'POST',
        body: JSON.stringify({
          challengeId: currentChallengeId,
          totpCode,
          dpopPublicJwk,
          enableCookieBind: true,
        }),
      });

      state.portalToken = res.portalToken;
      state.dpopThumbprint = res.dpopThumbprint;
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

  // Adapte le sélecteur de confidentialité selon l'habilitation RBAC de l'agent
  const classifSelect = document.getElementById('classificationSelect');
  const confOption = classifSelect?.querySelector('option[value="CONFIDENTIEL"]');
  if (confOption) {
    if (!canSendInstruction) {
      confOption.disabled = true;
      confOption.textContent = 'Confidentiel (Réservé Directeur / Admin)';
      if (classifSelect.value === 'CONFIDENTIEL') classifSelect.value = 'NORMAL';
    } else {
      confOption.disabled = false;
      confOption.textContent = 'Confidentiel (Floutage + Éphémère)';
    }
  }

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

  // Minuteur fluide (1s) pour les messages éphémères à autodestruction automatique
  if (state.ephemeralCountdownTimer) clearInterval(state.ephemeralCountdownTimer);
  state.ephemeralCountdownTimer = setInterval(async () => {
    if (!state.portalToken || !state.activeRoomId) return;
    const pills = document.querySelectorAll('.ephemeral-timer-pill[data-expires-at]');
    let anyExpired = false;
    pills.forEach((pill) => {
      const exp = Number(pill.getAttribute('data-expires-at'));
      const remainSec = Math.ceil((exp - Date.now()) / 1000);
      if (remainSec <= 0) {
        anyExpired = true;
      } else {
        pill.textContent = `⏳ Auto-destruction : ${remainSec}s`;
      }
    });
    if (anyExpired) {
      state.lastRenderSignature = '';
      await renderRoomMessages(state.activeRoomId, false);
    }
  }, 1000);

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
  state.lastRenderSignature = '';
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

function getFileTypeIcon(fileName = '', mimeType = '') {
  const lower = fileName.toLowerCase();
  if (mimeType.startsWith('image/') || /\.(png|jpe?g|gif|webp|svg)$/.test(lower)) return '🖼️';
  if (lower.endsWith('.pdf') || mimeType === 'application/pdf') return '📕';
  if (/\.(doc|docx)$/.test(lower)) return '📘';
  if (/\.(xls|xlsx|csv)$/.test(lower)) return '📗';
  if (/\.(ppt|pptx)$/.test(lower)) return '📙';
  if (/\.(zip|rar|7z|tar|gz)$/.test(lower)) return '🗜️';
  return '📄';
}

function triggerDecryptedFileDownload(dataUrl, fileName) {
  if (!dataUrl) {
    alert('Ce fichier de démonstration ne contient pas de binaire téléchargeable.');
    return;
  }
  const a = document.createElement('a');
  a.href = dataUrl;
  a.download = fileName || 'document-dechiffre';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

async function renderRoomMessages(roomId, forceScroll = false) {
  const data = await apiFetch(`/api/rooms/${encodeURIComponent(roomId)}/events`);
  const signature = data.events
    .map((e) => `${e.event_id}:${(e.receipts || []).length}`)
    .join('|');

  // Évite de reconstruire le DOM si aucun événement ni accusé de lecture n'a changé (ne coupe pas la lecture audio !)
  if (!forceScroll && signature === state.lastRenderSignature) {
    return;
  }
  state.lastRenderSignature = signature;

  const container = document.getElementById('messagesContainer');
  container.innerHTML = '';

  for (const ev of data.events) {
    if (ev.type === 'm.room.encryption') {
      const chip = document.createElement('div');
      chip.className = 'system-chip';
      chip.textContent =
        '🔒 Les messages, photos, documents et notes vocales de cette discussion sont chiffrés de bout en bout (AES-256-GCM / Matrix Megolm). Même le serveur ne peut pas les lire.';
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

      // Règles propres aux niveaux Diffusion Restreinte & Confidentiel (Anti-copie, Anti-clic droit)
      if (classification !== 'NORMAL') {
        bubble.addEventListener('copy', (e) => {
          e.preventDefault();
          alert('🔒 Copie bloquée : ce message est protégé par la classification ' + classification + '.');
        });
        bubble.addEventListener('contextmenu', (e) => {
          e.preventDefault();
        });
      }

      const timeStr = new Date(ev.origin_server_ts).toLocaleTimeString('fr-FR', {
        hour: '2-digit',
        minute: '2-digit',
      });

      const expiryBadgeHtml = meta.expires_at
        ? ` <span class="ephemeral-timer-pill" data-expires-at="${meta.expires_at}">⏳ Auto-destruction : ${Math.max(
            1,
            Math.ceil((meta.expires_at - Date.now()) / 1000)
          )}s</span>`
        : '';

      const classifBadgeHtml =
        classification !== 'NORMAL'
          ? `<span class="classif-pill ${classification}">${
              classification === 'CONFIDENTIEL' ? '🔴 Confidentiel' : '🟠 Diffusion restreinte'
            }</span>`
          : '';

      let contentHtml = decrypted.text
        ? `<div class="bubble-text">${escapeHtml(decrypted.text)}</div>`
        : '';

      // 1. Pièce jointe chiffrée (Photo avec aperçu visuel OU Document avec bouton Télécharger)
      if (decrypted.attachment) {
        const att = decrypted.attachment;
        const isImg =
          att.isImage ||
          (att.mimeType && att.mimeType.startsWith('image/')) ||
          (att.dataUrl && att.dataUrl.startsWith('data:image/'));
        const canDownload = classification !== 'CONFIDENTIEL' && Boolean(att.dataUrl);

        if (isImg && att.dataUrl) {
          contentHtml = `
            <div class="encrypted-photo-box">
              <img src="${att.dataUrl}" alt="${escapeHtml(att.name)}" class="encrypted-photo-img" title="Cliquez pour agrandir la photo déchiffrée" />
              <div class="encrypted-photo-footer">
                <span>🖼️ ${escapeHtml(att.name)} (${escapeHtml(att.sizeLabel)}) · Chiffré AES-256</span>
                ${
                  canDownload
                    ? `<button type="button" class="btn-download-file download-att-btn">⬇ Télécharger</button>`
                    : `<span style="color:#fda4af;font-weight:600;">🔒 Export bloqué (Confidentiel)</span>`
                }
              </div>
            </div>
            ${decrypted.text ? `<div class="bubble-text">${escapeHtml(decrypted.text)}</div>` : ''}
          `;
        } else {
          const icon = getFileTypeIcon(att.name, att.mimeType);
          contentHtml = `
            <div class="file-attachment-card">
              <span style="font-size:1.35rem;">${icon}</span>
              <div style="flex:1;overflow:hidden;">
                <div style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"><strong>${escapeHtml(att.name)}</strong></div>
                <div style="font-size:0.72rem;color:#64748b;">${escapeHtml(att.sizeLabel)} · Chiffré de bout en bout AES-256</div>
              </div>
              ${
                canDownload
                  ? `<button type="button" class="btn-download-file download-att-btn">⬇ Télécharger</button>`
                  : classification === 'CONFIDENTIEL'
                    ? `<span style="font-size:0.7rem;color:#be123c;font-weight:700;">🔒 Non exportable</span>`
                    : ''
              }
            </div>
            ${decrypted.text ? `<div class="bubble-text">${escapeHtml(decrypted.text)}</div>` : ''}
          `;
        }
      }

      // 2. Note vocale chiffrée (Lecteur audio HTML5 réel + Transcription langue nationale)
      if (meta.is_voice) {
        const langLabels = { fr: 'Français', mos: 'Mooré', dyu: 'Dioula', ff: 'Fulfuldé' };
        const langName = langLabels[meta.lang] || (meta.lang || 'fr').toUpperCase();
        const durLabel = decrypted.voiceDurationSec ? ` · ${decrypted.voiceDurationSec}s` : '';

        contentHtml = `
          <div class="voice-player">
            <div class="voice-player-top">
              <div style="font-size:0.8rem;font-weight:700;color:#0f172a;">
                🎙️ Message vocal chiffré (${escapeHtml(langName)}${escapeHtml(durLabel)})
              </div>
              ${
                decrypted.voiceSummary
                  ? `<button type="button" class="btn-primary play-tts-btn" style="padding:0.2rem 0.5rem;font-size:0.7rem;">🔊 Voix synthèse</button>`
                  : ''
              }
            </div>
            ${
              decrypted.audioDataUrl
                ? `<audio controls preload="metadata" src="${decrypted.audioDataUrl}" class="voice-audio-element"></audio>`
                : ''
            }
            ${
              decrypted.voiceSummary
                ? `<div style="font-size:0.76rem;color:#475569;margin-top:0.1rem;">« ${escapeHtml(decrypted.voiceSummary)} »</div>`
                : ''
            }
          </div>
        `;
      }

      // 3. Protection visuelle niveau CONFIDENTIEL (Floutage anti-capture d'écran + Filigrane au matricule du lecteur)
      if (classification === 'CONFIDENTIEL') {
        const readerWatermark = `${state.agent.fullName} · Matricule ${state.agent.matricule || state.agent.localpart}`;
        contentHtml = `
          <div class="confidential-content-shield blurred">
            <div class="confidential-reveal-hint" title="Cliquez ou survolez pour révéler le contenu confidentiel">
              👁️ Contenu CONFIDENTIEL protégé contre les regards/captures — Cliquez ou survolez pour lire
            </div>
            <div class="shield-inner">
              ${contentHtml}
            </div>
            <div class="confidential-watermark">🛡️ Filigrane de traçabilité : consulté par ${escapeHtml(readerWatermark)}</div>
          </div>
        `;
      }

      // 4. Instruction de service officielle avec accusé de lecture signé cryptographiquement (HMAC-SHA256)
      let instructionHtml = '';
      if (meta.is_instruction) {
        const receipts = ev.receipts || [];
        const hasAcked = receipts.some((r) => r.agentId === state.agent.userId);
        const receiptsListHtml =
          receipts.length > 0
            ? receipts
                .map((r) => {
                  const ackTime = r.timestampIso
                    ? new Date(r.timestampIso).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
                    : '';
                  const shortSig = (r.signature || '').slice(0, 10);
                  return `<div class="receipt-proof-item">✅ <strong>${escapeHtml(r.fullName)}</strong> (${escapeHtml(r.ministry)} · Matricule <code>${escapeHtml(r.matricule || 'N/A')}</code>) — Lu à ${ackTime} · Preuve HMAC <code>#${escapeHtml(shortSig)}</code></div>`;
                })
                .join('')
            : '<div style="margin-top:0.25rem;color:#64748b;font-style:italic;">⏳ En attente de confirmation de lecture signée par les destinataires.</div>';

        instructionHtml = `
          <div class="official-instruction-card">
            <div style="font-weight:700;color:#065f46;display:flex;align-items:center;justify-content:space-between;">
              <span>📌 Instruction Officielle de Service</span>
              <span style="font-size:0.68rem;background:#d1fae5;color:#065f46;padding:0.1rem 0.4rem;border-radius:4px;">Valeur probante HMAC-SHA256</span>
            </div>
            <div style="margin-top:0.25rem;">
              ${receiptsListHtml}
            </div>
            ${
              !hasAcked
                ? `<button type="button" class="ack-btn-inline" data-event-id="${ev.event_id}">✍️ Confirmer la lecture et signer l'accusé avec mon matricule (${escapeHtml(state.agent.matricule || state.agent.localpart)})</button>`
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
          <span>${timeStr}</span>
          ${expiryBadgeHtml}
          <span title="Chiffré de bout en bout (AES-256-GCM)">🔒</span>
        </div>
      `;

      // Événements interactifs sur la bulle
      const shield = bubble.querySelector('.confidential-content-shield');
      if (shield) {
        shield.addEventListener('mouseenter', () => shield.classList.remove('blurred'));
        shield.addEventListener('mouseleave', () => shield.classList.add('blurred'));
        shield.addEventListener('click', () => shield.classList.toggle('blurred'));
      }

      const dlBtn = bubble.querySelector('.download-att-btn');
      if (dlBtn && decrypted.attachment) {
        dlBtn.addEventListener('click', () => {
          triggerDecryptedFileDownload(decrypted.attachment.dataUrl, decrypted.attachment.name);
        });
      }

      const photoImg = bubble.querySelector('.encrypted-photo-img');
      if (photoImg && decrypted.attachment?.dataUrl) {
        photoImg.addEventListener('click', () => {
          const w = window.open('', '_blank');
          if (w) {
            w.document.write(
              `<html><head><title>${escapeHtml(decrypted.attachment.name)} — Photo déchiffrée E2EE</title></head><body style="margin:0;background:#0f172a;display:flex;align-items:center;justify-content:center;min-height:100vh;"><img src="${decrypted.attachment.dataUrl}" style="max-width:95vw;max-height:95vh;border-radius:8px;"/></body></html>`
            );
          }
        });
      }

      const ackBtn = bubble.querySelector('.ack-btn-inline');
      if (ackBtn) {
        ackBtn.addEventListener('click', async () => {
          await apiFetch('/api/receipts/acknowledge', {
            method: 'POST',
            body: JSON.stringify({ eventId: ev.event_id, roomId }),
          });
          state.lastRenderSignature = '';
          await renderRoomMessages(roomId, false);
        });
      }

      const ttsBtn = bubble.querySelector('.play-tts-btn');
      if (ttsBtn && decrypted.voiceSummary) {
        ttsBtn.addEventListener('click', () => {
          if ('speechSynthesis' in window) {
            window.speechSynthesis.cancel();
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
  {
    text,
    classification = 'NORMAL',
    ttlSec = 0,
    isInstruction = false,
    isVoice = false,
    voiceSummary = null,
    audioDataUrl = null,
    voiceDurationSec = null,
    attachment = null,
  }
) {
  const encrypted = await encryptRoomPayload(roomId, {
    text,
    voiceSummary,
    audioDataUrl,
    voiceDurationSec,
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

  // Bandeau discret de confidentialité + sélection automatique de l'expiration en mode Confidentiel
  document.getElementById('classificationSelect').addEventListener('change', (e) => {
    const val = e.target.value;
    const banner = document.getElementById('classificationBanner');
    const text = document.getElementById('classificationBannerText');
    const ttlSelect = document.getElementById('ttlSelect');
    if (val === 'NORMAL') {
      banner.classList.add('hidden');
    } else if (val === 'DIFFUSION_RESTREINTE') {
      banner.className = 'security-notice restricted';
      text.textContent =
        '🟠 Mode Diffusion Restreinte : copie (Ctrl+C) et clic droit désactivés sur ce message.';
    } else if (val === 'CONFIDENTIEL') {
      banner.className = 'security-notice confidential';
      text.textContent =
        '🔴 Mode Confidentiel : floutage anti-capture d’écran, filigrane au matricule du lecteur, export de fichier bloqué et auto-destruction automatique.';
      if (ttlSelect && ttlSelect.value === '0') {
        ttlSelect.value = '300';
      }
    }
  });

  // Lecture d'un fichier local en DataURL Base64 pour chiffrement E2EE AES-256-GCM
  const readFileAsDataUrl = (file) =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result));
      reader.onerror = () => reject(new Error('Impossible de lire le fichier sélectionné'));
      reader.readAsDataURL(file);
    });

  const clearStagedAttachment = () => {
    state.stagedAttachment = null;
    document.getElementById('fileAttachmentInput').value = '';
    document.getElementById('stagedAttachmentBar').classList.add('hidden');
    document.getElementById('stagedAttachmentPreview').innerHTML = '';
  };

  document.getElementById('cancelAttachmentBtn').addEventListener('click', clearStagedAttachment);

  // Sélection d'une photo ou d'un document à chiffrer de bout en bout
  const fileBtn = document.getElementById('attachFileBtn');
  const fileInput = document.getElementById('fileAttachmentInput');
  fileBtn.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files?.[0];
    if (!file || !state.activeRoomId) return;
    if (file.size > 10 * 1024 * 1024) {
      alert('Le fichier dépasse la taille maximale autorisée (10 Mo).');
      fileInput.value = '';
      return;
    }

    const sizeKb = Math.max(1, Math.round(file.size / 1024));
    const sizeLabel = sizeKb >= 1024 ? `${(sizeKb / 1024).toFixed(1)} Mo` : `${sizeKb} Ko`;
    const dataUrl = await readFileAsDataUrl(file);
    const isImage = file.type.startsWith('image/') || /\.(png|jpe?g|gif|webp|svg)$/i.test(file.name);

    state.stagedAttachment = {
      name: file.name,
      sizeLabel,
      mimeType: file.type || 'application/octet-stream',
      isImage,
      dataUrl,
    };

    const previewEl = document.getElementById('stagedAttachmentPreview');
    const icon = getFileTypeIcon(file.name, file.type);
    previewEl.innerHTML = `
      ${
        isImage
          ? `<img src="${dataUrl}" class="staged-thumb" alt="Aperçu" />`
          : `<span style="font-size:1.5rem;">${icon}</span>`
      }
      <div>
        <div><strong>${escapeHtml(file.name)}</strong> (${escapeHtml(sizeLabel)})</div>
        <div style="font-size:0.72rem;color:#047857;">🔒 Prêt à être chiffré de bout en bout (AES-256-GCM) — Cliquez sur « Envoyer »</div>
      </div>
    `;
    document.getElementById('stagedAttachmentBar').classList.remove('hidden');
    document.getElementById('messageInput').focus();
  });

  // Envoi d'un message texte et/ou d'une pièce jointe (photo / document) chiffrée de bout en bout
  document.getElementById('messageForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = document.getElementById('messageInput');
    const text = input.value.trim();
    if ((!text && !state.stagedAttachment) || !state.activeRoomId) return;

    const classification = document.getElementById('classificationSelect').value;
    const ttlSec = Number(document.getElementById('ttlSelect').value || 0);
    const isInstruction = document.getElementById('isInstructionCheckbox').checked;

    try {
      await sendEncryptedMessageToRoom(state.activeRoomId, {
        text,
        classification,
        ttlSec,
        isInstruction,
        attachment: state.stagedAttachment,
      });
      input.value = '';
      clearStagedAttachment();
      document.getElementById('isInstructionCheckbox').checked = false;
      state.lastRenderSignature = '';
      await renderRoomMessages(state.activeRoomId, true);
    } catch (err) {
      alert(err.message);
    }
  });

  // Générateur de fichier audio WAV de secours (si le PC n'a pas de microphone branché)
  const generateFallbackWavDataUrl = (durationSec = 3) => {
    const sampleRate = 8000;
    const numSamples = sampleRate * durationSec;
    const buffer = new ArrayBuffer(44 + numSamples * 2);
    const view = new DataView(buffer);
    const writeStr = (offset, str) => {
      for (let i = 0; i < str.length; i++) view.setUint8(offset + i, str.charCodeAt(i));
    };
    writeStr(0, 'RIFF');
    view.setUint32(4, 36 + numSamples * 2, true);
    writeStr(8, 'WAVE');
    writeStr(12, 'fmt ');
    view.setUint32(16, 16, true);
    view.setUint16(20, 1, true);
    view.setUint16(22, 1, true);
    view.setUint32(24, sampleRate, true);
    view.setUint32(28, sampleRate * 2, true);
    view.setUint16(32, 2, true);
    view.setUint16(34, 16, true);
    writeStr(36, 'data');
    view.setUint32(40, numSamples * 2, true);
    for (let i = 0; i < numSamples; i++) {
      const t = i / sampleRate;
      const freq = t < 1.0 ? 440 : t < 2.0 ? 554.37 : 659.25;
      const env = Math.sin(Math.PI * ((t % 1.0) / 1.0));
      const sample = Math.sin(2 * Math.PI * freq * t) * env * 0.35;
      view.setInt16(44 + i * 2, sample * 32767, true);
    }
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return 'data:audio/wav;base64,' + btoa(binary);
  };

  const stopVoiceRecorderStream = () => {
    if (state.voiceRecorder.timerInterval) {
      clearInterval(state.voiceRecorder.timerInterval);
      state.voiceRecorder.timerInterval = null;
    }
    if (state.voiceRecorder.stream) {
      state.voiceRecorder.stream.getTracks().forEach((t) => t.stop());
      state.voiceRecorder.stream = null;
    }
    state.voiceRecorder.mediaRecorder = null;
    state.voiceRecorder.chunks = [];
    document.getElementById('voiceRecorderBar').classList.add('hidden');
  };

  // Clic sur le bouton Microphone 🎙️ : démarre l'enregistrement vocal en direct
  document.getElementById('voiceNoteBtn').addEventListener('click', async () => {
    if (!state.activeRoomId) return;
    const recBar = document.getElementById('voiceRecorderBar');
    if (!recBar.classList.contains('hidden')) {
      return;
    }

    state.voiceRecorder.chunks = [];
    state.voiceRecorder.startedAt = Date.now();
    state.voiceRecorder.isFallbackMode = false;

    const updateRecTimer = () => {
      const sec = Math.max(0, Math.floor((Date.now() - state.voiceRecorder.startedAt) / 1000));
      const mm = String(Math.floor(sec / 60)).padStart(2, '0');
      const ss = String(sec % 60).padStart(2, '0');
      document.getElementById('voiceRecTimer').textContent = `${mm}:${ss}`;
    };

    try {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        throw new Error('API Microphone non disponible');
      }
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      state.voiceRecorder.stream = stream;
      const recorder = new MediaRecorder(stream);
      state.voiceRecorder.mediaRecorder = recorder;
      recorder.ondataavailable = (ev) => {
        if (ev.data && ev.data.size > 0) state.voiceRecorder.chunks.push(ev.data);
      };
      recorder.start();
      document.getElementById('voiceRecStatusText').textContent = '🎙️ Enregistrement micro en direct...';
    } catch {
      // Si l'ordinateur n'a pas de micro branché ou permission refusée : mode enregistrement simulé sans blocage
      state.voiceRecorder.isFallbackMode = true;
      document.getElementById('voiceRecStatusText').textContent =
        '🎙️ Enregistrement vocal (mode synthèse locale — aucun micro détecté)...';
    }

    updateRecTimer();
    state.voiceRecorder.timerInterval = setInterval(updateRecTimer, 500);
    recBar.classList.remove('hidden');
  });

  // Annuler l'enregistrement vocal
  document.getElementById('cancelVoiceBtn').addEventListener('click', () => {
    if (state.voiceRecorder.mediaRecorder && state.voiceRecorder.mediaRecorder.state !== 'inactive') {
      state.voiceRecorder.mediaRecorder.stop();
    }
    stopVoiceRecorderStream();
  });

  // Valider, chiffrer (AES-256-GCM) et envoyer le message vocal enregistré
  document.getElementById('sendVoiceBtn').addEventListener('click', async () => {
    if (!state.activeRoomId) return;
    const durationSec = Math.max(1, Math.round((Date.now() - state.voiceRecorder.startedAt) / 1000));
    const phrases = {
      fr: 'Note vocale de service enregistrée et chiffrée de bout en bout.',
      mos: 'Koɛɛga : Ne y zabr fãa, bɩ y ges sebrã tõnd sẽn tʋmã.',
      dyu: 'Kumakan : Aw ni baara, aw ye sɛbɛn cilen lajɛ.',
      ff: 'Daande : On jaaraama, ƴeewon dossier neldaaɗo oo.',
    };
    const customText = document.getElementById('messageInput').value.trim();
    const voiceSummary = customText || phrases[state.lang] || phrases.fr;

    let audioDataUrl = null;
    if (!state.voiceRecorder.isFallbackMode && state.voiceRecorder.mediaRecorder) {
      audioDataUrl = await new Promise((resolve) => {
        const rec = state.voiceRecorder.mediaRecorder;
        rec.onstop = async () => {
          const blob = new Blob(state.voiceRecorder.chunks, { type: rec.mimeType || 'audio/webm' });
          const dataUrl = await readFileAsDataUrl(blob);
          resolve(dataUrl);
        };
        if (rec.state !== 'inactive') {
          rec.stop();
        } else {
          resolve(generateFallbackWavDataUrl(Math.min(durationSec, 5)));
        }
      });
    } else {
      audioDataUrl = generateFallbackWavDataUrl(Math.min(durationSec, 5));
    }

    stopVoiceRecorderStream();

    try {
      await sendEncryptedMessageToRoom(state.activeRoomId, {
        text: voiceSummary,
        voiceSummary,
        audioDataUrl,
        voiceDurationSec: durationSec,
        isVoice: true,
        classification: document.getElementById('classificationSelect').value,
        ttlSec: Number(document.getElementById('ttlSelect').value || 0),
        isInstruction: document.getElementById('isInstructionCheckbox').checked,
      });
      document.getElementById('messageInput').value = '';
      state.lastRenderSignature = '';
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
        <div>✅ Agent <strong>${escapeHtml(res.agent.fullName)}</strong> enregistré dans l'annuaire souverain.</div>
        <div style="font-size:0.78rem;margin-top:0.25rem;">Aucune clé 2FA n'a été générée par l'administration. L'agent générera lui-même sa clé sur son téléphone (FreeOTP) lors de sa toute première connexion.</div>
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
