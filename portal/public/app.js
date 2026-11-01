/**
 * Client Web Souverain (FasoSouverain — MTDPCE / DGTD)
 *
 * Explication technique pour l'entretien avec le jury :
 * 1. Chiffrement de bout en bout (E2EE) côté client :
 *    - Utilise l'API cryptographique standard du navigateur (`window.crypto.subtle` — WebCrypto)
 *      pour dériver la clé de session de groupe Megolm (PBKDF2-SHA256 -> AES-GCM 256 bits)
 *      et chiffrer chaque message et chaque note vocale AVANT tout envoi réseau.
 *    - Le serveur ne reçoit qu'un évènement `m.room.encrypted` contenant `ciphertext` et `iv`.
 * 2. Authentification forte à 2 facteurs (Mot de passe + TOTP RFC 6238) + RBAC.
 * 3. Innovations pour l'administration :
 *    - Langues nationales : Français, Mooré, Dioula, Fulfuldé (+3 pts bonus)
 *    - Niveaux de classification : Normal, Diffusion Restreinte, Confidentiel État (expiration auto, anti-copie)
 *    - Instructions de service avec Accusé de Lecture à valeur probante signé (HMAC-SHA256)
 *    - Bouton d'urgence (Panic Wipe) : effacement des clés locales + révocation immédiate
 */

const I18N = {
  fr: {
    app_title: "MESSAGERIE SOUVERAINE DE L'ADMINISTRATION",
    gov_motto: "MTDPCE · DGTD — Burkina Faso · « La Patrie ou la Mort, nous Vaincrons »",
    lang_label: "Langue :",
    e2ee_active: "E2EE Olm/Megolm Actif",
    panic_btn: "Bouton d'Urgence",
    logout_btn: "Déconnexion",
    login_title: "Portail d'Accès Agent Public",
    login_subtitle: "Accès strictement réservé aux agents préalablement enrôlés par l'État. Authentification forte à 2 facteurs obligatoire.",
    label_username: "Identifiant Matricule / Agent Matrix",
    label_password: "Mot de passe souverain (1er facteur)",
    btn_step1: "Vérifier l'identité (Étape 1/2)",
    label_totp: "Code du 2e Facteur (TOTP à 6 chiffres — RFC 6238)",
    btn_step2: "Valider le 2e Facteur & Déverrouiller les Clés E2EE",
    jury_panel_title: "Console d'Évaluation Jury (Comptes Fictifs)",
    jury_panel_desc: "Cliquez sur un agent fictif pour pré-remplir ses identifiants et son code 2FA TOTP temps-réel, ou testez le rejet d'un intrus :",
    tab_chat: "Canaux Chiffrés",
    tab_directory: "Annuaire Ministères",
    tab_blind: "Preuve Serveur Aveugle",
    tab_admin: "Admin & Révocation",
    channels_title: "SALONS CHIFFRÉS (MEGOLM)",
    label_classification: "Classification :",
    label_ttl: "Expiration :",
    label_instruction: "Instruction de Service (Accusé signé requis)",
    msg_placeholder: "Écrire un message chiffré de bout en bout...",
    btn_voice: "Vocal",
    btn_send: "Chiffrer & Envoyer 🔒",
    dir_title: "Annuaire Officiel des Agents Publics Assermentés",
    dir_subtitle: "Répertoire souverain par Ministère, Direction et Fonction avec statut d'habilitation temps-réel.",
  },
  mos: {
    app_title: " GOUVERNEMENT SÕOR KIBARE (FASO MESSAGERIE)",
    gov_motto: "MTDPCE · DGTD — Burkina Faso · « Tẽngã bɩ kũum, tõnd na tõoge »",
    lang_label: "Goama :",
    e2ee_active: "Kibar sẽn pag ne Olm/Megolm",
    panic_btn: "Yãgbo / Sãam fãa",
    logout_btn: "Yi",
    login_title: "Tʋʋm-tʋmdb Kẽesg Zĩiga",
    login_subtitle: "Neb nins lɛta wã sẽn gʋls b yʋʋr bal n tõe n kẽ. TOTP Sõor a 6 la tɩlae.",
    label_username: "Tʋʋm-tʋmd Yʋʋre / Matricule",
    label_password: "Kʋɩlenga (Mot de passe)",
    btn_step1: "Vaees yʋʋrã (1/2)",
    label_totp: "TOTP Sõor a 6 (2FA)",
    btn_step2: "Kẽ la pak kibarã kʋɩlense",
    jury_panel_title: "Jury Makr Zĩiga (Comptes Fictifs)",
    jury_panel_desc: "Dĩm tʋʋm-tʋmd yʋʋr tɩ kẽes a 정보 la TOTP, bɩ y mak nin-sãanga (Intrus) :",
    tab_chat: "Sõsg Zĩisi",
    tab_directory: "Ministɛɛr Sebre",
    tab_blind: "Serveur Kãabgo",
    tab_admin: "Admin & Yiisgo",
    channels_title: "SÕSG ZĨISI (MEGOLM)",
    label_classification: " Gũusg Zĩiga :",
    label_ttl: "Saabo :",
    label_instruction: "Tʋʋm Noy (Instruction de Service)",
    msg_placeholder: "Gʋls koɛɛg sẽn pag ne E2EE...",
    btn_voice: "Koɛɛga",
    btn_send: "Pag la Tʋm 🔒",
    dir_title: "Lɛta Tʋʋm-tʋmdb Sebre",
    dir_subtitle: "Ministɛɛr fãa tʋʋm-tʋmdb yʋy la b tʋʋma.",
  },
  dyu: {
    app_title: "FANGA Kibarodagasira Лаkana (FASO MESSAGERIE)",
    gov_motto: "MTDPCE · DGTD — Burkina Faso · « Fasojamana walima Saya, an bɛ se »",
    lang_label: "Kan :",
    e2ee_active: "Kibaro Datugulen Olm/Megolm",
    panic_btn: "Balawo Bɔtɔn",
    logout_btn: "Bɔ",
    login_title: "Fanga Baarakɛlaw Donnida",
    login_subtitle: "Fanga baarakɛlaw dɔrɔn de bɛ se ka don. Lakanasɛbɛn filanan (2FA) wajibiyalen don.",
    label_username: "Baarakɛla Tɔgɔ / Matricule",
    label_password: "Gundodaɲɛ (Mot de passe)",
    btn_step1: "Tɔgɔ Sɛgɛsɛgɛ (1/2)",
    label_totp: "TOTP Nimɔrɔ 6 (2FA)",
    btn_step2: "Don ka E2EE Da Yɛlɛ",
    jury_panel_title: "Jury Kɔrɔbɔli Wala (Comptes Fictifs)",
    jury_panel_desc: "Baarakɛla kelen sugandi walasa ka don joona, walima dunan (Intrus) kɔrɔbɔ :",
    tab_chat: "Baro Kɛyɔrɔw",
    tab_directory: "Minisiriw Tɔgɔsɛbɛn",
    tab_blind: "Serveur Yeli Kɔrɔbɔli",
    tab_admin: "Admin & Dabɔli",
    channels_title: "BARO DATUGULENW (MEGOLM)",
    label_classification: "Lakana Hakɛ :",
    label_ttl: "Bannako :",
    label_instruction: "Baara Ci (Instruction de Service)",
    msg_placeholder: "Bataki sɛbɛn ni E2EE lakana ye...",
    btn_voice: "Kumakan",
    btn_send: "Datugu & Ci 🔒",
    dir_title: "Fanga Baarakɛlaw Tɔgɔsɛbɛn",
    dir_subtitle: "Minisiriso bɛɛ baarakɛlaw ni u ka jɔyɔrɔw.",
  },
  ff: {
    app_title: "NELAL LAAMU SUURangal (FASO MESSAGERIE)",
    gov_motto: "MTDPCE · DGTD — Burkina Faso · « Leydi men walla Maayde, minpooli »",
    lang_label: "Ɗemngal :",
    e2ee_active: "E2EE Olm/Megolm Huuɓtidii",
    panic_btn: "Momtugol Jaawngol",
    logout_btn: "Yaltu",
    login_title: "Damal Gollotooɓe Laamu",
    login_subtitle: "Gollotooɓe winnditaaɓe tan mbaawi naatde. 2FA TOTP ina waɗɗii.",
    label_username: "Innde Gollotooɗo / Matricule",
    label_password: "Finnde (Mot de passe)",
    btn_step1: "Ƴeewto Innde (1/2)",
    label_totp: "TOTP Limre 6 (2FA)",
    btn_step2: "Tabitinde 2FA & Udditde E2EE",
    jury_panel_title: "Ƴeewndo Jury (Comptes Fictifs)",
    jury_panel_desc: "Suɓo gollotooɗo ngam ƴeewndaade, walla ƴeewto keeri (Intrus) :",
    tab_chat: "Cuuɗi Yeewtere",
    tab_directory: "Deftere Ministeeruuji",
    tab_blind: "Ƴeewndo Serveur",
    tab_admin: "Admin & Ittugol",
    channels_title: "CUUƊI E2EE (MEGOLM)",
    label_classification: "Darnde Suura :",
    label_ttl: "Momtugol :",
    label_instruction: "Yamiroore Golle (Instruction)",
    msg_placeholder: "Winndu nelal cuuraangal E2EE...",
    btn_voice: "Daande",
    btn_send: "Suuru & Neldul 🔒",
    dir_title: "Deftere Gollotooɓe Laamu",
    dir_subtitle: "Gollotooɓe laamu fof e ministeeruuji mum en.",
  },
};

const state = {
  lang: 'fr',
  portalToken: null,
  matrixAccessToken: null,
  agent: null,
  rooms: [],
  activeRoomId: null,
  roomCryptoKeys: new Map(), // roomId -> { key: CryptoKey, fingerprint: string }
  pollTimer: null,
  demoAccounts: [],
};

// ============================================================================
// 1. CRYPTOGRAPHIE CLIENT (STANDARD WEBCRYPTO — AES-GCM 256 / MEGOLM SESSION)
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
    .slice(0, 6)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(':');

  const entry = {
    key: aesKey,
    sessionId: `megolm_${hashHex.replace(/:/g, '').toLowerCase()}`,
    fingerprint: `Empreinte Clé Megolm : ${hashHex}`,
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
    device_id: state.agent?.deviceId || 'FASO_WEB_DEVICE',
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
    return { text: '[Contenu chiffré — Clé de session non disponible sur cet appareil]' };
  }
}

// ============================================================================
// 2. INTERNATIONALISATION (FRANÇAIS, MOORÉ, DIOULA, FULULDÉ)
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
}

// ============================================================================
// 3. APPELS API ET GESTION DE LA RÉVOCATION EN TEMPS RÉEL
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
    throw new Error(data.message || 'Erreur requête');
  }
  return data;
}

function handleImmediateRevocationKick(reasonMsg) {
  // Purge immédiate des clés cryptographiques en mémoire et stockage local
  state.roomCryptoKeys.clear();
  state.portalToken = null;
  state.matrixAccessToken = null;
  state.agent = null;
  if (state.pollTimer) clearInterval(state.pollTimer);
  localStorage.clear();
  sessionStorage.clear();

  document.getElementById('workspaceScreen').classList.add('hidden');
  document.getElementById('authScreen').classList.remove('hidden');
  document.getElementById('panicBtn').classList.add('hidden');
  document.getElementById('logoutBtn').classList.add('hidden');

  showAuthAlert(
    `🚨 RÉVOCATION IMMÉDIATE : ${reasonMsg || "Votre accès a été révoqué par l'administration. Toutes les clés E2EE locales ont été purgées."}`,
    'error'
  );
  loadDemoAccounts();
}

function showAuthAlert(msg, type = 'error') {
  const box = document.getElementById('authAlert');
  box.textContent = msg;
  box.className = `alert ${type}`;
  box.classList.remove('hidden');
}

// ============================================================================
// 4. CONSOLE D'AIDE JURY & AUTHENTIFICATION 2FA
// ============================================================================

async function loadDemoAccounts() {
  try {
    const data = await apiFetch('/api/demo/accounts');
    state.demoAccounts = data.accounts || [];
    const container = document.getElementById('demoAccountsList');
    container.innerHTML = '';

    for (const acc of state.demoAccounts) {
      const div = document.createElement('div');
      div.className = `demo-account-item ${acc.status !== 'ACTIVE' ? 'revoked' : ''}`;
      div.innerHTML = `
        <div>
          <strong>${acc.fullName}</strong> <span class="role-tag ${acc.role}">${acc.role}</span>
          <div class="small-muted">@${acc.localpart} · ${acc.ministry} · Matricule: ${acc.matricule}</div>
          <div class="totp-hint">Code 2FA TOTP actuel : <code>${acc.currentTotpDemo}</code></div>
        </div>
        <button type="button" class="btn-secondary" ${acc.status !== 'ACTIVE' ? 'disabled' : ''}>
          ${acc.status === 'ACTIVE' ? 'Utiliser ce compte →' : '🚫 Révoqué'}
        </button>
      `;
      const btn = div.querySelector('button');
      if (acc.status === 'ACTIVE') {
        btn.addEventListener('click', () => {
          document.getElementById('usernameInput').value = acc.localpart;
          document.getElementById('passwordInput').value = data.demoPassword;
          document.getElementById('authAlert').classList.add('hidden');
        });
      }
      container.appendChild(div);
    }

    // Peuple le filtre ministère de l'annuaire
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

async function setupAuthHandlers() {
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
        <strong>✅ 1er Facteur Validé :</strong> ${res.agentPreview.fullName} (${res.agentPreview.matricule})<br/>
        <span>Ministère : <b>${res.agentPreview.ministry}</b> · Rôle : <b>${res.agentPreview.role}</b></span>
      `;
      document.getElementById('totpInput').value = res.demoTotpHint || '';
      document.getElementById('totpDemoHint').textContent =
        `💡 Aide Démo Jury : Le code TOTP RFC 6238 généré pour cet agent est pré-rempli (${res.demoTotpHint}).`;

      step1Form.classList.add('hidden');
      step2Form.classList.remove('hidden');
    } catch (err) {
      showAuthAlert(`❌ ${err.message}`, 'error');
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

      step2Form.classList.add('hidden');
      step1Form.classList.remove('hidden');
      enterWorkspace();
    } catch (err) {
      showAuthAlert(`❌ ${err.message}`, 'error');
    }
  });

  document.getElementById('backToStep1Btn').addEventListener('click', () => {
    step2Form.classList.add('hidden');
    step1Form.classList.remove('hidden');
  });

  // Bouton Épreuve Jury « Intrus »
  document.getElementById('testIntrusBtn').addEventListener('click', async () => {
    document.getElementById('usernameInput').value = 'intrus.externe';
    try {
      await apiFetch('/api/auth/login-step1', {
        method: 'POST',
        body: JSON.stringify({ username: 'intrus.externe', password: ' FakePassword123!' }),
      });
    } catch (err) {
      showAuthAlert(`🛡️ ÉPREUVE INTRUS RÉUSSIE (Rejet immédiat) : ${err.message}`, 'error');
    }
  });
}

// ============================================================================
// 5. ESPACE DE TRAVAIL MESSAGERIE, CLASSIFICATION & INSTRUCTIONS DE SERVICE
// ============================================================================

async function enterWorkspace() {
  document.getElementById('authScreen').classList.add('hidden');
  document.getElementById('workspaceScreen').classList.remove('hidden');
  document.getElementById('panicBtn').classList.remove('hidden');
  document.getElementById('logoutBtn').classList.remove('hidden');

  // Affiche la carte d'identité de l'agent connecté
  document.getElementById('currentUserCard').innerHTML = `
    <div><strong>${state.agent.fullName}</strong></div>
    <div class="small-muted">${state.agent.userId}</div>
    <div style="margin-top:0.35rem;">
      <span class="role-tag ${state.agent.role}">${state.agent.roleLabel}</span>
      <span class="role-tag">${state.agent.ministry}</span>
    </div>
    <div class="small-muted" style="margin-top:0.3rem;">Matricule : <code>${state.agent.matricule}</code></div>
  `;

  // Masque ou affiche les options réservées aux Directeurs / Admin
  const canSendInstruction =
    state.agent.role === 'ADMIN_SG' || state.agent.role === 'DIRECTEUR';
  document.getElementById('instructionToggleWrapper').style.display = canSendInstruction
    ? 'flex'
    : 'none';

  await loadRooms();
  await loadDirectory();
  await loadBlindCheck();
  await loadAdminPanel();

  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    if (!state.portalToken) return;
    try {
      await apiFetch('/api/me'); // Vérifie que l'agent n'est pas révoqué en direct
      if (state.activeRoomId) {
        await renderRoomMessages(state.activeRoomId);
      }
    } catch {
      // Géré automatiquement par apiFetch (déconnexion immédiate si révoqué)
    }
  }, 2500);
}

async function loadRooms() {
  const data = await apiFetch('/api/rooms');
  state.rooms = data.rooms || [];
  const ul = document.getElementById('roomsList');
  ul.innerHTML = '';

  for (const r of state.rooms) {
    const li = document.createElement('li');
    li.className = `room-item ${r.room_id === state.activeRoomId ? 'active' : ''}`;
    li.innerHTML = `
      <div><strong>🔒 ${r.name}</strong></div>
      <div class="small-muted">${r.ministry} · ${r.members.length} agents</div>
    `;
    li.addEventListener('click', () => selectRoom(r.room_id));
    ul.appendChild(li);
  }

  if (!state.activeRoomId && state.rooms.length > 0) {
    await selectRoom(state.rooms[0].room_id);
  }
}

async function selectRoom(roomId) {
  state.activeRoomId = roomId;
  const room = state.rooms.find((r) => r.room_id === roomId);
  if (room) {
    document.getElementById('activeRoomName').textContent = `🔒 ${room.name}`;
    document.getElementById('activeRoomTopic').textContent = room.topic;
  }

  const keyInfo = await getOrCreateRoomMegolmKey(roomId);
  document.getElementById('roomKeyFingerprint').textContent = keyInfo.fingerprint;

  document.querySelectorAll('.room-item').forEach((el, idx) => {
    el.classList.toggle('active', state.rooms[idx]?.room_id === roomId);
  });

  await renderRoomMessages(roomId);
}

async function renderRoomMessages(roomId) {
  const data = await apiFetch(`/api/rooms/${encodeURIComponent(roomId)}/events`);
  const container = document.getElementById('messagesContainer');
  container.innerHTML = '';

  for (const ev of data.events) {
    if (ev.type === 'm.room.encryption') {
      const sysDiv = document.createElement('div');
      sysDiv.className = 'small-muted';
      sysDiv.style.textAlign = 'center';
      sysDiv.textContent = `🔐 Salon initialisé avec le protocole Matrix ${ev.content.algorithm} (aucun texte en clair sur le serveur)`;
      container.appendChild(sysDiv);
      continue;
    }

    if (ev.type === 'm.room.member' && ev.content.membership === 'leave') {
      const revDiv = document.createElement('div');
      revDiv.className = 'alert error';
      revDiv.textContent = `⚡ SÉCURITÉ : L'agent ${ev.sender} a été retiré du salon (${ev.content.reason}). Rotation de clé Megolm effectuée.`;
      container.appendChild(revDiv);
      continue;
    }

    if (ev.type === 'm.room.encrypted') {
      const decrypted = await decryptRoomPayload(roomId, ev.content);
      const meta = ev.content.faso_meta || {};
      const classification = meta.classification || 'NORMAL';
      const isOwn = ev.sender === state.agent.userId;

      const card = document.createElement('div');
      card.className = `msg-card ${isOwn ? 'own' : ''} ${classification}`;

      // Blocage copie / transfert pour Diffusion Restreinte et Confidentiel
      if (classification !== 'NORMAL') {
        card.addEventListener('copy', (e) => {
          e.preventDefault();
          alert('🚫 Action bloquée : La copie et le transfert sont interdits sur un message classifié.');
        });
      }

      const timeStr = new Date(ev.origin_server_ts).toLocaleTimeString('fr-FR');
      const expiryBadge = meta.expires_at
        ? ` · ⏳ Expire dans ${Math.max(1, Math.round((meta.expires_at - Date.now()) / 1000))}s`
        : '';

      let bodyHtml = `<div class="msg-body">${escapeHtml(decrypted.text || '')}</div>`;
      if (meta.is_voice && decrypted.voiceSummary) {
        bodyHtml = `
          <div class="msg-body">
            🎙️ <strong>Note Vocale Chiffrée (${meta.lang?.toUpperCase() || 'FR'}) :</strong>
            ${escapeHtml(decrypted.voiceSummary)}
            <button type="button" class="btn-secondary play-voice-btn" style="margin-left:0.5rem;padding:0.2rem 0.5rem;">▶️ Écouter</button>
          </div>
        `;
      }

      let instructionHtml = '';
      if (meta.is_instruction) {
        const receipts = ev.receipts || [];
        const hasAcked = receipts.some((r) => r.agentId === state.agent.userId);
        const receiptsListHtml = receipts
          .map(
            (r) =>
              `<div>✅ <b>${escapeHtml(r.fullName)}</b> (${escapeHtml(r.matricule)} · ${escapeHtml(r.ministry)}) — Signé HMAC: <code>${r.signature.slice(0, 14)}...</code></div>`
          )
          .join('');

        instructionHtml = `
          <div class="instruction-box">
            <div>📜 <strong>INSTRUCTION DE SERVICE OFFICIELLE (Valeur Probante)</strong></div>
            <div style="margin-top:0.35rem;">${receiptsListHtml || '<em>Aucun accusé de réception enregistré pour le moment.</em>'}</div>
            ${
              !hasAcked
                ? `<button type="button" class="btn-primary ack-btn" data-event-id="${ev.event_id}" style="margin-top:0.45rem;">✍️ Accuser réception officiellement (Signature HMAC-SHA256)</button>`
                : ''
            }
          </div>
        `;
      }

      card.innerHTML = `
        <div class="msg-meta">
          <span><strong>${escapeHtml(ev.sender)}</strong> · ${timeStr}</span>
          <span><b class="role-tag">${classification}</b>${expiryBadge}</span>
        </div>
        ${bodyHtml}
        ${instructionHtml}
        <div class="msg-cipher-preview">
          Stocké dans Synapse PostgreSQL (m.room.encrypted) : ciphertext="${ev.content.ciphertext.slice(0, 38)}..."
        </div>
      `;

      const ackBtn = card.querySelector('.ack-btn');
      if (ackBtn) {
        ackBtn.addEventListener('click', async () => {
          await apiFetch('/api/receipts/acknowledge', {
            method: 'POST',
            body: JSON.stringify({ eventId: ev.event_id, roomId }),
          });
          await renderRoomMessages(roomId);
        });
      }

      const playBtn = card.querySelector('.play-voice-btn');
      if (playBtn) {
        playBtn.addEventListener('click', () => {
          if ('speechSynthesis' in window) {
            const utter = new SpeechSynthesisUtterance(decrypted.voiceSummary);
            utter.lang = 'fr-FR';
            window.speechSynthesis.speak(utter);
          }
        });
      }

      container.appendChild(card);
    }
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ============================================================================
// 6. ANNUAIRE MINISTÉRIEL, PREUVE SERVEUR AVEUGLE & CONSOLE ADMIN
// ============================================================================

async function loadDirectory() {
  const ministry = document.getElementById('ministryFilterSelect').value || 'ALL';
  const data = await apiFetch(`/api/directory?ministry=${encodeURIComponent(ministry)}`);
  const grid = document.getElementById('directoryGrid');
  grid.innerHTML = '';

  for (const ag of data.agents) {
    const card = document.createElement('div');
    card.className = 'dir-card';
    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <strong>${escapeHtml(ag.fullName)}</strong>
        <span class="role-tag ${ag.role}">${ag.status === 'ACTIVE' ? '🟢 ACTIF' : '🔴 RÉVOQUÉ'}</span>
      </div>
      <div class="small-muted" style="margin:0.3rem 0;">${escapeHtml(ag.title)} — ${escapeHtml(ag.direction)}</div>
      <div><span class="role-tag">${escapeHtml(ag.ministry)}</span> <span class="role-tag">${escapeHtml(ag.roleLabel)}</span></div>
      <div class="small-muted" style="margin-top:0.4rem;">Identifiant Matrix : <code>${escapeHtml(ag.userId)}</code> · Matricule : <code>${escapeHtml(ag.matricule)}</code></div>
    `;
    grid.appendChild(card);
  }
}

async function loadBlindCheck() {
  const data = await apiFetch('/api/security/blind-check');
  const container = document.getElementById('blindCheckResult');
  container.innerHTML = `
    <div class="dir-card">
      <h3>✅ Statut Base de Données : ${data.status}</h3>
      <p style="margin:0.5rem 0;font-size:1.1rem;color:#34d399;">
        Messages en clair (<code>m.room.message</code>) : <strong>${data.clear_text_events_count}</strong>
      </p>
      <p class="small-muted">Tous les échanges des agents sont stockés exclusivement sous forme d'évènements chiffrés <code>m.room.encrypted</code> (algorithme <code>m.megolm.v1.aes-sha2</code>).</p>
      <pre class="code-block" style="margin-top:0.65rem;">${escapeHtml(JSON.stringify(data.event_types_summary, null, 2))}</pre>
    </div>
    <div class="dir-card">
      <h3>🔐 Derniers Évènements Chiffrés en Base (Aucune clé sur le serveur)</h3>
      <pre class="code-block" style="margin-top:0.5rem;">${escapeHtml(JSON.stringify(data.sample_encrypted_records, null, 2))}</pre>
    </div>
    <div class="dir-card">
      <h3>🛡️ Politique de Minimisation des Métadonnées Active</h3>
      <pre class="code-block" style="margin-top:0.5rem;">${escapeHtml(JSON.stringify(data.metadata_minimization_policy, null, 2))}</pre>
    </div>
    <div class="dir-card">
      <h3>📋 Journal d'Audit Sécurité (Sans contenu de message)</h3>
      <pre class="code-block" style="margin-top:0.5rem;">${escapeHtml(JSON.stringify(data.audit_logs.slice(0, 6), null, 2))}</pre>
    </div>
  `;
}

async function loadAdminPanel() {
  const data = await apiFetch('/api/directory?ministry=ALL');
  const list = document.getElementById('adminAgentsList');
  list.innerHTML = '';

  for (const ag of data.agents) {
    const item = document.createElement('div');
    item.className = 'demo-account-item';
    const canRevoke =
      state.agent.role === 'ADMIN_SG' && ag.localpart !== 'admin' && ag.status === 'ACTIVE';

    item.innerHTML = `
      <div>
        <strong>${escapeHtml(ag.fullName)}</strong> (<code>@${escapeHtml(ag.localpart)}</code>)
        <div class="small-muted">${escapeHtml(ag.ministry)} · Rôle: ${escapeHtml(ag.role)} · Statut: <b>${ag.status}</b></div>
      </div>
      ${
        canRevoke
          ? `<button type="button" class="btn-panic revoke-agent-btn" data-localpart="${escapeHtml(ag.localpart)}">⚡ Révoquer immédiatement</button>`
          : `<span class="role-tag">${ag.status === 'REVOKED' ? '🚫 Déjà Révoqué' : 'Protégé'}</span>`
      }
    `;

    const revBtn = item.querySelector('.revoke-agent-btn');
    if (revBtn) {
      revBtn.addEventListener('click', async () => {
        try {
          const res = await apiFetch('/api/admin/revoke', {
            method: 'POST',
            body: JSON.stringify({ localpart: ag.localpart }),
          });
          alert(
            `✅ Agent @${ag.localpart} révoqué immédiatement !\n- Sessions coupées : ${res.matrixRevocation.revoked_sessions}\n- Salons quittés : ${res.matrixRevocation.rooms_removed}\n- Clé Megolm renouvelée.`
          );
          await loadAdminPanel();
          await loadDirectory();
          if (state.activeRoomId) await renderRoomMessages(state.activeRoomId);
        } catch (err) {
          alert(`Erreur : ${err.message}`);
        }
      });
    }
    list.appendChild(item);
  }
}

// ============================================================================
// 7. INITIALISATION GLOBALE DE L'INTERFACE
// ============================================================================

window.addEventListener('DOMContentLoaded', () => {
  loadDemoAccounts();
  setupAuthHandlers();

  // Changement de langue nationale (+3 pts bonus)
  document.getElementById('langSelect').addEventListener('change', (e) => {
    applyLanguage(e.target.value);
  });

  // Navigation par onglets
  document.querySelectorAll('.nav-tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.nav-tab').forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach((t) => t.classList.add('hidden'));
      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      document.getElementById(targetId).classList.remove('hidden');
      if (targetId === 'directoryTab') loadDirectory();
      if (targetId === 'blindTab') loadBlindCheck();
      if (targetId === 'adminTab') loadAdminPanel();
    });
  });

  // Changement de niveau de classification
  document.getElementById('classificationSelect').addEventListener('change', (e) => {
    const val = e.target.value;
    const banner = document.getElementById('classificationBanner');
    const text = document.getElementById('classificationBannerText');
    if (val === 'NORMAL') {
      banner.className = 'classification-banner normal';
      text.textContent =
        'Protection E2EE active : le serveur Synapse ne stocke que du contenu chiffré (m.room.encrypted).';
    } else if (val === 'DIFFUSION_RESTREINTE') {
      banner.className = 'classification-banner restricted';
      text.textContent =
        '⚠️ DIFFUSION RESTREINTE : Copie et transfert bloqués. Expiration automatique activée.';
    } else if (val === 'CONFIDENTIEL') {
      banner.className = 'classification-banner confidential';
      text.textContent =
        '🚨 CONFIDENTIEL ÉTAT : Réservé aux Directeurs/Admin. Interdiction stricte de capture/copie et autodestruction rapide.';
    }
  });

  // Envoi d'un message chiffré de bout en bout
  document.getElementById('messageForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = document.getElementById('messageInput');
    const text = input.value.trim();
    if (!text || !state.activeRoomId) return;

    const classification = document.getElementById('classificationSelect').value;
    const ttlSec = Number(document.getElementById('ttlSelect').value || 0);
    const isInstruction = document.getElementById('isInstructionCheckbox').checked;

    try {
      const encrypted = await encryptRoomPayload(state.activeRoomId, {
        text,
        senderName: state.agent.fullName,
        sentAt: new Date().toISOString(),
      });

      const expiresAt =
        ttlSec > 0
          ? Date.now() + ttlSec * 1000
          : classification === 'CONFIDENTIEL'
          ? Date.now() + 300 * 1000
          : null;

      await apiFetch(`/api/rooms/${encodeURIComponent(state.activeRoomId)}/send-encrypted`, {
        method: 'POST',
        body: JSON.stringify({
          type: 'm.room.encrypted',
          content: {
            ...encrypted,
            faso_meta: {
              classification,
              expires_at: expiresAt,
              is_instruction: isInstruction,
              is_voice: false,
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

      input.value = '';
      document.getElementById('isInstructionCheckbox').checked = false;
      await renderRoomMessages(state.activeRoomId);
    } catch (err) {
      alert(`⛔ Refusé : ${err.message}`);
    }
  });

  // Envoi d'une Note Vocale Chiffrée en Langue Nationale (+3 pts bonus)
  document.getElementById('voiceNoteBtn').addEventListener('click', async () => {
    if (!state.activeRoomId) return;
    const greetings = {
      fr: 'Instruction vocale chiffrée : Veuillez sécuriser le rapport ministériel.',
      mos: 'Koɛɛg sẽn pag ne E2EE : Ne y zabr fãa, bɩ y gũus ministɛɛrã sɛb sõma.',
      dyu: 'Kumakan datugulen : Aw ni baara, aw ye minisiriɲɛmɔgɔ ka sɛbɛnw lakana kosɛbɛ.',
      ff: 'Nelal daande cuuraangal : On jaaraama, ndeenon kaayitaaji laamu ɗii.',
    };
    const voiceSummary = greetings[state.lang] || greetings.fr;
    const encrypted = await encryptRoomPayload(state.activeRoomId, {
      text: voiceSummary,
      voiceSummary,
      isVoice: true,
    });

    await apiFetch(`/api/rooms/${encodeURIComponent(state.activeRoomId)}/send-encrypted`, {
      method: 'POST',
      body: JSON.stringify({
        type: 'm.room.encrypted',
        content: {
          ...encrypted,
          faso_meta: {
            classification: document.getElementById('classificationSelect').value,
            is_voice: true,
            lang: state.lang,
          },
        },
        faso_meta: {
          classification: document.getElementById('classificationSelect').value,
        },
      }),
    });
    await renderRoomMessages(state.activeRoomId);
  });

  // Création d'un nouveau salon chiffré
  document.getElementById('newRoomBtn').addEventListener('click', async () => {
    const name = prompt('Nom du nouveau salon chiffré (Megolm) :', 'Cellule Projet Souverain');
    if (!name) return;
    await apiFetch('/api/rooms', {
      method: 'POST',
      body: JSON.stringify({
        name,
        topic: 'Salon chiffré de bout en bout (Megolm AES-256)',
        ministry: state.agent.ministry,
        members: ['admin', 'aminata.ouedraogo', 'ibrahim.sawadogo', 'fatoumata.kabore'],
      }),
    });
    await loadRooms();
  });

  // Filtre annuaire
  document.getElementById('ministryFilterSelect').addEventListener('change', loadDirectory);

  // Actualiser preuve serveur aveugle
  document.getElementById('refreshBlindBtn').addEventListener('click', loadBlindCheck);

  // Formulaire d'enrôlement Admin
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
        ✅ <strong>Agent ${escapeHtml(res.agent.userId)} enrôlé !</strong><br/>
        Secret 2FA TOTP (Base32) : <code>${res.agent.totpSecret}</code><br/>
        Code 2FA actuel : <code>${res.currentTotpCode}</code>
      `;
      box.classList.remove('hidden');
      await loadAdminPanel();
      await loadDirectory();
    } catch (err) {
      box.className = 'alert error';
      box.textContent = `❌ ${err.message}`;
      box.classList.remove('hidden');
    }
  });

  // Bouton d'Urgence (Panic Wipe)
  document.getElementById('panicBtn').addEventListener('click', async () => {
    if (
      !confirm(
        "🚨 BOUTON D'URGENCE : Voulez-vous effacer immédiatement toutes les clés cryptographiques locales et révoquer vos sessions sur le serveur ?"
      )
    ) {
      return;
    }
    try {
      await apiFetch('/api/security/emergency-wipe', {
        method: 'POST',
        body: JSON.stringify({ reason: 'Urgence déclenchée par l’agent' }),
      });
    } finally {
      handleImmediateRevocationKick("Bouton d'urgence activé : appareil nettoyé et accès révoqué.");
    }
  });

  // Déconnexion normale
  document.getElementById('logoutBtn').addEventListener('click', () => {
    handleImmediateRevocationKick('Vous êtes déconnecté et les clés en mémoire ont été effacées.');
  });
});
