import './styles.css';
import { SecureMessenger } from './matrix';
import { I18N } from './i18n';
import { VoicePlayers } from './voice-player';
const voicePlayers = new VoicePlayers();

const $ = id => document.getElementById(id);
const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const initials = value => String(value || '?').split(/[\s.@]+/).filter(Boolean).slice(0, 2).map(s => s[0]).join('').toUpperCase();
const paths = {
  chat: '<path d="M21 14a3 3 0 0 1-3 3H8l-5 4V6a3 3 0 0 1 3-3h12a3 3 0 0 1 3 3z"/>',
  shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9S4 17 4 12V6z"/><path d="m8 12 3 3 5-6"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><path d="M12 14v3"/>',
  contacts: '<rect x="4" y="3" width="16" height="19" rx="2"/><circle cx="12" cy="9" r="3"/><path d="M7 18c0-5 10-5 10 0M2 7h3M2 12h3M2 17h3"/>',
  alert: '<path d="m12 3 10 18H2zM12 9v5M12 17h.01"/>',
  search: '<circle cx="10" cy="10" r="6"/><path d="m15 15 6 6"/>',
  compose: '<path d="M12 4H5a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h13a2 2 0 0 0 2-2v-7M16 3l5 5M10 14l-1 4 4-1L22 8l-4-4z"/>',
  arrow: '<path d="M4 12h16m-6-6 6 6-6 6"/>', back: '<path d="M20 12H4m6-6-6 6 6 6"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>', logout: '<path d="M9 3H4v18h5M9 12h12m-5-5 5 5-5 5"/>',
  key: '<circle cx="8" cy="8" r="5"/><path d="m12 12 9 9m-4-4 3-3m-6 0 3-3"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5M5 8a8 8 0 0 1 13-3l2 3M4 16l2 3a8 8 0 0 0 13-3"/>',
  attach: '<path d="m8 12 6-6a3 3 0 0 1 4 4L9 19a5 5 0 0 1-7-7L13 1m-7 12 9-9"/>',
  mic: '<rect x="9" y="2" width="6" height="13" rx="3"/><path d="M5 10v2a7 7 0 0 0 14 0v-2M12 19v3M8 22h8"/>',
  send: '<path d="m3 3 19 9-19 9 4-9zM7 12h15"/>',
  eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12"/><circle cx="12" cy="12" r="3"/>',
  file: '<path d="M14 2H5v20h14V7zM14 2v6h5M8 13h8M8 17h6"/>',
};
const icon = name => `<svg class="icon" aria-hidden="true" viewBox="0 0 24 24">${paths[name] || paths.shield}</svg>`;
function icons(root = document) { root.querySelectorAll('[data-icon]').forEach(el => { el.innerHTML = icon(el.dataset.icon); }); }
icons();
const state = { session: null, key: null, messenger: null, agents: [], ministries: [], requests: { incoming: [], outgoing: [] }, room: null, staged: null, recorder: null, view: 'messages', lang: localStorage.getItem('faso-language') || 'fr' };
let toastTimer, refreshTimer, renderQueued = false;
function notice(message) { $('toast').textContent = message; $('toast').classList.remove('hidden'); clearTimeout(toastTimer); toastTimer = setTimeout(() => $('toast').classList.add('hidden'), 6500); }
function error(error) { console.error(error); notice(error.message || 'Une erreur est survenue.'); }
function safe(fn) { return async event => { try { await fn(event); } catch (e) { error(e); } }; }
function busy(button, fn) { return async event => { event?.preventDefault(); button.disabled = true; try { await fn(event); } catch (e) { error(e); } finally { button.disabled = false; } }; }

async function keyStore(value) {
  const db = await new Promise((resolve, reject) => { const r = indexedDB.open('faso-session', 1); r.onupgradeneeded = () => r.result.createObjectStore('keys'); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
  return new Promise((resolve, reject) => { const tx = db.transaction('keys', value ? 'readwrite' : 'readonly'); const r = value ? tx.objectStore('keys').put(value, 'dpop') : tx.objectStore('keys').get('dpop'); tx.oncomplete = () => { resolve(r.result); db.close(); }; tx.onerror = () => { reject(tx.error); db.close(); }; });
}
function b64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
async function proof(method, pathname) {
  const jti = crypto.randomUUID(), iat = Math.floor(Date.now() / 1000), htm = method.toUpperCase(), htu = pathname;
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, state.key.privateKey, new TextEncoder().encode(`${jti}|${htm}|${htu}|${iat}`));
  return b64(new TextEncoder().encode(JSON.stringify({ jti, iat, htm, htu, sig: b64(signature) })));
}
async function transport(url, options = {}) {
  const target = new URL(url, location.origin);
  if (target.origin !== location.origin) throw new Error('Origine externe interdite.');
  const headers = new Headers(options.headers);
  if (state.session) { headers.set('Authorization', `Bearer ${state.session.portalToken}`); headers.set('X-Faso-DPoP', await proof(options.method || 'GET', target.pathname)); }
  const response = await fetch(target, { ...options, headers, credentials: 'same-origin' });
  if (response.status === 401 && state.session && !target.pathname.includes('/keys/device_signing/upload')) {
    const detail = await response.clone().json().catch(() => ({}));
    if (detail.error === 'SESSION_INVALID_OR_REVOKED' || detail.errcode === 'M_UNKNOWN_TOKEN') { signOut(); notice('Session expirée ou révoquée. Veuillez vous reconnecter.'); }
  }
  return response;
}
async function api(path, body, method) {
  const response = await transport(path, { method: method || (body ? 'POST' : 'GET'), headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const data = await response.json();
  if (!response.ok) throw Object.assign(new Error(data.message || data.error || 'Requête impossible.'), { status: response.status });
  return data;
}

function dialog(title, html, onSubmit, submitLabel = 'Confirmer') {
  if ($('dialog').open) $('dialog').close();
  $('dialog-title').textContent = title; $('dialog-body').innerHTML = html;
  $('dialog-submit').textContent = submitLabel; $('dialog-error').classList.add('hidden'); icons($('dialog'));
  $('dialog-form').onsubmit = async event => {
    event.preventDefault(); $('dialog-submit').disabled = true;
    try { await onSubmit(new FormData($('dialog-form'))); }
    catch (error) { $('dialog-error').textContent = error.message; $('dialog-error').classList.remove('hidden'); }
    finally { $('dialog-submit').disabled = false; }
  };
  $('dialog').showModal();
}
function ask(title, message, secret = false) {
  return new Promise(resolve => {
    dialog(title, `<p>${escape(message)}</p><input class="dialog-input" name="value" aria-label="${escape(title)}" type="${secret ? 'password' : 'text'}" autocomplete="off" required>`, data => { const value = data.get('value'); $('dialog').close(); resolve(value); });
    $('dialog').onclose = () => resolve(null);
  });
}
function confirm(title, message) {
  return new Promise(resolve => {
    dialog(title, `<p class="${message.includes(' · ') ? 'verification-sas' : ''}">${escape(message)}</p>`, () => { $('dialog').close(); resolve(true); });
    $('dialog').onclose = () => resolve(false);
  });
}
function showKey(key) {
  return new Promise((resolve, reject) => {
    dialog('Conservez votre clé de récupération', `<p>Copiez cette clé et conservez-la dans un lieu sûr, hors de cet appareil. Elle permet de retrouver vos messages.</p><code class="recovery-key">${escape(key)}</code><label class="check-row"><input type="checkbox" required> J’ai conservé ma clé de récupération.</label>`, () => { $('dialog').close(); resolve(); }, 'Activer la sauvegarde');
    $('dialog').onclose = () => reject(new Error('Configuration annulée.'));
  });
}
['dialog-close', 'dialog-cancel'].forEach(id => $(id).onclick = () => $('dialog').close());

$('show-password').onclick = () => { const hidden = $('password').type === 'password'; $('password').type = hidden ? 'text' : 'password'; $('show-password').setAttribute('aria-label', hidden ? 'Masquer le mot de passe' : 'Afficher le mot de passe'); };
$('back-login').onclick = () => { $('totp-form').classList.add('hidden'); $('login-form').classList.remove('hidden'); $('auth-error').classList.add('hidden'); };
$('login-form').onsubmit = async event => {
  event.preventDefault(); const button = event.submitter; button.disabled = true; $('auth-error').classList.add('hidden');
  try {
    if (!crypto.subtle) throw new Error('Un accès HTTPS ou localhost est nécessaire pour le chiffrement.');
    state.key = await keyStore();
    if (!state.key) { state.key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']); await keyStore(state.key); }
    const username = $('username').value.trim();
    const first = await api('/api/auth/login-step1', { username, password: $('password').value, deviceId: localStorage.getItem('faso-device:' + username.toLowerCase()) || undefined });
    state.challenge = first.challengeId; state.loginName = username.toLowerCase();
    $('password').value = ''; $('agent-preview').textContent = `${first.agentPreview.fullName} · ${first.agentPreview.ministry}`;
    $('qr-setup').classList.toggle('hidden', !first.isFirstSetup);
    if (first.isFirstSetup) { $('qr').innerHTML = first.qrSvg; $('totp-secret').textContent = first.totpSecret; }
    $('login-form').classList.add('hidden'); $('totp-form').classList.remove('hidden'); $('totp').value = ''; $('totp').focus();
  } catch (e) { $('auth-error').textContent = e.message; $('auth-error').classList.remove('hidden'); }
  finally { button.disabled = false; }
};
$('totp-form').onsubmit = async event => {
  event.preventDefault(); const button = event.submitter; button.disabled = true; $('auth-error').classList.add('hidden');
  try {
    state.session = await api('/api/auth/login-step2', { challengeId: state.challenge, totpCode: $('totp').value, dpopPublicJwk: await crypto.subtle.exportKey('jwk', state.key.publicKey), enableCookieBind: true });
    localStorage.setItem('faso-device:' + state.loginName, state.session.deviceId);
    sessionStorage.setItem('faso-session', JSON.stringify(state.session)); $('qr').innerHTML = ''; $('totp-secret').textContent = ''; $('totp').value = '';
    await enter();
  } catch (e) { $('auth-error').textContent = e.message; $('auth-error').classList.remove('hidden'); }
  finally { button.disabled = false; }
};

async function enter() {
  $('auth').classList.add('hidden'); $('workspace').classList.remove('hidden');
  const agent = state.session.agent;
  $('profile-name').textContent = agent.fullName; $('profile-avatar').textContent = initials(agent.fullName); $('device-id').textContent = state.session.deviceId;
  const privileged = ['ADMIN_SG', 'DIRECTEUR'].includes(agent.role);
  $('classification').querySelector('[value=CONFIDENTIEL]').disabled = !privileged; $('instruction-label').classList.toggle('hidden', !privileged);
  voicePlayers.destroy(); state.messenger?.stop();
  state.messenger = new SecureMessenger(state.session, transport, { error, notice, ask, confirm, showKey, changed: scheduleRender, trustChanged: () => updateTrust().catch(error), connection: status => {
    const online = ['PREPARED', 'SYNCING'].includes(status); $('connection').textContent = online ? 'E2EE · CONNECTÉ' : status === 'ERROR' || status === 'RECONNECTING' ? 'RECONNEXION…' : 'SYNCHRONISATION…'; $('connection').classList.toggle('online', online);
  } });
  try { await state.messenger.start(); await refreshDirectory(); await refreshRequests(); renderRooms(); await updateTrust(); }
  catch (e) { notice(e.message); $('connection').textContent = 'CONNEXION INTERROMPUE'; }
  clearInterval(refreshTimer);
  refreshTimer = setInterval(safe(async () => {
    if (!state.session) return;
    const seconds = Math.max(0, Math.ceil((state.session.sessionExpiresAt - Date.now()) / 1000));
    $('session-timer').textContent = `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
    if (!seconds) { signOut(); notice('Session expirée. Reconnectez-vous.'); return; }
    if (seconds % 15 === 0) { await api('/api/me'); await refreshRequests(); }
    if (state.room && state.messenger?.events(state.room).some(e => e.getContent().faso_meta?.expires_at)) { renderTimeline(); renderRooms(); }
  }), 1000);
}
function signOut() { clearInterval(refreshTimer); voicePlayers.destroy(); state.messenger?.stop(); state.messenger = null; state.session = null; state.room = null; sessionStorage.removeItem('faso-session'); $('workspace').classList.add('hidden'); $('auth').classList.remove('hidden'); $('back-login').click(); stopRecording(); }
$('logout').onclick = safe(async () => { await api('/api/auth/logout', {}); signOut(); });

function view(name) {
  state.view = name;
  ['messages', 'directory', 'security', 'actions'].forEach(v => { $('view-' + v).classList.toggle('hidden', v !== name); document.querySelector(`[data-view="${v}"]`).classList.toggle('active', v === name); });
  if (name === 'directory') refreshDirectory().catch(error);
  if (name === 'security') refreshSecurity().catch(error);
  if (name === 'actions') refreshRequests().catch(error);
}
document.querySelectorAll('[data-view]').forEach(el => el.onclick = () => view(el.dataset.view));
document.querySelectorAll('[data-go]').forEach(el => el.onclick = () => view(el.dataset.go));
$('requests-shortcut').onclick = () => view('actions');
$('toggle-details').onclick = () => { $('details').classList.toggle('open'); updateTrust().catch(error); };
$('close-details').onclick = () => $('details').classList.remove('open');
$('back-rooms').onclick = () => $('view-messages').classList.remove('chat-open');
document.addEventListener('keydown', event => { if ((event.ctrlKey || event.metaKey) && event.key === 'k') { event.preventDefault(); view('messages'); $('view-messages').classList.remove('chat-open'); $('room-search').focus(); } });
function scheduleRender() { if (renderQueued) return; renderQueued = true; setTimeout(() => { renderQueued = false; if (!state.messenger) return; renderRooms(); if (state.room) renderTimeline(); }, 80); }
function roomTitle(room) {
  const others = room.getJoinedMembers().filter(m => m.userId !== state.session.agent.userId);
  const direct = room.currentState.getStateEvents('bf.faso.room', '')?.getContent().isDirect;
  return direct && others.length === 1 ? state.agents.find(a => a.userId === others[0].userId)?.fullName || room.name : room.name;
}
function renderRooms() {
  if (!state.messenger?.client) return;
  const rooms = state.messenger.rooms(); const search = $('room-search').value.toLowerCase();
  $('rooms').innerHTML = rooms.filter(r => roomTitle(r).toLowerCase().includes(search)).map(room => {
    const events = room.getLiveTimeline().getEvents().filter(e => {
      const expiry = (e.getContent().faso_meta || e.getWireContent().faso_meta)?.expires_at;
      return (e.getType() === 'm.room.message' || e.isEncrypted()) && (!expiry || expiry > Date.now());
    });
    const last = events.at(-1)?.getContent();
    const preview = last?.faso_meta?.classification && last.faso_meta.classification !== 'NORMAL' ? 'Message classifié · ouvrir la conversation' : last?.msgtype === 'm.audio' ? 'Message vocal' : last?.body || (events.length ? 'Message chiffré' : 'Conversation prête à accueillir vos échanges');
    return `<button class="room-item ${state.room === room.roomId ? 'active' : ''}" data-room="${escape(room.roomId)}"><span class="avatar">${escape(initials(roomTitle(room)))}</span><span class="room-meta"><strong>${escape(roomTitle(room))}</strong><small>${escape(preview)}</small></span></button>`;
  }).join('') || `<div class="empty">${icon('chat')}<h3>Aucune conversation</h3><p>Contactez un agent depuis l’annuaire ou créez un canal.</p></div>`;
  $('rooms').querySelectorAll('[data-room]').forEach(button => button.onclick = () => selectRoom(button.dataset.room));
}
$('room-search').oninput = renderRooms;
function selectRoom(roomId) {
  state.room = roomId; view('messages'); $('view-messages').classList.add('chat-open');
  const room = state.messenger.client.getRoom(roomId); if (!room) return;
  $('room-name').textContent = roomTitle(room); $('room-avatar').textContent = initials(roomTitle(room));
  $('room-topic').textContent = room.currentState.getStateEvents('m.room.topic', '')?.getContent().topic || 'Conversation chiffrée de bout en bout';
  $('room-members').innerHTML = room.getJoinedMembers().map(m => { const name = state.agents.find(a => a.userId === m.userId)?.fullName || m.name; return `<div class="member"><span class="avatar">${escape(initials(name))}</span>${escape(name)}</div>`; }).join('');
  $('load-history').classList.remove('hidden'); renderRooms(); renderTimeline(true); loadReceipts().catch(error);
}
let receipts = [];
async function loadReceipts() { const id = state.room; const result = await api('/api/receipts?roomId=' + encodeURIComponent(id)); if (id === state.room) { receipts = result.receipts; renderTimeline(); } }
function renderTimeline(scroll = false) {
  if (!state.room || !state.messenger) return;
  const container = $('timeline'), atBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 80;
  const events = state.messenger.events(state.room).filter(e => e.isEncrypted() || e.getType() === 'm.room.message');
  let day = '';
  container.innerHTML = events.map(event => {
    const content = event.getContent(), wireMeta = event.getWireContent().faso_meta || {}, innerMeta = content.faso_meta || {};
    const meta = content.msgtype ? innerMeta : wireMeta;
    const normalize = m => JSON.stringify([m.classification || 'NORMAL', !!m.is_instruction, m.expires_at || null]);
    const mismatch = !event.status && content.msgtype && event.isEncrypted() && normalize(innerMeta) !== normalize(wireMeta);
    if (meta.expires_at && meta.expires_at <= Date.now()) return '';
    const mine = event.getSender() === state.session.agent.userId;
    const sender = state.agents.find(a => a.userId === event.getSender())?.fullName || event.getSender();
    const date = new Date(event.getTs()), label = date.toLocaleDateString('fr-FR', { weekday: 'long', day: 'numeric', month: 'long' });
    const separator = day !== label ? `<div class="day-label">${escape(label.toUpperCase())}</div>` : ''; day = label;
    const failed = mismatch || event.isDecryptionFailure() || content.msgtype === 'm.bad.encrypted' || !content.msgtype;
    let body = mismatch ? 'Message bloqué : les métadonnées chiffrées ne correspondent pas à l’enveloppe autorisée.' : failed ? `${icon('lock')} Message chiffré · clés indisponibles sur cet appareil. Utilisez la récupération ou la vérification d’appareil.` : `<span class="message-text">${escape(content.body)}</span>`;
    if (!failed && content.file) body = content.msgtype === 'm.audio'
      ? `<div data-voice="${escape(event.getId())}"></div>`
      : `<div class="file-card">${icon('file')}<div class="grow"><strong>${escape(content.filename || content.body)}</strong><br><small class="muted">${Math.ceil((content.info?.size || 0) / 1024)} Ko · Chiffré sur l’appareil</small></div><button class="icon-button" data-file="${escape(event.getId())}" aria-label="Télécharger et déchiffrer">${icon('arrow')}</button></div>`;
    const received = receipts.filter(r => r.eventId === event.getId());
    const instruction = meta.is_instruction ? `<div class="instruction-title">${icon('shield')} INSTRUCTION OFFICIELLE</div>` : '';
    const acknowledgment = meta.is_instruction && !failed ? `<footer><button class="primary" data-ack="${escape(event.getId())}" ${received.some(r => r.agentId === state.session.agent.userId) ? 'disabled' : ''}>${received.some(r => r.agentId === state.session.agent.userId) ? 'Lecture signée' : 'Signer la lecture'}</button><span class="receipts">${received.length} accusé(s) signé(s)</span></footer>` : '';
    return `${separator}<article class="message-row ${mine ? 'mine' : ''} ${meta.classification !== 'NORMAL' && meta.classification ? 'restricted' : ''} ${meta.classification === 'CONFIDENTIEL' ? 'confidential' : ''}"><div class="${meta.is_instruction ? 'instruction-box' : ''}">${instruction}<div class="message-bubble">${mine ? '' : `<span class="message-sender">${escape(sender)}</span>`}${body}</div>${acknowledgment}</div><div class="message-time">${date.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })}${meta.expires_at ? ` · expire dans ${Math.max(0, Math.ceil((meta.expires_at - Date.now()) / 1000))} s` : ''}${meta.classification && meta.classification !== 'NORMAL' ? ` · ${escape(meta.classification.replaceAll('_', ' '))}` : ''}${event.status ? ` · ${escape(event.status)}` : ''}</div></article>`;
  }).join('') || `<div class="empty">${icon('lock')}<h3>Le début de votre conversation</h3><p>Les messages et fichiers sont chiffrés sur vos appareils.</p></div>`;
  const visibleVocals = new Set();
  container.querySelectorAll('[data-voice]').forEach(placeholder => {
    const id = placeholder.dataset.voice; visibleVocals.add(id);
    voicePlayers.mount(placeholder, id, events.find(e => e.getId() === id).getContent(), content => state.messenger.attachment(content));
  });
  voicePlayers.retain(visibleVocals);
  container.querySelectorAll('[data-ack]').forEach(button => button.onclick = busy(button, async () => { await api('/api/receipts/acknowledge', { eventId: button.dataset.ack, roomId: state.room }); await loadReceipts(); }));
  container.querySelectorAll('[data-file]').forEach(button => button.onclick = busy(button, async () => {
    const event = events.find(e => e.getId() === button.dataset.file); const content = event.getContent(); const url = await state.messenger.attachment(content);
    const link = document.createElement('a'); link.href = url; link.download = content.filename || content.body; link.click();
  }));
  if (scroll || atBottom) container.scrollTop = container.scrollHeight;
}
$('load-history').onclick = busy($('load-history'), async () => { const room = state.messenger.client.getRoom(state.room); await state.messenger.client.scrollback(room, 50); renderTimeline(); });
function composeMeta() { const classification = $('classification').value, ttl = Number($('ttl').value) || (classification === 'CONFIDENTIEL' ? 300 : 0); return { classification, is_instruction: $('instruction').checked, expires_at: ttl ? Date.now() + ttl * 1000 : null }; }
$('classification').onchange = () => $('classification-notice').classList.toggle('hidden', $('classification').value === 'NORMAL');
$('composer').onsubmit = busy($('send'), async () => {
  if (!state.room) throw new Error('Sélectionnez une conversation.');
  if (!$('message').value.trim() && !state.staged) return;
  await state.messenger.send(state.room, { text: $('message').value.trim(), file: state.staged, meta: composeMeta() });
  $('message').value = ''; state.staged = null; renderStaged(); renderTimeline(true);
});
$('attach').onclick = () => $('attachment').click();
$('attachment').onchange = () => { state.staged = $('attachment').files[0] || null; $('attachment').value = ''; renderStaged(); };
function renderStaged() { $('staged').classList.toggle('hidden', !state.staged); $('staged').innerHTML = state.staged ? `${icon('file')}<span class="grow">${escape(state.staged.name)} · ${Math.ceil(state.staged.size / 1024)} Ko</span><button id="cancel-file" class="quiet">Retirer</button>` : ''; if ($('cancel-file')) $('cancel-file').onclick = () => { state.staged = null; renderStaged(); }; }
function stopRecording() { if (state.recorder) { state.recorder.cancelled = true; if (state.recorder.media.state !== 'inactive') state.recorder.media.stop(); state.recorder.stream.getTracks().forEach(t => t.stop()); clearInterval(state.recorder.timer); state.recorder = null; } $('recording').classList.add('hidden'); }
$('voice').onclick = safe(async () => {
  if (!state.room) throw new Error('Sélectionnez une conversation.');
  if (!navigator.mediaDevices || !window.MediaRecorder) throw new Error('Enregistrement vocal indisponible dans ce navigateur.');
  stopRecording(); const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  const media = new MediaRecorder(stream), chunks = [], start = Date.now(), roomId = state.room, meta = composeMeta();
  const recorder = { media, stream, cancelled: false }; state.recorder = recorder;
  media.ondataavailable = event => chunks.push(event.data);
  media.onstop = async () => { stream.getTracks().forEach(t => t.stop()); if (recorder.cancelled) return; try { await state.messenger.send(roomId, { file: new File(chunks, 'Note-vocale.webm', { type: media.mimeType }), voice: true, durationMs: Date.now() - start, meta }); renderTimeline(true); } catch (e) { error(e); } };
  media.start(); $('recording').classList.remove('hidden');
  recorder.timer = setInterval(() => { const sec = Math.floor((Date.now() - start) / 1000); $('recording-time').textContent = `${Math.floor(sec / 60)}:${String(sec % 60).padStart(2, '0')}`; if (sec >= 180) $('send-recording').click(); }, 1000);
});
$('cancel-recording').onclick = stopRecording;
$('send-recording').onclick = () => { if (!state.recorder) return; clearInterval(state.recorder.timer); state.recorder.media.stop(); state.recorder = null; $('recording').classList.add('hidden'); };

async function refreshDirectory() {
  const result = await api('/api/directory?ministry=ALL'); state.agents = result.agents; state.ministries = result.ministries;
  const value = $('ministry').value; $('ministry').innerHTML = '<option value="ALL">Tous les ministères</option>' + state.ministries.map(m => `<option value="${escape(m.code)}">${escape(m.shortName)}</option>`).join(''); $('ministry').value = value;
  renderDirectory(); renderRooms();
}
function renderDirectory() {
  const search = $('agent-search').value.toLowerCase(), ministry = $('ministry').value;
  const agents = state.agents.filter(a => (ministry === 'ALL' || a.ministry === ministry) && [a.fullName, a.direction, a.matricule, a.title].join(' ').toLowerCase().includes(search));
  $('directory-count').textContent = `${agents.length} AGENT(S)`;
  $('directory-grid').innerHTML = agents.map(agent => `<article class="card agent-card"><div class="agent-head"><span class="avatar">${escape(initials(agent.fullName))}</span><div class="grow"><h3>${escape(agent.fullName)}</h3><span class="tag">${escape(agent.ministry)}</span></div></div><div class="agent-info"><p>${escape(agent.title)}</p><p>${escape(agent.direction)}</p><p class="mono">${escape(agent.matricule)}</p></div><footer><span class="status ${agent.status !== 'ACTIVE' ? 'revoked' : ''}"><span class="dot"></span>${agent.status === 'ACTIVE' ? 'Accrédité' : 'Révoqué'}</span>${agent.localpart === state.session.agent.localpart ? '<span class="muted">Vous</span>' : `<button class="${agent.canMessageDirectly ? 'primary' : 'secondary'}" data-contact="${escape(agent.localpart)}" ${agent.status !== 'ACTIVE' || agent.pendingDirection === 'OUTGOING' ? 'disabled' : ''}>${agent.pendingDirection === 'OUTGOING' ? 'Demande envoyée' : agent.canMessageDirectly ? 'Message sécurisé' : agent.pendingDirection === 'INCOMING' ? 'Voir la demande' : 'Demander un contact'}</button>`}</footer></article>`).join('') || '<div class="empty">Aucun agent ne correspond à votre recherche.</div>';
  $('directory-grid').querySelectorAll('[data-contact]').forEach(button => button.onclick = busy(button, async () => {
    const agent = state.agents.find(a => a.localpart === button.dataset.contact);
    if (agent.pendingDirection === 'INCOMING') { view('actions'); return; }
    if (agent.canMessageDirectly) { const result = await api('/api/rooms/direct', { targetLocalpart: agent.localpart }); await openCreatedRoom(result.room_id); }
    else { const reason = await ask('Demande de contact sécurisé', `Motif de votre demande à ${agent.fullName} (${agent.ministry})`); if (reason) { await api('/api/contact-requests', { targetLocalpart: agent.localpart, reason }); await refreshDirectory(); notice('Demande de contact envoyée.'); } }
  }));
}
$('agent-search').oninput = renderDirectory; $('ministry').onchange = renderDirectory; $('refresh-directory').onclick = safe(refreshDirectory);
async function openCreatedRoom(roomId) { notice('Ouverture du salon chiffré…'); for (let i = 0; i < 30; i++) { if (state.messenger.client.getRoom(roomId)) { selectRoom(roomId); return; } await new Promise(r => setTimeout(r, 300)); } throw new Error('Salon créé. La synchronisation est en cours ; ouvrez-le dans la liste.'); }
$('new-room').onclick = () => {
  const members = state.agents.filter(a => a.status === 'ACTIVE' && a.canMessageDirectly && a.localpart !== state.session.agent.localpart);
  const requestId = crypto.randomUUID();
  dialog('Créer un canal chiffré', `<div class="form-grid"><label class="span2">Nom du canal<input name="name" required maxlength="100"></label><label class="span2">Objet<input name="topic" maxlength="250"></label><label class="span2">Participants<select name="members" multiple size="${Math.min(5, Math.max(2, members.length))}">${members.map(a => `<option value="${escape(a.localpart)}">${escape(a.fullName)}</option>`).join('')}</select></label></div>`, async data => { const result = await api('/api/rooms', { name: data.get('name'), topic: data.get('topic'), members: data.getAll('members'), isInstitutional: ['ADMIN_SG', 'DIRECTEUR'].includes(state.session.agent.role), requestId }); $('dialog').close(); await openCreatedRoom(result.room_id); }, 'Créer le canal');
};
async function refreshRequests() {
  state.requests = await api('/api/contact-requests'); $('requests-count').textContent = state.requests.incoming.length;
  $('requests').innerHTML = state.requests.incoming.map(r => `<div class="request-row"><span class="avatar">${escape(initials(r.fromFullName))}</span><div><strong>${escape(r.fromFullName)}</strong><small>${escape(r.fromMinistry)} · ${escape(r.reason)}</small></div><button data-reject="${escape(r.id)}" class="secondary">Refuser</button><button data-accept="${escape(r.id)}" class="primary">Accepter</button></div>`).join('') || '<p class="muted">Aucune demande en attente.</p>';
  $('requests').innerHTML += state.requests.outgoing.map(r => `<div class="request-row"><div><strong>${escape(r.toFullName)}</strong><small>Demande envoyée · ${escape(r.status)}</small></div></div>`).join('');
  $('requests').querySelectorAll('[data-accept],[data-reject]').forEach(button => button.onclick = busy(button, async () => { const id = button.dataset.accept || button.dataset.reject; await api(`/api/contact-requests/${encodeURIComponent(id)}/respond`, { action: button.dataset.accept ? 'ACCEPT' : 'REJECT' }); await refreshRequests(); await refreshDirectory(); }));
}
async function updateTrust() { if (!state.messenger?.client?.getCrypto()) return; const status = await state.messenger.trust(); const backup = await state.messenger.client.getCrypto().getActiveSessionBackupVersion(); $('trust-status').textContent = `${status?.isVerified() ? 'Appareil vérifié' : 'Appareil à vérifier'} · ${backup ? 'Sauvegarde des clés active' : 'Sauvegarde à configurer'}`; }
async function refreshSecurity() {
  const devices = await api('/api/security/devices');
  $('devices').innerHTML = devices.devices.map(d => `<div class="device-row"><span class="avatar">${icon('shield')}</span><div class="grow"><strong>${escape(d.display_name || d.device_id)} ${d.device_id === state.session.deviceId ? '· Cet appareil' : ''}</strong><small>${escape(d.device_id)} · ${d.last_seen_ts ? new Date(d.last_seen_ts).toLocaleString('fr-FR') : 'Date indisponible'}</small></div>${d.device_id !== state.session.deviceId ? `<button class="secondary" data-verify="${escape(d.device_id)}">Vérifier</button>` : ''}</div>`).join('');
  $('devices').querySelectorAll('[data-verify]').forEach(button => button.onclick = safe(() => state.messenger.verifyDevice(button.dataset.verify)));
  if (state.session.agent.role !== 'ADMIN_SG') { $('security-content').innerHTML = '<div class="card"><h2>Vos accès sont protégés</h2><p class="muted">La gestion des habilitations et le journal global sont réservés à l’administrateur de sécurité.</p><button class="secondary" id="personal-backup">Configurer la récupération des clés</button></div>'; $('personal-backup').onclick = safe(backup); return; }
  await refreshDirectory(); const report = await api('/api/security/blind-check');
  $('security-content').innerHTML = `<div class="stat-grid"><div class="card"><span>Agents accrédités</span><strong>${state.agents.filter(a => a.status === 'ACTIVE').length}</strong></div><div class="card"><span>Messages chiffrés stockés</span><strong>${report.event_types_summary?.['m.room.encrypted'] ?? '—'}</strong></div><div class="card"><span>Messages en clair détectés</span><strong>${report.clear_text_events_count ?? '—'}</strong></div></div><div class="security-columns"><div class="card"><div class="card-header"><h2>Agents enrôlés</h2><button id="enroll" class="primary">Enrôler un agent</button></div>${state.agents.map(a => `<div class="agent-admin"><span class="avatar">${escape(initials(a.fullName))}</span><div class="grow"><strong>${escape(a.fullName)}</strong><small>${escape(a.ministry)} · ${escape(a.role)} · ${escape(a.status)}</small></div>${a.localpart !== 'admin' && a.status === 'ACTIVE' ? `<button class="quiet danger" data-revoke="${escape(a.localpart)}">Révoquer</button>` : ''}</div>`).join('')}</div><div class="card"><div class="card-header"><h2>Journal de sécurité</h2><span class="tag">AUDIT</span></div>${report.audit_logs.map(a => `<div class="audit-entry"><span class="mono">${escape(new Date(a.timestamp).toLocaleString('fr-FR'))}</span><strong>${escape(a.action)} · ${escape(a.actor)}</strong><p>${escape(a.details)}</p></div>`).join('')}</div></div>`;
  $('enroll').onclick = enroll;
  $('security-content').querySelectorAll('[data-revoke]').forEach(button => button.onclick = safe(async () => { const agent = state.agents.find(a => a.localpart === button.dataset.revoke); if (await confirm('Révocation d’un agent accrédité', `Révoquer ${agent.fullName} ? Toutes ses sessions seront interrompues et son compte sera désactivé.`)) { await api('/api/admin/revoke', { localpart: agent.localpart }); await refreshSecurity(); notice('Compte révoqué.'); } }));
}
function enroll() {
  dialog('Enrôlement d’un nouvel agent', `<div class="form-grid"><label>Identifiant<input name="localpart" pattern="(?:[a-z0-9._]|-)+" required></label><label>Matricule<input name="matricule" required></label><label class="span2">Nom complet<input name="fullName" required></label><label>Ministère<select name="ministry">${state.ministries.map(m => `<option value="${escape(m.code)}">${escape(m.shortName)}</option>`).join('')}</select></label><label>Rôle<select name="role"><option value="AGENT_PUBLIC">Agent public</option><option value="DIRECTEUR">Directeur</option><option value="ADMIN_SG">Administrateur sécurité</option></select></label><label>Direction<input name="direction" required></label><label>Fonction<input name="title" required></label><label class="span2">Mot de passe initial<input name="password" type="password" minlength="12" autocomplete="new-password" required></label></div><p class="muted fine">L’agent configure lui-même son second facteur lors de sa première connexion.</p>`, async data => { await api('/api/admin/enroll', Object.fromEntries(data)); $('dialog').close(); await refreshSecurity(); notice('Agent enrôlé.'); }, 'Enrôler l’agent');
}
$('refresh-security').onclick = safe(refreshSecurity);
async function backup() { notice(await state.messenger.setupRecovery()); await updateTrust(); }
$('setup-recovery').onclick = safe(backup); $('actions-backup').onclick = safe(backup);
$('restore').onclick = safe(async () => { notice(await state.messenger.restore()); await updateTrust(); });
$('wipe').onclick = safe(async () => {
  if (!await confirm('Purge d’urgence du terminal', 'Cette opération désactive votre compte, coupe toutes vos sessions et efface les clés locales de ce navigateur. Elle ne peut pas être annulée ici. Confirmer la purge ?')) return;
  const messenger = state.messenger;
  let failure;
  try { await api('/api/security/emergency-wipe', { reason: 'Purge demandée par l’agent depuis le portail' }); } catch (e) { failure = e; }
  await messenger.wipe(); signOut();
  state.key = null;
  indexedDB.deleteDatabase('faso-session');
  notice(failure ? 'Clés locales effacées. Révocation serveur non confirmée : contactez votre administrateur.' : 'Clés locales effacées et compte révoqué.');
});

const translations = {
  fr: ['Messages', 'Annuaire', 'Sécurité', 'Actions critiques', 'Rédiger un message chiffré…', 'Annuaire interministériel'],
  mos: ['Koɛɛga', 'Sebre', 'Gũusgo', 'Yãgbo', 'Gʋls koɛɛga…', 'Ministɛɛr Tʋʋm-tʋmdb Sebre'],
  dyu: ['Batakiw', 'Tɔgɔsɛbɛn', 'Lakana', 'Balawo', 'Bataki sɛbɛn…', 'Minisiriso Baarakɛlaw Tɔgɔsɛbɛn'],
  ff: ['Nelal', 'Deftere', 'Ndeenka', 'Jaawngol', 'Winndu nelal…', 'Deftere Gollotooɓe Ministeeruuji'],
};
function language(lang) {
  state.lang = translations[lang] ? lang : 'fr'; localStorage.setItem('faso-language', state.lang);
  const t = translations[state.lang], dict = I18N[state.lang]; document.documentElement.lang = state.lang;
  $('language').value = state.lang; $('language-auth').value = state.lang;
  document.querySelectorAll('[data-view]').forEach((b, i) => { b.title = t[i]; b.setAttribute('aria-label', t[i]); });
  $('message').placeholder = dict.msg_placeholder; $('view-directory').querySelector('h1').textContent = dict.dir_title;
  document.querySelector('label[for=username]').textContent = dict.label_username;
  document.querySelector('label[for=password]').textContent = dict.label_password;
  document.querySelector('label[for=totp]').textContent = dict.label_totp;
  $('login-form').querySelector('button[type=submit]').firstChild.textContent = dict.btn_step1 + ' ';
  $('totp-form').querySelector('button[type=submit]').firstChild.textContent = dict.btn_step2 + ' ';
  $('view-directory').querySelector('.page-heading p').textContent = dict.dir_subtitle;
  $('classification').parentElement.firstChild.textContent = dict.label_classification + ' ';
  $('ttl').parentElement.firstChild.textContent = dict.label_ttl + ' ';
  $('send').setAttribute('aria-label', dict.btn_send);
}
$('language').onchange = e => language(e.target.value); $('language-auth').onchange = e => language(e.target.value); language(state.lang);

async function init() {
  const info = await api('/api/health');
  if (info.demoMode) { const data = await api('/api/demo/accounts'); $('demo').classList.remove('hidden'); $('demo-accounts').innerHTML = data.accounts.filter(a => a.status === 'ACTIVE').map(a => `<button type="button" data-demo="${escape(a.localpart)}">${escape(a.localpart)}</button>`).join(''); $('demo-accounts').querySelectorAll('button').forEach(b => b.onclick = () => { $('username').value = b.dataset.demo; $('password').value = data.demoPassword; }); }
  const session = sessionStorage.getItem('faso-session');
  if (session) { state.key = await keyStore(); state.session = JSON.parse(session); if (!state.key) signOut(); else { try { await api('/api/me'); await enter(); } catch { signOut(); } } }
}
init().catch(e => { $('auth-error').textContent = e.message; $('auth-error').classList.remove('hidden'); });
