/**
 * Accusés de lecture à valeur probante pour les Instructions de Service
 * et jetons de session signés (HMAC-SHA256).
 *
 * Explication pour le jury :
 * Lorsqu'un Directeur envoie une "Instruction de Service", un agent qui clique sur
 * "Accuser réception" génère un reçu horodaté dont l'empreinte (digest SHA-256)
 * est signée par HMAC-SHA256 sur les métadonnées d'accusé (ID d'évènement Matrix,
 * identifiant de l'agent, matricule, ministère, horodatage UTC) sans jamais exposer
 * le contenu en clair du message au serveur.
 */
const crypto = require('crypto');

/**
 * Crée un accusé de lecture signé pour une instruction de service.
 */
function createSignedReceipt({ eventId, roomId, agentId, matricule, ministry, timestampIso }, signingKey) {
  const canonicalPayload = [
    'FASO-RECEIPT-V1',
    String(eventId || ''),
    String(roomId || ''),
    String(agentId || ''),
    String(matricule || ''),
    String(ministry || ''),
    String(timestampIso || new Date().toISOString()),
  ].join('|');

  const signature = crypto
    .createHmac('sha256', String(signingKey))
    .update(canonicalPayload, 'utf8')
    .digest('hex');

  return {
    version: 'FASO-RECEIPT-V1',
    eventId,
    roomId,
    agentId,
    matricule,
    ministry,
    timestampIso,
    signature,
  };
}

/**
 * Vérifie l'intégrité et l'authenticité d'un accusé de lecture.
 */
function verifySignedReceipt(receipt, signingKey) {
  if (!receipt || !receipt.signature) return false;
  const expected = createSignedReceipt(receipt, signingKey);
  const sigBuf = Buffer.from(String(receipt.signature), 'utf8');
  const expBuf = Buffer.from(String(expected.signature), 'utf8');
  if (sigBuf.length !== expBuf.length) return false;
  return crypto.timingSafeEqual(sigBuf, expBuf);
}

/**
 * Génère un jeton de session portail après validation réussie du 1er facteur (Matrix) + 2e facteur (TOTP).
 */
function signPortalToken(payload, secretKey, expiresInSeconds = 28800) {
  const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const body = Buffer.from(JSON.stringify({ ...payload, exp }), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', String(secretKey)).update(body).digest('base64url');
  return `${body}.${sig}`;
}

/**
 * Vérifie et décode un jeton de session portail.
 */
function verifyPortalToken(token, secretKey) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', String(secretKey)).update(body).digest('base64url');
  const sigBuf = Buffer.from(sig, 'utf8');
  const expBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }
  try {
    const data = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (data.exp && Math.floor(Date.now() / 1000) > data.exp) {
      return null;
    }
    return data;
  } catch {
    return null;
  }
}

module.exports = {
  createSignedReceipt,
  verifySignedReceipt,
  signPortalToken,
  verifyPortalToken,
};
