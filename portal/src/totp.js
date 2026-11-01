/**
 * Module TOTP (Time-based One-Time Password) conforme à la RFC 6238 / RFC 4226 (HOTP).
 * Utilise uniquement le module standard 'crypto' de Node.js (HMAC-SHA1).
 *
 * Explication pour le jury :
 * 1. Le secret partagé (Base32) est décodé en octets.
 * 2. Le compteur de temps (Math.floor(Date.now() / 1000 / 30)) change toutes les 30 secondes.
 * 3. On calcule HMAC-SHA1(secret, compteur_sur_8_octets).
 * 4. On applique une troncature dynamique (Dynamic Truncation) pour extraire 4 octets
 *    et obtenir un code à 6 chiffres modulo 10^6.
 */
const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Génère un secret aléatoire encodé en Base32 (compatible Google Authenticator / FreeOTP).
 */
function generateBase32Secret(byteLength = 20) {
  const buf = crypto.randomBytes(byteLength);
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

/**
 * Décode une chaîne Base32 en Buffer d'octets.
 */
function decodeBase32(str) {
  const cleaned = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/**
 * Génère le code TOTP à 6 chiffres pour un secret et un horodatage donné.
 */
function generateTOTP(base32Secret, timestampMs = Date.now(), stepSeconds = 30) {
  const key = decodeBase32(base32Secret);
  const counter = Math.floor(timestampMs / 1000 / stepSeconds);

  // Compteur sur 8 octets Big-Endian (RFC 4226 section 5.1)
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter & 0xffffffff, 4);

  // Calcul HMAC-SHA1 standard
  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();

  // Troncature dynamique (Dynamic Truncation - RFC 4226 section 5.3)
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binary % 1000000;
  return String(otp).padStart(6, '0');
}

/**
 * Vérifie un code TOTP avec une tolérance de ±1 fenêtre de 30s (anti-décalage d'horloge).
 * Utilise timingSafeEqual pour éviter les attaques temporelles (Timing Attacks).
 */
function verifyTOTP(base32Secret, token, timestampMs = Date.now(), window = 1) {
  const cleanToken = String(token || '').trim();
  if (!/^\d{6}$/.test(cleanToken)) return false;

  const tokenBuf = Buffer.from(cleanToken, 'utf8');
  for (let errorWindow = -window; errorWindow <= window; errorWindow++) {
    const expected = generateTOTP(base32Secret, timestampMs + errorWindow * 30000);
    const expectedBuf = Buffer.from(expected, 'utf8');
    if (crypto.timingSafeEqual(tokenBuf, expectedBuf)) {
      return true;
    }
  }
  return false;
}

/**
 * Construit l'URI otpauth:// standard pour les applications d'authentification (FreeOTP, Aegis).
 */
function buildOtpAuthUri(localpart, base32Secret, issuer = 'FasoSouverain-DGTD') {
  const label = encodeURIComponent(`${issuer}:${localpart}`);
  const params = new URLSearchParams({
    secret: base32Secret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

module.exports = {
  generateBase32Secret,
  decodeBase32,
  generateTOTP,
  verifyTOTP,
  buildOtpAuthUri,
};

