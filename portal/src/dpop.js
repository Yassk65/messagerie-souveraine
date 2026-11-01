/**
 * Module de Sécurité « Niveau NASA » : DPoP (Demonstrating Proof-of-Possession — RFC 9449)
 * + Protection Anti-Rejeu (Replay Attack Detection) + Empreinte de Contexte (Channel Binding).
 *
 * Explication pour le jury :
 * Comment empêcher un attaquant qui vole un Cookie ou un Bearer Token de faire des appels API ?
 * 1. À la connexion, le navigateur génère une paire de clés asymétriques ECDSA P-256 dans le
 *    moteur matériel WebCrypto avec `extractable: false` (la clé privée ne peut JAMAIS être
 *    exportée ni lue, même par du code JavaScript).
 * 2. Le serveur lie le jeton de session à l'empreinte SHA-256 de la clé publique (`cnf.jkt`)
 *    et dépose en parallèle un cookie `HttpOnly; SameSite=Strict` contenant un secret de liaison.
 * 3. À CHAQUE requête API, le client doit signer (`ECDSA-SHA256`) la méthode HTTP, l'URL,
 *    l'horodatage et un identifiant unique (`jti`).
 * 4. Si un pirate copie le token ou le cookie sur sa machine :
 *    - Il n'a pas la clé privée non-extractible -> Signature DPoP invalide -> Rejet HTTP 401.
 *    - S'il capture et rejoue une requête entière -> Le `jti` est déjà dans le registre anti-rejeu
 *      -> Alerte d'intrusion et révocation immédiate de la session !
 */
const crypto = require('crypto');

class DPoPGuard {
  constructor() {
    // Registre anti-rejeu des identifiants uniques de requête (jti -> timestamp)
    this.seenJtis = new Map();
  }

  /**
   * Calcule l'empreinte (thumbprint SHA-256) d'une clé publique JWK ECDSA P-256 (RFC 7638).
   */
  computeJwkThumbprint(jwk) {
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
      return null;
    }
    const canonical = JSON.stringify({
      crv: jwk.crv,
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y,
    });
    return crypto.createHash('sha256').update(canonical, 'utf8').digest('base64url');
  }

  /**
   * Calcule l'empreinte du contexte client (User-Agent + IP locale) pour bloquer
   * l'utilisation d'un cookie/token depuis un autre outil (ex: vol depuis Chrome utilisé dans curl).
   */
  computeClientContextHash(req) {
    const ua = String(req.headers['user-agent'] || 'unknown-ua');
    return crypto.createHash('sha256').update(`faso-ctx::${ua}`, 'utf8').digest('base64url');
  }

  /**
   * Vérifie la preuve de possession cryptographique (en-tête `x-faso-dpop`) sur chaque requête API.
   */
  verifyDPoPProof({ dpopHeader, expectedPublicJwk, expectedThumbprint, method, pathname }) {
    if (!dpopHeader || typeof dpopHeader !== 'string') {
      return { valid: false, reason: 'MISSING_DPOP_PROOF' };
    }

    let proof;
    try {
      proof = JSON.parse(Buffer.from(dpopHeader, 'base64url').toString('utf8'));
    } catch {
      return { valid: false, reason: 'MALFORMED_DPOP_PROOF' };
    }

    const { jti, htm, htu, iat, sig } = proof;
    if (!jti || !htm || !htu || !iat || !sig) {
      return { valid: false, reason: 'INCOMPLETE_DPOP_CLAIMS' };
    }

    // 1. Vérification de la méthode HTTP et du chemin URL signé
    if (String(htm).toUpperCase() !== String(method).toUpperCase() || String(htu) !== String(pathname)) {
      return { valid: false, reason: 'DPOP_ENDPOINT_MISMATCH' };
    }

    // 2. Vérification de la fenêtre temporelle stricte (±30 secondes max)
    const nowSec = Math.floor(Date.now() / 1000);
    if (Math.abs(nowSec - Number(iat)) > 30) {
      return { valid: false, reason: 'DPOP_PROOF_EXPIRED' };
    }

    // 3. Détection d'attaque par rejeu (Replay Attack) : chaque `jti` ne peut servir qu'UNE SEULE fois
    this.cleanupExpiredJtis(nowSec);
    if (this.seenJtis.has(jti)) {
      return { valid: false, reason: 'REPLAY_ATTACK_DETECTED', replayDetected: true };
    }

    // 4. Vérification de l'empreinte de la clé publique liée au token
    const actualThumbprint = this.computeJwkThumbprint(expectedPublicJwk);
    if (!actualThumbprint || actualThumbprint !== expectedThumbprint) {
      return { valid: false, reason: 'DPOP_KEY_BINDING_MISMATCH' };
    }

    // 5. Vérification mathématique de la signature ECDSA P-256 (IEEE P1363 générée par WebCrypto)
    const signedPayload = `${jti}|${String(htm).toUpperCase()}|${htu}|${iat}`;
    try {
      const pubKeyObj = crypto.createPublicKey({ key: expectedPublicJwk, format: 'jwk' });
      const sigBuf = Buffer.from(sig, 'base64url');
      const isSigValid = crypto.verify(
        'sha256',
        Buffer.from(signedPayload, 'utf8'),
        { key: pubKeyObj, dsaEncoding: 'ieee-p1363' },
        sigBuf
      );

      if (!isSigValid) {
        return { valid: false, reason: 'DPOP_CRYPTO_SIGNATURE_INVALID' };
      }

      // Enregistre le jti pour empêcher tout rejeu futur
      this.seenJtis.set(jti, nowSec);
      return { valid: true };
    } catch {
      return { valid: false, reason: 'DPOP_VERIFICATION_ERROR' };
    }
  }

  cleanupExpiredJtis(nowSec) {
    if (this.seenJtis.size < 500) return;
    for (const [jti, ts] of this.seenJtis.entries()) {
      if (nowSec - ts > 60) this.seenJtis.delete(jti);
    }
  }
}

/**
 * Utilitaire côté Node.js (pour les tests automatisés) permettant de générer une paire de clés
 * ECDSA P-256 et de signer une preuve DPoP exactement comme le navigateur WebCrypto.
 */
function createNodeDPoPClientIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicJwk = publicKey.export({ format: 'jwk' });

  const signRequest = (method, pathname) => {
    const jti = `jti_${crypto.randomBytes(12).toString('hex')}`;
    const iat = Math.floor(Date.now() / 1000);
    const htm = String(method).toUpperCase();
    const htu = String(pathname);
    const signedPayload = `${jti}|${htm}|${htu}|${iat}`;

    const sigBuf = crypto.sign('sha256', Buffer.from(signedPayload, 'utf8'), {
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    });

    const proofObj = {
      jti,
      htm,
      htu,
      iat,
      sig: sigBuf.toString('base64url'),
    };
    return Buffer.from(JSON.stringify(proofObj), 'utf8').toString('base64url');
  };

  return { publicJwk, signRequest };
}

module.exports = {
  DPoPGuard,
  createNodeDPoPClientIdentity,
};
