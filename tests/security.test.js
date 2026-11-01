/**
 * Suite de Tests Automatisés des Fonctions de Sécurité (Bonus +2 points)
 * Exécution : node --test tests/security.test.js
 *
 * Couvre les 5 épreuves du jury et le socle de sécurité obligatoire :
 * 1. Authentification forte à 2 facteurs (TOTP RFC 6238)
 * 2. Épreuve « Intrus » : rejet immédiat d'un compte non enrôlé
 * 3. Épreuve « Le serveur ne lit rien » : rejet des messages en clair (`m.room.message`)
 *    et stockage exclusif de `m.room.encrypted` (Olm/Megolm)
 * 4. Contrôle d'accès par rôle (RBAC) sur les niveaux de classification (Confidentiel, Instructions)
 * 5. Accusé de lecture à valeur probante signé (HMAC-SHA256) et détection de falsification
 * 6. Épreuve « Révocation immédiate » : coupure instantanée des jetons et retrait des salons
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const { generateBase32Secret, generateTOTP, verifyTOTP } = require('../portal/src/totp');
const { createSignedReceipt, verifySignedReceipt } = require('../portal/src/receipts');
const { createNodeDPoPClientIdentity } = require('../portal/src/dpop');
const { SovereignPortalApp } = require('../portal/src/server');

test('1. Second facteur TOTP (RFC 6238) : génération, validation et rejet d’un code erroné', () => {
  const secret = generateBase32Secret(20);
  const now = 1730000000000;
  const code = generateTOTP(secret, now);

  assert.match(code, /^\d{6}$/, 'Le code TOTP doit comporter exactement 6 chiffres');
  assert.equal(verifyTOTP(secret, code, now), true, 'Le code TOTP courant doit être validé');
  assert.equal(
    verifyTOTP(secret, code, now + 29000),
    true,
    'La tolérance de fenêtre temporelle (±30s) doit fonctionner'
  );
  assert.equal(verifyTOTP(secret, '000000', now), false, 'Un code invalide doit être rejeté');
});

test('2. Épreuve Jury « Intrus » : un compte non enrôlé est immédiatement rejeté (HTTP 403)', async () => {
  const app = new SovereignPortalApp({ serverName: 'faso.gov.bf' });

  const res = await app.dispatchTestRequest('POST', '/api/auth/login-step1', {
    body: { username: 'intrus.non.enrole', password: 'Demo-Fictif-2026!' },
  });

  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error, 'INTRUS_REJETE');
});

test('3. Authentification complète 2FA + Épreuve « Le serveur ne lit rien » (0 message en clair)', async () => {
  const app = new SovereignPortalApp({ serverName: 'faso.gov.bf' });

  // Étape 1 : Mot de passe pour aminata.ouedraogo (Directrice)
  const step1Res = await app.dispatchTestRequest('POST', '/api/auth/login-step1', {
    body: { username: 'aminata.ouedraogo', password: 'Demo-Fictif-2026!' },
  });
  assert.equal(step1Res.status, 200);
  const step1Data = await step1Res.json();
  assert.equal(step1Data.step, 'SECOND_FACTOR_REQUIRED');

  // Étape 2 : Validation avec un mauvais code 2FA -> doit échouer (401)
  const badStep2 = await app.dispatchTestRequest('POST', '/api/auth/login-step2', {
    body: { challengeId: step1Data.challengeId, totpCode: '999999' },
  });
  assert.equal(badStep2.status, 401);

  // Étape 2 : Validation avec le bon code TOTP
  const step2Res = await app.dispatchTestRequest('POST', '/api/auth/login-step2', {
    body: {
      challengeId: step1Data.challengeId,
      totpCode: step1Data.demoTotpHint,
    },
  });
  assert.equal(step2Res.status, 200);
  const authData = await step2Res.json();
  const token = authData.portalToken;

  // Tentative d'envoyer un message en clair (m.room.message) -> DOIT ÊTRE BLOQUÉ PAR LE SERVEUR
  const roomId = '!canal-interministeriel:faso.gov.bf';
  const clearAttempt = await app.dispatchTestRequest(
    'POST',
    `/api/rooms/${encodeURIComponent(roomId)}/send-encrypted`,
    {
      headers: { Authorization: `Bearer ${token}` },
      body: {
        type: 'm.room.message',
        content: { msgtype: 'm.text', body: 'Message en clair interdit' },
      },
    }
  );
  assert.equal(clearAttempt.status, 400, 'Le serveur doit rejeter tout message en clair');

  // Envoi d'un évènement chiffré de bout en bout (m.room.encrypted)
  const encSend = await app.dispatchTestRequest(
    'POST',
    `/api/rooms/${encodeURIComponent(roomId)}/send-encrypted`,
    {
      headers: { Authorization: `Bearer ${token}` },
      body: {
        type: 'm.room.encrypted',
        content: {
          algorithm: 'm.megolm.v1.aes-sha2',
          session_id: 'megolm_test_session',
          ciphertext: 'U2FsdGVkX1+9x8y7z6a5b4c3d2e1f0==',
          iv: 'MTIzNDU2Nzg5MDEy',
          faso_meta: { classification: 'CONFIDENTIEL', is_instruction: true },
        },
        faso_meta: { classification: 'CONFIDENTIEL', is_instruction: true },
      },
    }
  );
  assert.equal(encSend.status, 200);

  // Inspection « Serveur Aveugle »
  const blindRes = await app.dispatchTestRequest('GET', '/api/security/blind-check', {
    headers: { Authorization: `Bearer ${token}` },
  });
  const blindData = await blindRes.json();
  assert.equal(blindData.status, 'BLIND_OK');
  assert.equal(blindData.clear_text_events_count, 0, 'Aucun message en clair ne doit exister');
  assert.ok(blindData.event_types_summary['m.room.encrypted'] >= 1);
});

test('4. Contrôle des Rôles (RBAC) : un Agent standard ne peut pas envoyer en niveau CONFIDENTIEL', async () => {
  const app = new SovereignPortalApp({ serverName: 'faso.gov.bf' });

  // Connexion de ibrahim.sawadogo (AGENT_PUBLIC)
  const s1 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step1', {
      body: { username: 'ibrahim.sawadogo', password: 'Demo-Fictif-2026!' },
    })
  ).json();
  const s2 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step2', {
      body: { challengeId: s1.challengeId, totpCode: s1.demoTotpHint },
    })
  ).json();

  const roomId = '!canal-interministeriel:faso.gov.bf';
  const forbiddenRes = await app.dispatchTestRequest(
    'POST',
    `/api/rooms/${encodeURIComponent(roomId)}/send-encrypted`,
    {
      headers: { Authorization: `Bearer ${s2.portalToken}` },
      body: {
        type: 'm.room.encrypted',
        content: {
          algorithm: 'm.megolm.v1.aes-sha2',
          ciphertext: 'Y2lwaGVydGV4dA==',
          iv: 'MTIzNDU2Nzg5MDEy',
        },
        faso_meta: { classification: 'CONFIDENTIEL' },
      },
    }
  );
  assert.equal(forbiddenRes.status, 403, 'Le niveau CONFIDENTIEL doit être refusé à AGENT_PUBLIC');
});

test('5. Épreuve Jury « Révocation immédiate » : un agent révoqué perd immédiatement son accès', async () => {
  const app = new SovereignPortalApp({ serverName: 'faso.gov.bf' });

  // 1. Connexion de fatoumata.kabore
  const f1 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step1', {
      body: { username: 'fatoumata.kabore', password: 'Demo-Fictif-2026!' },
    })
  ).json();
  const f2 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step2', {
      body: { challengeId: f1.challengeId, totpCode: f1.demoTotpHint },
    })
  ).json();

  // Vérifie que Fatoumata a bien accès à ses salons avant révocation
  const beforeRevoke = await app.dispatchTestRequest('GET', '/api/rooms', {
    headers: { Authorization: `Bearer ${f2.portalToken}` },
  });
  assert.equal(beforeRevoke.status, 200);

  // 2. Connexion de l'administrateur (admin)
  const a1 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step1', {
      body: { username: 'admin', password: 'Demo-Fictif-2026!' },
    })
  ).json();
  const a2 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step2', {
      body: { challengeId: a1.challengeId, totpCode: a1.demoTotpHint },
    })
  ).json();

  // 3. L'administrateur révoque fatoumata.kabore en direct
  const revokeRes = await app.dispatchTestRequest('POST', '/api/admin/revoke', {
    headers: { Authorization: `Bearer ${a2.portalToken}` },
    body: { localpart: 'fatoumata.kabore' },
  });
  assert.equal(revokeRes.status, 200);

  // 4. Fatoumata tente immédiatement de lire les salons ou d'envoyer un message -> HTTP 401 immédiat
  const afterRevoke = await app.dispatchTestRequest('GET', '/api/rooms', {
    headers: { Authorization: `Bearer ${f2.portalToken}` },
  });
  assert.equal(
    afterRevoke.status,
    401,
    'Le jeton de l’agent révoqué doit être invalidé immédiatement'
  );
});

test('6. Accusé de lecture à valeur probante : signature HMAC-SHA256 et détection de falsification', () => {
  const key = 'secret-etat-burkina-2026';
  const receipt = createSignedReceipt(
    {
      eventId: '$enc_12345',
      roomId: '!canal:faso.gov.bf',
      agentId: '@ibrahim.sawadogo:faso.gov.bf',
      matricule: 'BF-MEFP-3108',
      ministry: 'MEFP',
      timestampIso: '2026-11-01T08:00:00.000Z',
    },
    key
  );

  assert.equal(verifySignedReceipt(receipt, key), true);
  // Falsification du matricule
  const tampered = { ...receipt, matricule: 'BF-FAKE-9999' };
  assert.equal(verifySignedReceipt(tampered, key), false);
});

test('7. Cloisonnement inter-administrations et 2FA par courriel gouvernemental (.gov.bf)', async () => {
  const app = new SovereignPortalApp({ serverName: 'faso.gov.bf' });

  // Connexion de Aminata (MTDPCE) + vérification que le mail 2FA est bien délivré dans la boîte .gov.bf
  const a1 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step1', {
      body: { username: 'aminata.ouedraogo', password: 'Demo-Fictif-2026!' },
    })
  ).json();
  assert.equal(a1.deliveryChannel, 'EMAIL_GOV_BF');
  assert.equal(a1.sentToEmail, 'aminata.ouedraogo@mtdpce.gov.bf');

  const inboxRes = await (
    await app.dispatchTestRequest('GET', `/api/auth/webmail-inbox?email=${encodeURIComponent(a1.sentToEmail)}`)
  ).json();
  assert.ok(inboxRes.messages.length >= 1, 'Le courriel 2FA doit être présent dans la boîte gouvernementale');
  const emailOtp = inboxRes.messages[0].otpCode;

  const a2 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step2', {
      body: { challengeId: a1.challengeId, totpCode: emailOtp },
    })
  ).json();
  assert.equal(a2.status, 'AUTHENTICATED');
  assert.equal(a1.isFirstSetup, true, 'La 1ère connexion doit présenter le QR Code FreeOTP');
  assert.ok(a1.qrSvg && a1.qrSvg.includes('<svg'), 'Un vrai QR Code SVG doit être généré');
  assert.equal(a2.sessionMaxAgeSeconds, 1800, 'La session doit expirer au bout de 30 minutes (1800s)');

  // 2e connexion d'Aminata : le QR Code doit être définitivement scellé (isFirstSetup = false, qrSvg = null)
  const aSecondLogin = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step1', {
      body: { username: 'aminata.ouedraogo', password: 'Demo-Fictif-2026!' },
    })
  ).json();
  assert.equal(aSecondLogin.isFirstSetup, false, 'Le QR Code ne doit plus jamais être affiché après la 1ère connexion');
  assert.equal(aSecondLogin.qrSvg, null);
  assert.equal(aSecondLogin.totpSecret, null);

  // Aminata (MTDPCE) peut contacter directement Admin (même ministère MTDPCE)
  const sameMinRes = await app.dispatchTestRequest('POST', '/api/rooms/direct', {
    headers: { Authorization: `Bearer ${a2.portalToken}` },
    body: { targetLocalpart: 'admin' },
  });
  assert.equal(sameMinRes.status, 200);

  // Aminata (MTDPCE) tente de contacter directement Ibrahim (MEFP - autre administration) -> BLOQUÉ (403)
  const crossMinBlocked = await app.dispatchTestRequest('POST', '/api/rooms/direct', {
    headers: { Authorization: `Bearer ${a2.portalToken}` },
    body: { targetLocalpart: 'ibrahim.sawadogo' },
  });
  assert.equal(crossMinBlocked.status, 403, 'Le message direct inter-administration sans demande préalable doit être bloqué');

  // Aminata envoie une demande personnelle de contact à Ibrahim (MEFP)
  const reqCreated = await app.dispatchTestRequest('POST', '/api/contact-requests', {
    headers: { Authorization: `Bearer ${a2.portalToken}` },
    body: { targetLocalpart: 'ibrahim.sawadogo', reason: 'Dossier budgétaire MTDPCE-MEFP' },
  });
  assert.equal(reqCreated.status, 201);
  const reqData = await reqCreated.json();

  // Ibrahim (MEFP) se connecte et accepte la demande personnelle d'Aminata
  const i1 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step1', {
      body: { username: 'ibrahim.sawadogo', password: 'Demo-Fictif-2026!' },
    })
  ).json();
  const i2 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step2', {
      body: { challengeId: i1.challengeId, totpCode: i1.demoTotpHint },
    })
  ).json();

  const acceptRes = await app.dispatchTestRequest(
    'POST',
    `/api/contact-requests/${encodeURIComponent(reqData.request.id)}/respond`,
    {
      headers: { Authorization: `Bearer ${i2.portalToken}` },
      body: { action: 'ACCEPT' },
    }
  );
  assert.equal(acceptRes.status, 200);

  // Désormais, Aminata et Ibrahim peuvent échanger en message direct chiffré !
  const crossMinAllowed = await app.dispatchTestRequest('POST', '/api/rooms/direct', {
    headers: { Authorization: `Bearer ${a2.portalToken}` },
    body: { targetLocalpart: 'ibrahim.sawadogo' },
  });
  assert.equal(crossMinAllowed.status, 200);
});

test('8. Sécurité Niveau NASA (DPoP RFC 9449 + Cookie HttpOnly + Anti-Rejeu) : blocage des tokens/cookies volés', async () => {
  const app = new SovereignPortalApp({ serverName: 'faso.gov.bf' });
  const dpopClient = createNodeDPoPClientIdentity();

  // 1. Connexion d'Aminata avec liaison matérielle DPoP ECDSA P-256 + Cookie HttpOnly
  const step1 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step1', {
      headers: { 'User-Agent': 'FasoBrowser/1.0' },
      body: { username: 'aminata.ouedraogo', password: 'Demo-Fictif-2026!' },
    })
  ).json();

  const step2Res = await app.dispatchTestRequest('POST', '/api/auth/login-step2', {
    headers: { 'User-Agent': 'FasoBrowser/1.0' },
    body: {
      challengeId: step1.challengeId,
      totpCode: step1.demoTotpHint,
      dpopPublicJwk: dpopClient.publicJwk,
      enableCookieBind: true,
    },
  });
  assert.equal(step2Res.status, 200);
  const step2Data = await step2Res.json();
  assert.equal(step2Data.dpopBound, true);

  const setCookieHeader = step2Res.headers['Set-Cookie'] || '';
  assert.ok(setCookieHeader.includes('HttpOnly') && setCookieHeader.includes('SameSite=Strict'));
  const cookiePair = setCookieHeader.split(';')[0];

  // 2. Appel légitime avec Token + Cookie HttpOnly + Preuve DPoP signée ECDSA P-256 -> SUCCÈS (200)
  const validProof = dpopClient.signRequest('GET', '/api/rooms');
  const legitimateCall = await app.dispatchTestRequest('GET', '/api/rooms', {
    headers: {
      Authorization: `Bearer ${step2Data.portalToken}`,
      Cookie: cookiePair,
      'X-Faso-DPoP': validProof,
      'User-Agent': 'FasoBrowser/1.0',
    },
  });
  assert.equal(legitimateCall.status, 200);

  // 3. ATTAQUE 1 : Un pirate vole le Bearer Token et le Cookie mais n'a pas la clé privée non-extractible -> REJET (401)
  const attackerKey = createNodeDPoPClientIdentity();
  const forgedProof = attackerKey.signRequest('GET', '/api/rooms');
  const stolenTokenAttempt = await app.dispatchTestRequest('GET', '/api/rooms', {
    headers: {
      Authorization: `Bearer ${step2Data.portalToken}`,
      Cookie: cookiePair,
      'X-Faso-DPoP': forgedProof,
      'User-Agent': 'FasoBrowser/1.0',
    },
  });
  assert.equal(stolenTokenAttempt.status, 401, 'Un token volé sans la clé privée matérielle doit être rejeté');

  // 4. ATTAQUE 2 : Un pirate intercepte la requête légitime et tente de la REJOUER (Replay Attack) -> REJET & DESTRUCTION SESSION (401)
  const replayAttempt = await app.dispatchTestRequest('GET', '/api/rooms', {
    headers: {
      Authorization: `Bearer ${step2Data.portalToken}`,
      Cookie: cookiePair,
      'X-Faso-DPoP': validProof, // Même preuve rejouée !
      'User-Agent': 'FasoBrowser/1.0',
    },
  });
  assert.equal(replayAttempt.status, 401, 'Toute attaque par rejeu (même jti) doit être bloquée immédiatement');
});

test('9. Enrôlement Admin Zero-Knowledge : l’admin enregistre l’agent sans générer sa clé 2FA, l’agent la génère lui-même à sa 1ère connexion', async () => {
  const app = new SovereignPortalApp({ serverName: 'faso.gov.bf' });

  // 1. Connexion de l'administrateur
  const adm1 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step1', {
      body: { username: 'admin', password: 'Demo-Fictif-2026!' },
    })
  ).json();
  const adm2 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step2', {
      body: { challengeId: adm1.challengeId, totpCode: adm1.demoTotpHint },
    })
  ).json();

  // 2. L'admin enregistre un nouvel agent (moussa.zongo)
  const enrollRes = await app.dispatchTestRequest('POST', '/api/admin/enroll', {
    headers: { Authorization: `Bearer ${adm2.portalToken}` },
    body: {
      localpart: 'moussa.zongo',
      fullName: 'Moussa Zongo',
      ministry: 'MTDPCE',
      role: 'AGENT_PUBLIC',
      password: 'Demo-Fictif-2026!',
    },
  });
  assert.equal(enrollRes.status, 201);
  const enrollData = await enrollRes.json();

  // Vérifie que l'admin n'a reçu ni généré aucune clé 2FA
  assert.equal(enrollData.totpSecret, undefined, 'Aucune clé 2FA ne doit être retournée à l’administrateur');
  assert.equal(enrollData.agent.totpSecret, undefined, 'Aucune clé 2FA ne doit figurer dans l’objet agent retourné');
  assert.equal(app.directory.get('moussa.zongo').totpSecret, null, 'La clé 2FA doit rester null tant que l’agent ne s’est pas connecté');

  // 3. L'agent Moussa Zongo effectue sa toute première connexion : sa clé et son QR Code sont générés à cet instant
  const m1 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step1', {
      body: { username: 'moussa.zongo', password: 'Demo-Fictif-2026!' },
    })
  ).json();
  assert.equal(m1.isFirstSetup, true);
  assert.ok(m1.qrSvg && m1.qrSvg.includes('<svg'), 'Le QR Code FreeOTP est généré pour l’agent à sa 1ère connexion');
  assert.ok(app.directory.get('moussa.zongo').totpSecret, 'La clé 2FA est maintenant générée par l’agent');

  // Validation du 1er code OTP par l'agent -> scelle définitivement le QR Code
  const m2 = await (
    await app.dispatchTestRequest('POST', '/api/auth/login-step2', {
      body: { challengeId: m1.challengeId, totpCode: m1.demoTotpHint },
    })
  ).json();
  assert.equal(m2.status, 'AUTHENTICATED');
  assert.equal(app.directory.get('moussa.zongo').totpEnrolled, true);
});



