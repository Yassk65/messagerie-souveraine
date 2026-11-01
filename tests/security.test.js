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
