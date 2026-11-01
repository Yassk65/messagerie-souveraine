/**
 * Serveur Portail Souverain & Passerelle de Sécurité (FasoSouverain - MTDPCE / DGTD)
 *
 * Responsabilités :
 * 1. Authentification forte à 2 facteurs :
 *    - Facteur 1 : Authentification Matrix Synapse (`/_matrix/client/v3/login`)
 *    - Facteur 2 : Code TOTP à 6 chiffres (RFC 6238)
 * 2. Gestion des Rôles (RBAC) et Annuaire Officiel par Ministère
 * 3. Révocation immédiate d'un agent (API Admin Synapse + coupure instantanée des sessions)
 * 4. Accusés de lecture à valeur probante (signés par HMAC-SHA256) pour les Instructions de Service
 * 5. Vérification en direct pour le jury (« Le serveur ne lit rien » : 0 message en clair)
 * 6. Distribution de l'interface web multilingue (Français, Mooré, Dioula, Fulfuldé)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const {
  generateBase32Secret,
  generateTOTP,
  verifyTOTP,
  buildOtpAuthUri,
} = require('./totp');
const {
  MINISTRIES,
  ROLES,
  CLASSIFICATIONS,
  DEFAULT_DEMO_AGENTS,
  hasPermission,
  canUseClassification,
} = require('./roles');
const {
  createSignedReceipt,
  verifySignedReceipt,
  signPortalToken,
  verifyPortalToken,
} = require('./receipts');
const { EmbeddedMatrixEngine } = require('./matrix_engine');
const { SovereignEmail2FAService } = require('./mailer');
const { generateQrSvg } = require('./qrcode');
const { DPoPGuard } = require('./dpop');

class SovereignPortalApp {
  constructor(options = {}) {
    this.serverName = options.serverName || process.env.SERVER_NAME || 'localhost';
    this.synapseUrl = options.synapseUrl || process.env.SYNAPSE_INTERNAL_URL || '';
    this.signingKey =
      options.signingKey ||
      process.env.PORTAL_SIGNING_KEY ||
      crypto.randomBytes(32).toString('hex');

    // Moteur Matrix (intégré et synchronisé avec Synapse)
    this.matrix = new EmbeddedMatrixEngine(this.serverName);

    // Service d'envoi de code 2FA par courriel gouvernemental (.gov.bf)
    this.mailer = new SovereignEmail2FAService();

    // Protection DPoP (RFC 9449) & Anti-Rejeu (empêche l'utilisation d'un cookie/token volé)
    this.dpopGuard = new DPoPGuard();
    this.dpopBoundSessions = new Map(); // sessionId -> { publicJwk, jkt, cookieBindHash, ctxHash }

    // Annuaire officiel des agents enrôlés : localpart -> fiche agent
    this.directory = new Map();
    for (const agent of DEFAULT_DEMO_AGENTS) {
      this.directory.set(agent.localpart, {
        ...agent,
        email: agent.email || `${agent.localpart}@${agent.ministry.toLowerCase()}.gov.bf`,
        userId: `@${agent.localpart}:${this.serverName}`,
        totpEnrolled: false, // Scellé à true dès la fin de la 1ère connexion (le QR code n'est plus jamais affiché)
        enrolledAt: new Date(Date.now() - 86400000).toISOString(),
      });
    }

    // Sessions pré-authentifiées en attente du 2e facteur (Email OTP + TOTP)
    this.pendingSecondFactor = new Map(); // challengeId -> { localpart, emailOtpCode, matrixSession, expiresAt }

    // Demandes personnelles de communication inter-administration (Cloisonnement par Ministère)
    this.contactRequests = new Map(); // reqId -> { id, fromLocalpart, toLocalpart, fromMinistry, toMinistry, reason, status, createdAt }
    this.approvedContacts = new Set(); // Set de paires triées "agentA|agentB"

    // Registre des accusés de lecture à valeur probante : eventId -> Array<Receipt>
    this.probativeReceipts = new Map();

    // Journal d'audit de sécurité (sans métadonnées de contenu)
    this.auditLogs = [
      {
        id: 'audit-init-1',
        timestamp: new Date().toISOString(),
        action: 'SYSTEM_BOOT',
        actor: 'system',
        details: 'Socle souverain initialisé : E2EE forcé (Olm/Megolm), 2FA TOTP actif, fédération désactivée.',
      },
    ];
  }

  logAudit(action, actor, details) {
    this.auditLogs.unshift({
      id: `audit-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
      timestamp: new Date().toISOString(),
      action,
      actor,
      details,
    });
    if (this.auditLogs.length > 100) this.auditLogs.pop();
  }

  pairKey(localA, localB) {
    return [String(localA).toLowerCase(), String(localB).toLowerCase()].sort().join('|');
  }

  /**
   * Cloisonnement par administration :
   * Deux agents peuvent communiquer directement s'ils appartiennent au MÊME Ministère/Administration,
   * OU si une demande de contact personnelle inter-administration a été acceptée.
   */
  canCommunicateDirectly(agentA, agentB) {
    if (!agentA || !agentB) return false;
    if (agentA.localpart === agentB.localpart) return true;
    if (agentA.ministry === agentB.ministry) return true;
    return this.approvedContacts.has(this.pairKey(agentA.localpart, agentB.localpart));
  }

  /**
   * Tente d'appeler le serveur Synapse réel s'il est joignable en réseau Docker,
   * et maintient la cohérence avec le moteur Matrix embarqué.
   */
  async callSynapseIfConfigured(endpointPath, method = 'GET', body = null, bearerToken = null) {
    if (!this.synapseUrl) return null;
    try {
      const headers = { 'Content-Type': 'application/json' };
      if (bearerToken) headers['Authorization'] = `Bearer ${bearerToken}`;
      const res = await fetch(`${this.synapseUrl}${endpointPath}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      });
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, data };
    } catch {
      return null;
    }
  }

  parseCookies(req) {
    const raw = req.headers['cookie'] || '';
    const out = {};
    for (const part of raw.split(';')) {
      const idx = part.indexOf('=');
      if (idx > -1) {
        const k = part.slice(0, idx).trim();
        const v = part.slice(idx + 1).trim();
        out[k] = v;
      }
    }
    return out;
  }

  authenticateRequest(req, pathname = '') {
    const authHeader = req.headers['authorization'] || '';
    if (!authHeader.startsWith('Bearer ')) return null;
    const token = authHeader.slice(7).trim();
    const payload = verifyPortalToken(token, this.signingKey);
    if (!payload) return null;

    // Vérifie que l'agent n'a pas été révoqué entre-temps !
    const agent = this.directory.get(payload.localpart);
    if (!agent || agent.status !== 'ACTIVE') return null;

    // Vérifie que le token Matrix sous-jacent est toujours actif
    const matrixValid = this.matrix.verifyAccessToken(payload.matrixAccessToken);
    if (!matrixValid) return null;

    // --- VÉRIFICATION SÉCURITÉ « NIVEAU NASA » (DPoP RFC 9449 + Cookie HttpOnly + Anti-Rejeu) ---
    if (payload.cnf && payload.cnf.jkt && payload.sid) {
      const bound = this.dpopBoundSessions.get(payload.sid);
      if (!bound) return null;

      // 1. Vérifie le cookie HttpOnly __Host-FasoBind (si envoyé par un navigateur)
      if (bound.cookieBindHash) {
        const cookies = this.parseCookies(req);
        const cookieSecret = cookies['FasoHostBind'] || '';
        const actualHash = crypto.createHash('sha256').update(cookieSecret, 'utf8').digest('hex');
        if (!cookieSecret || actualHash !== bound.cookieBindHash) {
          this.logAudit(
            'TOKEN_THEFT_BLOCKED_COOKIE_MISMATCH',
            payload.localpart,
            'Tentative d’utilisation d’un Bearer Token volé sans le Cookie matériel HttpOnly correspondant !'
          );
          return null;
        }
      }

      // 2. Vérifie l'empreinte de contexte (User-Agent)
      const currentCtx = this.dpopGuard.computeClientContextHash(req);
      if (bound.ctxHash && currentCtx !== bound.ctxHash) {
        this.logAudit(
          'TOKEN_THEFT_BLOCKED_CONTEXT_MISMATCH',
          payload.localpart,
          'Tentative d’utilisation d’une session depuis un navigateur/outil différent !'
        );
        return null;
      }

      // 3. Vérifie la signature cryptographique ECDSA P-256 à usage unique (x-faso-dpop)
      const dpopHeader = req.headers['x-faso-dpop'] || '';
      const dpopCheck = this.dpopGuard.verifyDPoPProof({
        dpopHeader,
        expectedPublicJwk: bound.publicJwk,
        expectedThumbprint: payload.cnf.jkt,
        method: req.method,
        pathname,
      });

      if (!dpopCheck.valid) {
        this.logAudit(
          'DPOP_ATTACK_BLOCKED',
          payload.localpart,
          `Requête API bloquée par DPoP (${dpopCheck.reason}) sur ${req.method} ${pathname}`
        );
        // En cas d'attaque par rejeu détectée, détruit immédiatement la session !
        if (dpopCheck.replayDetected) {
          this.dpopBoundSessions.delete(payload.sid);
        }
        return null;
      }
    }

    return { ...payload, agent };
  }

  async handleApi(req, res, pathname, parsedUrl) {
    const sendJson = (status, data, extraHeaders = {}) => {
      res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none';",
        ...extraHeaders,
      });
      res.end(JSON.stringify(data));
    };

    const readBody = () =>
      new Promise((resolve, reject) => {
        if (req._DirectBody !== undefined) {
          return resolve(req._DirectBody);
        }
        let raw = '';
        req.on('data', (chunk) => {
          raw += chunk;
          if (raw.length > 15 * 1024 * 1024) reject(new Error('Payload trop volumineux (max 15 Mo)'));
        });
        req.on('end', () => {
          if (!raw) return resolve({});
          try {
            resolve(JSON.parse(raw));
          } catch {
            reject(new Error('JSON invalide'));
          }
        });
      });

    try {
      // 1. Santé & Informations Souveraines
      if (pathname === '/api/health' && req.method === 'GET') {
        return sendJson(200, {
          status: 'OK',
          service: 'Messagerie Souveraine du Burkina Faso (MTDPCE / DGTD)',
          protocol: 'Matrix E2EE (Olm / Megolm AES-256 + WebCrypto)',
          secondFactor: 'TOTP RFC 6238 (HMAC-SHA1)',
          federation: false,
          registrationOpen: false,
          serverName: this.serverName,
        });
      }

      // 2. Aide Démo Jury : obtenir les comptes fictifs et leurs codes TOTP temps-réel
      if (pathname === '/api/demo/accounts' && req.method === 'GET') {
        const list = [];
        for (const agent of this.directory.values()) {
          list.push({
            localpart: agent.localpart,
            userId: agent.userId,
            fullName: agent.fullName,
            matricule: agent.matricule,
            ministry: agent.ministry,
            direction: agent.direction,
            title: agent.title,
            role: agent.role,
            roleLabel: ROLES[agent.role]?.label || agent.role,
            status: agent.status,
            currentTotpDemo:
              agent.status !== 'ACTIVE'
                ? 'RÉVOQUÉ'
                : agent.totpSecret
                  ? generateTOTP(agent.totpSecret)
                  : 'À générer à la 1ère connexion',
          });
        }
        return sendJson(200, {
          demoPassword: process.env.DEMO_PASSWORD || 'Demo-Fictif-2026!',
          accounts: list,
          ministries: MINISTRIES,
          roles: ROLES,
          classifications: CLASSIFICATIONS,
        });
      }

      // 3. Étape 1 de Connexion : Vérification de l'enrôlement + Mot de passe Matrix
      if (pathname === '/api/auth/login-step1' && req.method === 'POST') {
        const body = await readBody();
        const rawInput = String(body.username || '').trim();
        let cleanLocal = rawInput
          .replace(/^@/, '')
          .split(':')[0]
          .split('@')[0]
          .toLowerCase();

        // Permet aussi de se connecter avec le Matricule (ex: BF-DGTD-0001) ou l'email complet
        let agent = this.directory.get(cleanLocal);
        if (!agent) {
          for (const candidate of this.directory.values()) {
            if (
              candidate.matricule?.toLowerCase() === rawInput.toLowerCase() ||
              candidate.email?.toLowerCase() === rawInput.toLowerCase()
            ) {
              agent = candidate;
              cleanLocal = candidate.localpart;
              break;
            }
          }
        }

        const password = String(body.password || '');

        if (!agent) {
          this.logAudit('INTRUSION_BLOCKED', cleanLocal || 'inconnu', 'Tentative de connexion par un compte non enrôlé');
          return sendJson(403, {
            error: 'INTRUS_REJETE',
            message: `Accès rejeté : l'identifiant "${rawInput}" n'est pas enrôlé dans l'annuaire souverain de l'administration.`,
          });
        }

        if (agent.status !== 'ACTIVE') {
          this.logAudit('REVOKED_LOGIN_ATTEMPT', cleanLocal, 'Tentative de connexion d’un agent révoqué');
          return sendJson(403, {
            error: 'AGENT_REVOQUE',
            message: `Accès refusé : le compte de l'agent ${agent.fullName} (${agent.matricule}) a été révoqué.`,
          });
        }

        // Vérification sur le moteur Matrix (et Synapse si présent)
        let matrixSession;
        try {
          matrixSession = this.matrix.login(cleanLocal, password);
        } catch (err) {
          this.logAudit('AUTH_FAILURE_FACTOR1', cleanLocal, 'Échec du mot de passe (1er facteur)');
          return sendJson(403, {
            error: err.code || 'M_FORBIDDEN',
            message: err.message,
          });
        }

        await this.callSynapseIfConfigured('/_matrix/client/v3/login', 'POST', {
          type: 'm.login.password',
          identifier: { type: 'm.id.user', user: cleanLocal },
          password,
        });

        // Si l'agent se connecte pour la toute première fois, il génère lui-même sa clé 2FA maintenant
        // (l'administrateur n'y a jamais eu accès lors de l'inscription)
        if (!agent.totpSecret) {
          agent.totpSecret = generateBase32Secret(20);
        }

        // Génère le code TOTP RFC 6238 hors-ligne (FreeOTP)
        const totpCodeNow = generateTOTP(agent.totpSecret);
        const mailDelivery = await this.mailer.send2FACodeEmail({
          toEmail: agent.email,
          fullName: agent.fullName,
          matricule: agent.matricule,
          ministry: agent.ministry,
          otpCode: totpCodeNow,
        });

        const challengeId = `chl_${crypto.randomBytes(16).toString('hex')}`;
        this.pendingSecondFactor.set(challengeId, {
          localpart: cleanLocal,
          emailOtpCode: totpCodeNow,
          matrixSession,
          expiresAt: Date.now() + 5 * 60 * 1000,
        });

        // Politique de sécurité : le QR Code FreeOTP n'est transmis QUE lors de la toute première connexion !
        const isFirstSetup = !agent.totpEnrolled;
        const otpAuthUri = isFirstSetup ? buildOtpAuthUri(agent.localpart, agent.totpSecret) : null;
        const qrSvg = isFirstSetup ? generateQrSvg(otpAuthUri) : null;

        return sendJson(200, {
          step: 'SECOND_FACTOR_REQUIRED',
          challengeId,
          isFirstSetup,
          qrSvg,
          totpSecret: isFirstSetup ? agent.totpSecret : null,
          otpAuthUri,
          deliveryChannel: 'EMAIL_GOV_BF',
          sentToEmail: agent.email,
          mailId: mailDelivery.mailId,
          agentPreview: {
            localpart: agent.localpart,
            fullName: agent.fullName,
            email: agent.email,
            matricule: agent.matricule,
            ministry: agent.ministry,
            role: agent.role,
          },
          demoTotpHint: totpCodeNow,
        });
      }

      // 3b. Consultation de la boîte de réception gouvernementale locale (Webmail .gov.bf pour lire le code 2FA)
      if (pathname === '/api/auth/webmail-inbox' && req.method === 'GET') {
        const email = parsedUrl.searchParams.get('email') || '';
        const messages = this.mailer.getInboxForEmail(email);
        return sendJson(200, { email, messages });
      }

      // 4. Étape 2 de Connexion : Vérification du Second Facteur (Code FreeOTP à 6 chiffres)
      if (pathname === '/api/auth/login-step2' && req.method === 'POST') {
        const body = await readBody();
        const { challengeId, totpCode } = body;
        const pending = this.pendingSecondFactor.get(challengeId);

        if (!pending || pending.expiresAt < Date.now()) {
          this.pendingSecondFactor.delete(challengeId);
          return sendJson(401, {
            error: 'CHALLENGE_EXPIRED',
            message: 'Le code de vérification a expiré. Veuillez recommencer.',
          });
        }

        const agent = this.directory.get(pending.localpart);
        if (!agent || agent.status !== 'ACTIVE') {
          this.pendingSecondFactor.delete(challengeId);
          return sendJson(403, { error: 'AGENT_REVOQUE', message: 'Compte agent révoqué.' });
        }

        const cleanInputCode = String(totpCode || '').trim();
        const isEmailOtpValid =
          pending.emailOtpCode &&
          cleanInputCode.length === 6 &&
          crypto.timingSafeEqual(
            Buffer.from(cleanInputCode, 'utf8'),
            Buffer.from(String(pending.emailOtpCode), 'utf8')
          );
        const isValidTotp = isEmailOtpValid || verifyTOTP(agent.totpSecret, cleanInputCode);
        if (!isValidTotp) {
          this.logAudit('AUTH_FAILURE_FACTOR2', agent.localpart, 'Code 2FA FreeOTP invalide');
          return sendJson(401, {
            error: 'INVALID_TOTP',
            message: 'Code OTP à 6 chiffres invalide. Vérifiez l’application FreeOTP sur votre téléphone.',
          });
        }

        this.pendingSecondFactor.delete(challengeId);

        // Scelle définitivement l'enrôlement 2FA après la 1ère connexion réussie : le QR code ne sera plus jamais affiché !
        if (!agent.totpEnrolled) {
          agent.totpEnrolled = true;
          this.logAudit(
            '2FA_QR_SEALED',
            agent.localpart,
            'Premier appairage FreeOTP validé : QR Code scellé définitivement.'
          );
        }

        // Session strictement limitée à 30 minutes (1800 secondes)
        const sessionDurationSeconds = 1800;
        const sessionExpiresAt = Date.now() + sessionDurationSeconds * 1000;
        const sid = `sid_${crypto.randomBytes(12).toString('hex')}`;

        // Liaison cryptographique DPoP (RFC 9449) + Cookie HttpOnly SameSite=Strict
        let cnf = null;
        const responseHeaders = {};
        if (body.dpopPublicJwk) {
          const jkt = this.dpopGuard.computeJwkThumbprint(body.dpopPublicJwk);
          if (!jkt) {
            return sendJson(400, { error: 'INVALID_DPOP_KEY', message: 'Clé publique DPoP ECDSA P-256 invalide.' });
          }
          cnf = { jkt };
          const useCookieBind = Boolean(body.enableCookieBind);
          let cookieBindHash = null;
          if (useCookieBind) {
            const cookieSecret = crypto.randomBytes(24).toString('base64url');
            cookieBindHash = crypto.createHash('sha256').update(cookieSecret, 'utf8').digest('hex');
            responseHeaders['Set-Cookie'] =
              `FasoHostBind=${cookieSecret}; HttpOnly; SameSite=Strict; Path=/api; Max-Age=${sessionDurationSeconds}`;
          }
          this.dpopBoundSessions.set(sid, {
            publicJwk: body.dpopPublicJwk,
            jkt,
            cookieBindHash,
            ctxHash: this.dpopGuard.computeClientContextHash(req),
          });
        }

        const portalToken = signPortalToken(
          {
            sid,
            localpart: agent.localpart,
            userId: agent.userId,
            role: agent.role,
            ministry: agent.ministry,
            matricule: agent.matricule,
            matrixAccessToken: pending.matrixSession.access_token,
            deviceId: pending.matrixSession.device_id,
            cnf,
          },
          this.signingKey,
          sessionDurationSeconds
        );

        this.logAudit(
          'AUTH_SUCCESS_2FA',
          agent.localpart,
          `Authentification forte réussie (Mot de passe + FreeOTP${cnf ? ' + DPoP ECDSA P-256' : ''}) — Expiration auto dans 30 min`
        );

        return sendJson(
          200,
          {
            status: 'AUTHENTICATED',
            portalToken,
            dpopBound: Boolean(cnf),
            dpopThumbprint: cnf?.jkt || null,
            sessionExpiresAt,
            sessionMaxAgeSeconds: sessionDurationSeconds,
            matrixAccessToken: pending.matrixSession.access_token,
            deviceId: pending.matrixSession.device_id,
            agent: {
              localpart: agent.localpart,
              userId: agent.userId,
              fullName: agent.fullName,
              matricule: agent.matricule,
              ministry: agent.ministry,
              direction: agent.direction,
              title: agent.title,
              role: agent.role,
              roleLabel: ROLES[agent.role]?.label,
              permissions: ROLES[agent.role]?.permissions || [],
            },
          },
          responseHeaders
        );
      }

      // --- ROUTES PROTÉGÉES PAR JETON 2FA + PREUVE DE POSSESSION DPoP ---
      const session = this.authenticateRequest(req, pathname);
      if (!session) {
        return sendJson(401, {
          error: 'SESSION_INVALID_OR_REVOKED',
          message:
            'Accès refusé : Session expirée, compte révoqué, ou tentative d’utilisation d’un jeton volé sans signature matérielle DPoP.',
        });
      }

      // 5. Profil et vérification de session active
      if (pathname === '/api/me' && req.method === 'GET') {
        return sendJson(200, {
          agent: session.agent,
          roleDetails: ROLES[session.agent.role],
        });
      }

      // 6. Annuaire officiel des agents par ministère et statut de relation (Cloisonnement)
      if (pathname === '/api/directory' && req.method === 'GET') {
        const ministryFilter = parsedUrl.searchParams.get('ministry');
        const agents = [];
        for (const a of this.directory.values()) {
          if (ministryFilter && ministryFilter !== 'ALL' && a.ministry !== ministryFilter) continue;

          const sameMinistry = a.ministry === session.ministry;
          const canMessageDirectly = this.canCommunicateDirectly(session.agent, a);
          let pendingRequestId = null;
          let pendingDirection = null;
          for (const reqItem of this.contactRequests.values()) {
            if (reqItem.status !== 'PENDING') continue;
            if (reqItem.fromLocalpart === session.localpart && reqItem.toLocalpart === a.localpart) {
              pendingRequestId = reqItem.id;
              pendingDirection = 'OUTGOING';
            } else if (reqItem.fromLocalpart === a.localpart && reqItem.toLocalpart === session.localpart) {
              pendingRequestId = reqItem.id;
              pendingDirection = 'INCOMING';
            }
          }

          agents.push({
            localpart: a.localpart,
            userId: a.userId,
            fullName: a.fullName,
            email: a.email,
            matricule: a.matricule,
            ministry: a.ministry,
            direction: a.direction,
            title: a.title,
            role: a.role,
            roleLabel: ROLES[a.role]?.label || a.role,
            status: a.status,
            sameMinistry,
            canMessageDirectly,
            pendingRequestId,
            pendingDirection,
          });
        }
        return sendJson(200, { ministries: MINISTRIES, agents });
      }

      // 6b. Gestion des demandes personnelles de communication inter-administration
      if (pathname === '/api/contact-requests' && req.method === 'GET') {
        const incoming = [];
        const outgoing = [];
        for (const r of this.contactRequests.values()) {
          if (r.toLocalpart === session.localpart && r.status === 'PENDING') {
            incoming.push(r);
          } else if (r.fromLocalpart === session.localpart) {
            outgoing.push(r);
          }
        }
        return sendJson(200, { incoming, outgoing });
      }

      if (pathname === '/api/contact-requests' && req.method === 'POST') {
        const body = await readBody();
        const targetLocal = String(body.targetLocalpart || '').trim().toLowerCase();
        const reason = String(body.reason || 'Besoin de coordination inter-services').trim();
        const targetAgent = this.directory.get(targetLocal);

        if (!targetAgent || targetAgent.status !== 'ACTIVE') {
          return sendJson(404, { error: 'NOT_FOUND', message: 'Agent destinataire introuvable ou inactif.' });
        }

        if (this.canCommunicateDirectly(session.agent, targetAgent)) {
          return sendJson(400, {
            error: 'ALREADY_AUTHORIZED',
            message: 'Vous êtes déjà autorisé à échanger directement avec cet agent.',
          });
        }

        // Vérifie si une demande est déjà en attente
        for (const existing of this.contactRequests.values()) {
          if (
            existing.status === 'PENDING' &&
            ((existing.fromLocalpart === session.localpart && existing.toLocalpart === targetLocal) ||
              (existing.fromLocalpart === targetLocal && existing.toLocalpart === session.localpart))
          ) {
            return sendJson(200, { request: existing, alreadyPending: true });
          }
        }

        const reqId = `req_${crypto.randomBytes(6).toString('hex')}`;
        const newReq = {
          id: reqId,
          fromLocalpart: session.localpart,
          fromFullName: session.agent.fullName,
          fromMinistry: session.ministry,
          fromTitle: session.agent.title,
          toLocalpart: targetAgent.localpart,
          toFullName: targetAgent.fullName,
          toMinistry: targetAgent.ministry,
          reason,
          status: 'PENDING',
          createdAt: new Date().toISOString(),
        };
        this.contactRequests.set(reqId, newReq);
        this.logAudit(
          'CONTACT_REQUEST_SENT',
          session.localpart,
          `Demande de communication inter-administration (${session.ministry} -> ${targetAgent.ministry}) envoyée à ${targetAgent.localpart}`
        );
        return sendJson(201, { request: newReq });
      }

      if (pathname.startsWith('/api/contact-requests/') && pathname.endsWith('/respond') && req.method === 'POST') {
        const reqId = decodeURIComponent(pathname.slice('/api/contact-requests/'.length, -'/respond'.length));
        const body = await readBody();
        const action = String(body.action || '').toUpperCase(); // 'ACCEPT' ou 'REJECT'
        const reqItem = this.contactRequests.get(reqId);

        if (!reqItem || reqItem.toLocalpart !== session.localpart) {
          return sendJson(404, { error: 'NOT_FOUND', message: 'Demande de contact introuvable.' });
        }

        if (action === 'ACCEPT') {
          reqItem.status = 'ACCEPTED';
          this.approvedContacts.add(this.pairKey(reqItem.fromLocalpart, reqItem.toLocalpart));
          const senderAgent = this.directory.get(reqItem.fromLocalpart);
          const dm = this.matrix.getOrCreateDirectRoom(
            session.userId,
            reqItem.fromLocalpart,
            `${senderAgent?.fullName || reqItem.fromLocalpart} (${reqItem.fromMinistry}) ↔ ${session.agent.fullName} (${session.ministry})`
          );
          this.logAudit(
            'CONTACT_REQUEST_ACCEPTED',
            session.localpart,
            `Demande de contact inter-administration acceptée avec ${reqItem.fromLocalpart}`
          );
          return sendJson(200, { status: 'ACCEPTED', request: reqItem, room_id: dm.room_id });
        } else {
          reqItem.status = 'REJECTED';
          return sendJson(200, { status: 'REJECTED', request: reqItem });
        }
      }

      // 7. Liste des salons chiffrés de l'agent
      if (pathname === '/api/rooms' && req.method === 'GET') {
        const rooms = this.matrix.getRoomsForUser(session.userId);
        return sendJson(200, { rooms });
      }

      // 8. Création d'un salon / canal institutionnel chiffré (Restreint aux agents du même ministère ou contacts approuvés)
      if (pathname === '/api/rooms' && req.method === 'POST') {
        const body = await readBody();
        if (body.isInstitutional && !hasPermission(session.role, 'CREATE_INSTITUTIONAL_CHANNEL')) {
          return sendJson(403, {
            error: 'ROLE_FORBIDDEN',
            message: 'Seuls les Directeurs et Administrateurs peuvent créer un canal institutionnel officiel.',
          });
        }

        const requestedMembers = Array.isArray(body.members) ? body.members : [];
        const allowedMembers = [];
        for (const lp of requestedMembers) {
          const cleanLp = String(lp).replace(/^@/, '').split(':')[0].toLowerCase();
          const targetAg = this.directory.get(cleanLp);
          if (targetAg && this.canCommunicateDirectly(session.agent, targetAg)) {
            allowedMembers.push(cleanLp);
          }
        }

        const created = this.matrix.createEncryptedRoom(session.userId, {
          name: body.name || 'Nouveau Salon Chiffré',
          topic: body.topic || `Canal interne (${session.ministry}) chiffré de bout en bout`,
          ministry: body.ministry || session.ministry,
          inviteLocalparts: allowedMembers,
        });
        this.logAudit('ROOM_CREATED', session.localpart, `Création du salon chiffré ${created.room_id}`);
        return sendJson(201, created);
      }

      // 8b. Démarrer ou rejoindre une discussion directe chiffrée (1:1) — Soumis au cloisonnement par administration
      if (pathname === '/api/rooms/direct' && req.method === 'POST') {
        const body = await readBody();
        const targetLocal = String(body.targetLocalpart || '').trim().toLowerCase();
        const targetAgent = this.directory.get(targetLocal);
        if (!targetAgent || targetAgent.status !== 'ACTIVE') {
          return sendJson(404, { error: 'NOT_FOUND', message: 'Agent introuvable ou inactif.' });
        }

        // Vérification stricte du cloisonnement administratif
        if (!this.canCommunicateDirectly(session.agent, targetAgent)) {
          return sendJson(403, {
            error: 'CROSS_ADMINISTRATION_REQUEST_REQUIRED',
            message: `Cloisonnement administratif : ${targetAgent.fullName} appartient à une autre administration (${targetAgent.ministry}). Vous devez d'abord lui envoyer une demande de contact personnelle et attendre son acceptation.`,
          });
        }

        const dm = this.matrix.getOrCreateDirectRoom(
          session.userId,
          targetLocal,
          `${targetAgent.fullName} (${targetAgent.ministry})`
        );
        return sendJson(200, dm);
      }

      // 9. Lecture des évènements chiffrés d'un salon
      if (pathname.startsWith('/api/rooms/') && pathname.endsWith('/events') && req.method === 'GET') {
        const roomId = decodeURIComponent(pathname.slice('/api/rooms/'.length, -'/events'.length));
        const events = this.matrix.getRoomEvents(session.userId, roomId);
        const enriched = events.map((ev) => ({
          ...ev,
          receipts: this.probativeReceipts.get(ev.event_id) || [],
        }));
        return sendJson(200, { room_id: roomId, events: enriched });
      }

      // 10. Envoi d'un évènement chiffré de bout en bout (`m.room.encrypted`)
      if (pathname.startsWith('/api/rooms/') && pathname.endsWith('/send-encrypted') && req.method === 'POST') {
        const roomId = decodeURIComponent(pathname.slice('/api/rooms/'.length, -'/send-encrypted'.length));
        const body = await readBody();

        const classification = body.faso_meta?.classification || 'NORMAL';
        if (!canUseClassification(session.role, classification)) {
          return sendJson(403, {
            error: 'CLASSIFICATION_FORBIDDEN_FOR_ROLE',
            message: `Votre rôle (${session.role}) n'est pas habilité à émettre des messages de niveau ${classification}.`,
          });
        }

        if (body.faso_meta?.is_instruction && !hasPermission(session.role, 'SEND_INSTRUCTION_SERVICE')) {
          return sendJson(403, {
            error: 'INSTRUCTION_FORBIDDEN_FOR_ROLE',
            message: 'Seuls les Directeurs et Administrateurs peuvent émettre une Instruction de Service.',
          });
        }

        const result = this.matrix.sendEncryptedEvent(
          session.userId,
          roomId,
          body.type || 'm.room.encrypted',
          body.content || body
        );
        return sendJson(200, result);
      }

      // 11. Accusé de lecture à valeur probante pour une Instruction de Service
      if (pathname === '/api/receipts/acknowledge' && req.method === 'POST') {
        const body = await readBody();
        const { eventId, roomId } = body;
        if (!eventId || !roomId) {
          return sendJson(400, { error: 'MISSING_FIELDS', message: 'eventId et roomId requis' });
        }

        const receipt = createSignedReceipt(
          {
            eventId,
            roomId,
            agentId: session.userId,
            matricule: session.agent.matricule,
            ministry: session.agent.ministry,
            timestampIso: new Date().toISOString(),
          },
          this.signingKey
        );

        const existing = this.probativeReceipts.get(eventId) || [];
        const already = existing.find((r) => r.agentId === session.userId);
        if (!already) {
          existing.push({
            ...receipt,
            fullName: session.agent.fullName,
            title: session.agent.title,
            verified: verifySignedReceipt(receipt, this.signingKey),
          });
          this.probativeReceipts.set(eventId, existing);
        }

        this.logAudit(
          'INSTRUCTION_ACKNOWLEDGED',
          session.localpart,
          `Accusé de lecture signé (HMAC-SHA256) pour l'instruction ${eventId}`
        );
        return sendJson(200, { receipt, totalReceipts: existing.length });
      }

      // 12. Enrôlement d'un nouvel agent par l'Administrateur (Identité Vérifiée + 2FA + Rôle)
      if (pathname === '/api/admin/enroll' && req.method === 'POST') {
        if (!hasPermission(session.role, 'ENROLL_AGENT')) {
          return sendJson(403, {
            error: 'ADMIN_REQUIRED',
            message: 'Seul un Administrateur Sécurité (ADMIN_SG) peut enrôler un nouvel agent.',
          });
        }

        const body = await readBody();
        const cleanLocal = String(body.localpart || '')
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9._-]/g, '');
        const password = String(body.password || '');

        if (!cleanLocal || password.length < 12) {
          return sendJson(400, {
            error: 'INVALID_INPUT',
            message: 'Identifiant requis et mot de passe de 12 caractères minimum exigé par la politique de sécurité.',
          });
        }
        if (this.directory.has(cleanLocal)) {
          return sendJson(409, { error: 'ALREADY_EXISTS', message: 'Cet agent est déjà enrôlé.' });
        }

        const role = ROLES[body.role] ? body.role : 'AGENT_PUBLIC';
        const ministry = body.ministry || 'MTDPCE';
        const email =
          String(body.email || '').trim().toLowerCase() ||
          `${cleanLocal}@${ministry.toLowerCase()}.gov.bf`;

        this.matrix.registerUser(cleanLocal, password, role === 'ADMIN_SG', ministry);

        // Principe Zero-Knowledge Admin : l'admin enregistre uniquement l'identité de l'agent.
        // La clé 2FA (totpSecret) reste à null et ne sera générée que par l'agent lui-même lors de sa 1ère connexion !
        const newAgent = {
          localpart: cleanLocal,
          userId: `@${cleanLocal}:${this.serverName}`,
          fullName: body.fullName || cleanLocal,
          email,
          matricule: body.matricule || `BF-${ministry}-${Math.floor(1000 + Math.random() * 9000)}`,
          ministry,
          direction: body.direction || 'Direction Générale',
          title: body.title || 'Agent Public',
          role,
          totpSecret: null,
          totpEnrolled: false,
          status: 'ACTIVE',
          enrolledAt: new Date().toISOString(),
        };

        this.directory.set(cleanLocal, newAgent);
        this.logAudit(
          'AGENT_ENROLLED',
          session.localpart,
          `Enregistrement de ${newAgent.userId} (${newAgent.matricule}) — Clé 2FA différée à la 1ère connexion de l'agent`
        );

        return sendJson(201, {
          agent: {
            localpart: newAgent.localpart,
            userId: newAgent.userId,
            fullName: newAgent.fullName,
            matricule: newAgent.matricule,
            ministry: newAgent.ministry,
            role: newAgent.role,
            status: newAgent.status,
          },
        });
      }

      // 13. Révocation immédiate d'un agent (Épreuve Jury : Révocation en direct)
      if (pathname === '/api/admin/revoke' && req.method === 'POST') {
        if (!hasPermission(session.role, 'REVOKE_AGENT')) {
          return sendJson(403, {
            error: 'ADMIN_REQUIRED',
            message: 'Seul un Administrateur Sécurité (ADMIN_SG) peut révoquer un agent.',
          });
        }

        const body = await readBody();
        const targetLocal = String(body.localpart || '')
          .trim()
          .replace(/^@/, '')
          .split(':')[0]
          .toLowerCase();

        if (targetLocal === 'admin') {
          return sendJson(400, { error: 'CANNOT_REVOKE_ROOT_ADMIN', message: 'Impossible de révoquer le compte admin principal.' });
        }

        const targetAgent = this.directory.get(targetLocal);
        if (!targetAgent) {
          return sendJson(404, { error: 'NOT_FOUND', message: 'Agent introuvable dans l’annuaire.' });
        }

        targetAgent.status = 'REVOKED';
        targetAgent.revokedAt = new Date().toISOString();
        targetAgent.revokedBy = session.userId;

        const matrixRevocation = this.matrix.deactivateUser(targetLocal);

        // Appel vers Synapse Admin API si déployé sous Docker
        await this.callSynapseIfConfigured(
          `/_synapse/admin/v1/deactivate/@${targetLocal}:${this.serverName}`,
          'POST',
          { erase: false },
          session.matrixAccessToken
        );

        this.logAudit(
          'AGENT_REVOKED_IMMEDIATELY',
          session.localpart,
          `Révocation immédiate de ${targetAgent.userId} : ${matrixRevocation.revoked_sessions} session(s) coupée(s), retiré de ${matrixRevocation.rooms_removed} salon(s).`
        );

        return sendJson(200, {
          status: 'REVOKED',
          agent: targetAgent,
          matrixRevocation,
        });
      }

      // 14. Bouton d'urgence / Effacement à distance (Panic Wipe)
      if (pathname === '/api/security/emergency-wipe' && req.method === 'POST') {
        const body = await readBody();
        const reason = body.reason || 'Déclenchement du bouton d’urgence par l’agent sur le terrain';
        // Coupe immédiatement toutes les sessions Matrix de l'agent appelant
        const rev = this.matrix.deactivateUser(session.localpart);
        const agent = this.directory.get(session.localpart);
        if (agent && session.localpart !== 'admin') {
          agent.status = 'REVOKED';
          agent.revokedReason = reason;
        }
        this.logAudit('EMERGENCY_PANIC_WIPE', session.localpart, reason);
        return sendJson(200, {
          status: 'WIPED_AND_REVOKED',
          message: 'Clés locales effacées et sessions serveur révoquées immédiatement.',
          details: rev,
        });
      }

      // 15. Épreuve Jury : Inspection « Le serveur ne lit rien »
      if (pathname === '/api/security/blind-check' && req.method === 'GET') {
        const report = this.matrix.inspectServerBlindness();
        return sendJson(200, {
          ...report,
          audit_logs: this.auditLogs.slice(0, 15),
          metadata_minimization_policy: {
            presence_enabled: false,
            user_ips_max_age: '1d',
            url_preview_enabled: false,
            push_include_content: false,
            federation_enabled: false,
          },
        });
      }

      return sendJson(404, { error: 'NOT_FOUND', message: `Route API inconnue: ${pathname}` });
    } catch (err) {
      return sendJson(err.status || 500, {
        error: err.code || 'SERVER_ERROR',
        message: err.message || 'Erreur interne du serveur souverain',
      });
    }
  }

  /**
   * Permet d'exécuter une requête API directement en mémoire (idéal pour les tests automatisés).
   */
  async dispatchTestRequest(method, urlPath, { headers = {}, body = null } = {}) {
    const parsedUrl = new URL(urlPath, 'http://localhost');
    const normalizedHeaders = {};
    for (const [k, v] of Object.entries(headers)) {
      normalizedHeaders[k.toLowerCase()] = v;
    }
    const req = {
      method: method.toUpperCase(),
      headers: normalizedHeaders,
      _DirectBody: body || {},
    };
    let statusCode = 200;
    let rawResponse = '';
    let responseHeaders = {};
    const res = {
      writeHead(code, hdrs = {}) {
        statusCode = code;
        responseHeaders = hdrs;
      },
      end(chunk) {
        rawResponse = chunk || '';
      },
    };
    await this.handleApi(req, res, parsedUrl.pathname, parsedUrl);
    return {
      status: statusCode,
      headers: responseHeaders,
      json: async () => (rawResponse ? JSON.parse(rawResponse) : {}),
    };
  }

  createHttpServer() {
    const publicDir = path.join(__dirname, '..', 'public');
    const mimeTypes = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.json': 'application/json; charset=utf-8',
      '.svg': 'image/svg+xml',
      '.png': 'image/png',
    };

    return http.createServer(async (req, res) => {
      const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
      const pathname = parsedUrl.pathname;

      if (pathname.startsWith('/api/')) {
        return this.handleApi(req, res, pathname, parsedUrl);
      }

      // Fichiers statiques de l'interface web souveraine
      let filePath = pathname === '/' ? path.join(publicDir, 'index.html') : path.join(publicDir, pathname);
      if (!filePath.startsWith(publicDir)) {
        res.writeHead(403);
        return res.end('Forbidden');
      }

      fs.readFile(filePath, (err, content) => {
        if (err) {
          res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
          return res.end('Fichier introuvable');
        }
        const ext = path.extname(filePath).toLowerCase();
        res.writeHead(200, {
          'Content-Type': mimeTypes[ext] || 'application/octet-stream',
          'X-Frame-Options': 'DENY',
          'X-Content-Type-Options': 'nosniff',
        });
        res.end(content);
      });
    });
  }
}

if (require.main === module) {
  const port = Number(process.env.PORTAL_PORT || 3000);
  const app = new SovereignPortalApp();
  const server = app.createHttpServer();
  server.listen(port, '0.0.0.0', () => {
    console.log(`[FasoSouverain] Portail & Messagerie Souveraine démarré sur http://localhost:${port}`);
  });
}

module.exports = { SovereignPortalApp };
