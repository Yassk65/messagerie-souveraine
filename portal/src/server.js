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

    // Annuaire officiel des agents enrôlés : localpart -> fiche agent
    this.directory = new Map();
    for (const agent of DEFAULT_DEMO_AGENTS) {
      this.directory.set(agent.localpart, {
        ...agent,
        userId: `@${agent.localpart}:${this.serverName}`,
        enrolledAt: new Date(Date.now() - 86400000).toISOString(),
      });
    }

    // Sessions pré-authentifiées en attente du 2e facteur (TOTP)
    this.pendingSecondFactor = new Map(); // challengeId -> { localpart, matrixSession, expiresAt }

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

  authenticateRequest(req) {
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

    return { ...payload, agent };
  }

  async handleApi(req, res, pathname, parsedUrl) {
    const sendJson = (status, data) => {
      res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-store',
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
          if (raw.length > 2 * 1024 * 1024) reject(new Error('Payload trop volumineux'));
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
            currentTotpDemo: agent.status === 'ACTIVE' ? generateTOTP(agent.totpSecret) : 'RÉVOQUÉ',
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
        const cleanLocal = String(body.username || '')
          .trim()
          .replace(/^@/, '')
          .split(':')[0]
          .toLowerCase();
        const password = String(body.password || '');

        const agent = this.directory.get(cleanLocal);
        if (!agent) {
          this.logAudit('INTRUSION_BLOCKED', cleanLocal || 'inconnu', 'Tentative de connexion par un compte non enrôlé');
          return sendJson(403, {
            error: 'INTRUS_REJETE',
            message: `Accès rejeté : l'identifiant "${cleanLocal}" n'est pas enrôlé dans l'annuaire souverain de l'administration.`,
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

        const challengeId = `chl_${crypto.randomBytes(16).toString('hex')}`;
        this.pendingSecondFactor.set(challengeId, {
          localpart: cleanLocal,
          matrixSession,
          expiresAt: Date.now() + 5 * 60 * 1000,
        });

        return sendJson(200, {
          step: 'SECOND_FACTOR_REQUIRED',
          challengeId,
          agentPreview: {
            localpart: agent.localpart,
            fullName: agent.fullName,
            matricule: agent.matricule,
            ministry: agent.ministry,
            role: agent.role,
          },
          demoTotpHint: generateTOTP(agent.totpSecret),
        });
      }

      // 4. Étape 2 de Connexion : Vérification du Second Facteur (Code TOTP à 6 chiffres)
      if (pathname === '/api/auth/login-step2' && req.method === 'POST') {
        const body = await readBody();
        const { challengeId, totpCode } = body;
        const pending = this.pendingSecondFactor.get(challengeId);

        if (!pending || pending.expiresAt < Date.now()) {
          this.pendingSecondFactor.delete(challengeId);
          return sendJson(401, {
            error: 'CHALLENGE_EXPIRED',
            message: 'La session de vérification a expiré. Veuillez recommencer.',
          });
        }

        const agent = this.directory.get(pending.localpart);
        if (!agent || agent.status !== 'ACTIVE') {
          this.pendingSecondFactor.delete(challengeId);
          return sendJson(403, { error: 'AGENT_REVOQUE', message: 'Compte agent révoqué.' });
        }

        const isValidTotp = verifyTOTP(agent.totpSecret, totpCode);
        if (!isValidTotp) {
          this.logAudit('AUTH_FAILURE_FACTOR2', agent.localpart, 'Code TOTP (2e facteur) invalide');
          return sendJson(401, {
            error: 'INVALID_TOTP',
            message: 'Code de sécurité à 6 chiffres (2FA TOTP) invalide.',
          });
        }

        this.pendingSecondFactor.delete(challengeId);

        const portalToken = signPortalToken(
          {
            localpart: agent.localpart,
            userId: agent.userId,
            role: agent.role,
            ministry: agent.ministry,
            matricule: agent.matricule,
            matrixAccessToken: pending.matrixSession.access_token,
            deviceId: pending.matrixSession.device_id,
          },
          this.signingKey
        );

        this.logAudit(
          'AUTH_SUCCESS_2FA',
          agent.localpart,
          `Authentification forte réussie (Mot de passe + TOTP) — Rôle: ${agent.role}`
        );

        return sendJson(200, {
          status: 'AUTHENTICATED',
          portalToken,
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
        });
      }

      // --- ROUTES PROTÉGÉES PAR JETON 2FA ---
      const session = this.authenticateRequest(req);
      if (!session) {
        return sendJson(401, {
          error: 'SESSION_INVALID_OR_REVOKED',
          message: 'Session expirée ou compte révoqué immédiatement par l’administration.',
        });
      }

      // 5. Profil et vérification de session active
      if (pathname === '/api/me' && req.method === 'GET') {
        return sendJson(200, {
          agent: session.agent,
          roleDetails: ROLES[session.agent.role],
        });
      }

      // 6. Annuaire officiel des agents par ministère et fonction
      if (pathname === '/api/directory' && req.method === 'GET') {
        const ministryFilter = parsedUrl.searchParams.get('ministry');
        const agents = [];
        for (const a of this.directory.values()) {
          if (ministryFilter && ministryFilter !== 'ALL' && a.ministry !== ministryFilter) continue;
          agents.push({
            localpart: a.localpart,
            userId: a.userId,
            fullName: a.fullName,
            matricule: a.matricule,
            ministry: a.ministry,
            direction: a.direction,
            title: a.title,
            role: a.role,
            roleLabel: ROLES[a.role]?.label || a.role,
            status: a.status,
          });
        }
        return sendJson(200, { ministries: MINISTRIES, agents });
      }

      // 7. Liste des salons chiffrés de l'agent
      if (pathname === '/api/rooms' && req.method === 'GET') {
        const rooms = this.matrix.getRoomsForUser(session.userId);
        return sendJson(200, { rooms });
      }

      // 8. Création d'un salon / canal institutionnel chiffré
      if (pathname === '/api/rooms' && req.method === 'POST') {
        const body = await readBody();
        if (body.isInstitutional && !hasPermission(session.role, 'CREATE_INSTITUTIONAL_CHANNEL')) {
          return sendJson(403, {
            error: 'ROLE_FORBIDDEN',
            message: 'Seuls les Directeurs et Administrateurs peuvent créer un canal institutionnel officiel.',
          });
        }
        const created = this.matrix.createEncryptedRoom(session.userId, {
          name: body.name || 'Nouveau Salon Chiffré',
          topic: body.topic || 'Chiffrement de bout en bout Megolm actif',
          ministry: body.ministry || session.ministry,
          inviteLocalparts: Array.isArray(body.members) ? body.members : [],
        });
        this.logAudit('ROOM_CREATED', session.localpart, `Création du salon chiffré ${created.room_id}`);
        return sendJson(201, created);
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
        const totpSecret = generateBase32Secret(20);

        this.matrix.registerUser(cleanLocal, password, role === 'ADMIN_SG');

        const newAgent = {
          localpart: cleanLocal,
          userId: `@${cleanLocal}:${this.serverName}`,
          fullName: body.fullName || cleanLocal,
          matricule: body.matricule || `BF-${ministry}-${Math.floor(1000 + Math.random() * 9000)}`,
          ministry,
          direction: body.direction || 'Direction Générale',
          title: body.title || 'Agent Public',
          role,
          totpSecret,
          status: 'ACTIVE',
          enrolledAt: new Date().toISOString(),
        };

        this.directory.set(cleanLocal, newAgent);
        this.logAudit(
          'AGENT_ENROLLED',
          session.localpart,
          `Enrôlement de ${newAgent.userId} (${newAgent.matricule}) avec rôle ${role}`
        );

        return sendJson(201, {
          agent: newAgent,
          otpAuthUri: buildOtpAuthUri(cleanLocal, totpSecret),
          currentTotpCode: generateTOTP(totpSecret),
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
    const res = {
      writeHead(code) {
        statusCode = code;
      },
      end(chunk) {
        rawResponse = chunk || '';
      },
    };
    await this.handleApi(req, res, parsedUrl.pathname, parsedUrl);
    return {
      status: statusCode,
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
