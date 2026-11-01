const { canUseClassification, hasPermission } = require('./roles');
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };

function allowedPath(method, path, userId) {
  if (path === '/_matrix/client/versions') return method === 'GET';
  if (/^\/_matrix\/media\/v3\/(?:upload|config)$/.test(path)) return method === (path.endsWith('/upload') ? 'POST' : 'GET');
  const match = path.match(/^\/_matrix\/client\/(?:v1|v3|r0|unstable)\/(.+)$/);
  if (!match) return false;
  const p = match[1];
  if (p.startsWith(`user/${encodeURIComponent(userId)}/filter`) || p.startsWith(`user/${userId}/filter`)) {
    const tail = p.slice(p.indexOf('/filter') + '/filter'.length);
    return (method === 'POST' && tail === '') || (method === 'GET' && /^\/[^/]+$/.test(tail));
  }
  if (method === 'GET' && /^(sync|capabilities|pushrules\/?|devices|joined_rooms|account\/whoami|room_keys\/version(?:\/[^/]+)?|room_keys\/keys(?:\/.*)?)$/.test(p)) return true;
  if (/^keys\/(upload|query|claim|changes|device_signing\/upload|signatures\/upload)$/.test(p)) return ['POST', 'GET'].includes(method);
  if (/^sendToDevice\/[A-Za-z0-9_.]+\/[^/]+$/.test(p)) return method === 'PUT';
  if (p.startsWith(`user/${encodeURIComponent(userId)}/account_data/`) || p.startsWith(`user/${userId}/account_data/`)) return ['GET', 'PUT'].includes(method);
  if (/^room_keys\/(version(?:\/[^/]+)?|keys(?:\/.*)?)$/.test(p)) return ['GET', 'POST', 'PUT'].includes(method);
  if (/^rooms\/[^/]+\/(state(?:\/.*)?|messages|event\/[^/]+|members|joined_members|context\/[^/]+)$/.test(p)) return method === 'GET';
  if (/^rooms\/[^/]+\/send\/m.room.encrypted\/[^/]+$/.test(p)) return method === 'PUT';
  if (/^rooms\/[^/]+\/receipt\/m.read\/[^/]+$/.test(p)) return method === 'POST';
  if (/^rooms\/[^/]+\/(read_markers|leave|join)$/.test(p)) return method === 'POST';
  if (/^join\/[^/]+$/.test(p)) return method === 'POST';
  if (/^(?:devices\/[^/]+)$/.test(p)) return ['GET', 'PUT', 'DELETE'].includes(method);
  if (/^org.matrix.msc\d+\/.*$/.test(p)) return false;
  // Modern authenticated media endpoints.
  if (/^media\/(config|upload|download\/[^/]+\/[^/]+(?:\/[^/]+)?)$/.test(p)) return method === (p === 'media/upload' ? 'POST' : 'GET');
  return false;
}

async function readRaw(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 15 * 1024 * 1024) fail(413, 'Fichier trop volumineux (15 Mo maximum).');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function gateway(app, req, res, url) {
  const session = app.authenticateRequest(req, url.pathname);
  if (!session) fail(401, 'Session expirée ou révoquée.');
  const path = url.pathname.slice('/matrix'.length);
  const backupSessionPath = /^\/_matrix\/client\/v3\/room_keys\/keys\/[^/]+\/[^/]+$/.test(path);
  if (url.searchParams.has('access_token') || /%5c|\.\./i.test(path) || /%2f/i.test(path) && !backupSessionPath) fail(403, 'Chemin interdit.');
  if (!allowedPath(req.method, path, session.userId)) fail(403, 'Opération Matrix interdite.');
  const roomMatch = path.match(/\/(?:rooms|join)\/([^/]+)/);
  if (roomMatch && ![...app.matrix.roomMappings.values()].includes(decodeURIComponent(roomMatch[1]))) fail(403, 'Salon non géré par le portail.');
  const raw = ['GET', 'HEAD'].includes(req.method) ? undefined : await readRaw(req);
  let body;
  const mediaUpload = path === '/_matrix/media/v3/upload' || path === '/_matrix/client/v1/media/upload';
  if (raw?.length && !mediaUpload) {
    try { body = JSON.parse(raw); } catch { fail(400, 'JSON invalide.'); }
  }
  if (path.includes('/send/m.room.encrypted/')) {
    if (body.algorithm !== 'm.megolm.v1.aes-sha2' || !body.ciphertext || body.body || body.plaintext) fail(400, 'Événement chiffré invalide.');
    const meta = body.faso_meta || {};
    if (!canUseClassification(session.role, meta.classification || 'NORMAL')) fail(403, 'Classification non autorisée.');
    if (meta.is_instruction && !hasPermission(session.role, 'SEND_INSTRUCTION_SERVICE')) fail(403, 'Instruction non autorisée.');
  }
  if (path.includes('/sendToDevice/') && body?.messages) {
    for (const userId of Object.keys(body.messages)) {
      const agent = [...app.directory.values()].find(a => a.userId === userId && a.status === 'ACTIVE');
      if (!agent || !app.canCommunicateDirectly(session.agent, agent)) fail(403, 'Destinataire non autorisé.');
    }
  }
  // Never forward browser cookies, its bearer token, or arbitrary proxy headers.
  let upstream;
  try {
    upstream = await fetch(app.synapseUrl + path + url.search, {
      method: req.method,
      headers: { Authorization: `Bearer ${session.matrixAccessToken}`, 'Content-Type': req.headers['content-type'] || 'application/json' },
      body: raw, signal: AbortSignal.timeout(40000),
    });
  } catch { fail(503, 'Synapse est indisponible.'); }
  const data = Buffer.from(await upstream.arrayBuffer());
  if (app.directory.get(session.localpart)?.status !== 'ACTIVE' || !app.serverSessions.has(session.sid)) fail(401, 'Session révoquée.');
  res.writeHead(upstream.status, { 'Content-Type': upstream.headers.get('content-type') || 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(data);
}
module.exports = { gateway, allowedPath };
