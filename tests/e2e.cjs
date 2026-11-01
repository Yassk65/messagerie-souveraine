// Full-stack browser acceptance test. Run only against a local DEMO_MODE=true stack.
const { chromium } = require('../portal/node_modules/@playwright/test');
const fs = require('fs');
const path = require('path');
const assert = require('node:assert/strict');
const { generateTOTP } = require('../portal/src/totp');
const base = process.env.FASO_BASE_URL || 'http://localhost:3000';
const artifacts = path.resolve(__dirname, '../data/e2e');
fs.mkdirSync(artifacts, { recursive: true });
let secretFile;
let secrets = {};
const errors = [];

async function call(page, pathname, body, method = 'POST', savedToken) {
  return page.evaluate(async ({ pathname, body, method, savedToken }) => {
    const session = JSON.parse(sessionStorage.getItem('faso-session') || '{}');
    const key = await new Promise((resolve, reject) => { const r = indexedDB.open('faso-session', 1); r.onsuccess = () => { const db = r.result; const tx = db.transaction('keys'); const get = tx.objectStore('keys').get('dpop'); get.onsuccess = () => { resolve(get.result); db.close(); }; }; r.onerror = () => reject(r.error); });
    const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const jti = crypto.randomUUID(), iat = Math.floor(Date.now() / 1000);
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, new TextEncoder().encode(`${jti}|${method}|${pathname}|${iat}`));
    const proof = encode(new TextEncoder().encode(JSON.stringify({ jti, htm: method, htu: pathname, iat, sig: encode(signature) })));
    const response = await fetch(pathname, { method, headers: { Authorization: `Bearer ${savedToken || session.portalToken}`, 'X-Faso-DPoP': proof, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    return { status: response.status, data: await response.json() };
  }, { pathname, body, method, savedToken });
}

async function login(context, username) {
  const page = await context.newPage();
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', message => { if (message.type() === 'error') console.log('BROWSER', message.text().slice(0, 300)); });
  page.on('response', async r => { if (r.status() >= 400 && r.url().includes('/api/')) console.log('API', r.status(), new URL(r.url()).pathname, (await r.text()).slice(0, 250)); });
  page.on('response', async r => { if (r.status() >= 400 && r.url().includes('/matrix/')) console.log('MATRIX', r.status(), new URL(r.url()).pathname, (await r.text()).slice(0, 160)); });
  await page.goto(base);
  await page.locator('#username').fill(username);
  await page.locator('#password').fill('Demo-Fictif-2026!');
  const firstResponse = page.waitForResponse(r => r.url().endsWith('/api/auth/login-step1'));
  await page.locator('#login-form button[type=submit]').click();
  const first = await (await firstResponse).json();
  assert.equal(first.step, 'SECOND_FACTOR_REQUIRED', first.message);
  if (first.totpSecret) { secrets[username] = first.totpSecret; fs.writeFileSync(secretFile, JSON.stringify(secrets)); }
  assert.ok(secrets[username], 'Test requires the demo account TOTP key from its initial setup.');
  await page.locator('#totp').fill(generateTOTP(secrets[username]));
  const response = page.waitForResponse(r => r.url().endsWith('/api/auth/login-step2'));
  await page.locator('#totp-form button[type=submit]').click();
  const data = await (await response).json();
  assert.equal(data.status, 'AUTHENTICATED'); assert.equal(data.matrixAccessToken, undefined);
  await page.locator('#connection.online').waitFor({ timeout: 60000 });
  await page.waitForFunction(() => document.querySelector('#directory-count').textContent.includes('AGENT'));
  return page;
}

async function run() {
  let health;
  for (let i = 0; i < 30; i++) { try { health = await (await fetch(base + '/api/health')).json(); break; } catch { await new Promise(r => setTimeout(r, 500)); } }
  assert.equal(health?.demoMode, true, 'Only run with a healthy fictitious demo stack');
  secretFile = path.join(artifacts, `demo-totp-${health.instanceId || 'legacy'}.json`);
  secrets = fs.existsSync(secretFile) ? JSON.parse(fs.readFileSync(secretFile)) : {};
  const browser = await chromium.launch({ channel: 'msedge', headless: true, args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'] });
  const contexts = [];
  try {
    const a = await browser.newContext({ viewport: { width: 1600, height: 1000 }, acceptDownloads: true, permissions: ['microphone'] }); contexts.push(a);
    const landing = await a.newPage(); await landing.goto(base); await landing.screenshot({ path: path.join(artifacts, 'connexion-desktop.png'), fullPage: true }); await landing.close();
    const admin = await login(a, 'admin');
    if (process.env.FASO_EXTENDED === 'true' && secrets._recoveryKey) {
      await admin.locator('#restore').click(); await admin.locator('#dialog input[name=value]').waitFor({ timeout: 15000 });
      await admin.locator('#dialog input[name=value]').fill(secrets._recoveryKey); await admin.locator('#dialog-submit').click();
      await admin.locator('#toast').filter({ hasText: /restaurée/ }).waitFor({ timeout: 30000 });
    }
    const b = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true }); contexts.push(b);
    const director = await login(b, 'aminata.ouedraogo');
    await admin.locator('[data-view=directory]').click();
    await admin.locator('[data-contact="aminata.ouedraogo"]').click();
    await admin.locator('#view-messages.chat-open').waitFor({ timeout: 20000 });
    const room = await admin.locator('.room-item.active').getAttribute('data-room');
    await director.locator(`[data-room="${room}"]`).waitFor({ timeout: 30000 });
    await director.locator(`[data-room="${room}"]`).click();
    const message = 'Échange chiffré de validation ' + Date.now();
    await admin.locator('#message').fill(message); await admin.locator('#send').click();
    await director.locator('#timeline').getByText(message, { exact: false }).waitFor({ timeout: 30000 });
    await director.locator('#message').fill('Bien reçu sur le second navigateur.'); await director.locator('#send').click();
    await admin.locator('#timeline').getByText('Bien reçu sur le second navigateur.', { exact: false }).last().waitFor({ timeout: 30000 });
    console.log('PASS two-browser Megolm exchange');
    await admin.locator('#attachment').setInputFiles({ name: 'validation.txt', mimeType: 'text/plain', buffer: Buffer.from('Pièce jointe confidentielle du test') });
    await admin.locator('#send').click();
    const file = director.locator('.file-card').filter({ hasText: 'validation.txt' }).last();
    await file.waitFor({ timeout: 30000 });
    const download = director.waitForEvent('download'); await file.locator('button').click();
    const saved = await download; const downloadPath = await saved.path(); assert.equal(fs.readFileSync(downloadPath, 'utf8'), 'Pièce jointe confidentielle du test');
    console.log('PASS encrypted attachment upload/download');
    await admin.locator('#instruction').check(); await admin.locator('#message').fill('Instruction de validation ' + Date.now()); await admin.locator('#send').click();
    await director.locator('[data-ack]').last().waitFor({ timeout: 30000 }); await director.locator('[data-ack]').last().click();
    await director.getByRole('button', { name: 'Lecture signée', exact: true }).last().waitFor({ timeout: 10000 });
    console.log('PASS signed acknowledgment');
    if (process.env.FASO_EXTENDED === 'true') {
      await admin.locator('#instruction').uncheck();
      await admin.locator('#voice').click(); await admin.locator('#recording').waitFor();
      await admin.waitForTimeout(1500); await admin.locator('#send-recording').click();
      const voice = director.locator('.file-card').filter({ hasText: 'Note-vocale.webm' }).last();
      await voice.waitFor({ timeout: 30000 }); await voice.locator('button').click();
      await director.locator('#timeline audio').waitFor({ timeout: 10000 });
      console.log('PASS encrypted voice recording and playback');
      if (!secrets._recoveryKey) {
        await admin.locator('#setup-recovery').click();
        await admin.locator('#dialog[open]').waitFor({ timeout: 15000 });
        if ((await admin.locator('#dialog-title').textContent()).includes('Confirmer')) {
          await admin.locator('#dialog input[name=value]').fill('Demo-Fictif-2026!'); await admin.locator('#dialog-submit').click();
        }
        await admin.locator('.recovery-key').waitFor({ timeout: 20000 });
        secrets._recoveryKey = await admin.locator('.recovery-key').textContent(); fs.writeFileSync(secretFile, JSON.stringify(secrets));
        await admin.locator('#dialog input[type=checkbox]').check(); await admin.locator('#dialog-submit').click();
        await admin.waitForFunction(() => document.querySelector('#trust-status').textContent.includes('Sauvegarde des clés active'), { timeout: 30000 });
      }
      console.log('PASS client-encrypted key backup setup');
      // Wait until the SDK has actually uploaded the Megolm session backup.
      await admin.waitForResponse(r => /\/room_keys\/keys/.test(r.url()) && r.request().method() === 'PUT' && r.status() === 200, { timeout: 30000 }).catch(() => {});
      const c = await browser.newContext({ viewport: { width: 1600, height: 1000 } }); contexts.push(c);
      const recovery = await login(c, 'admin');
      await recovery.locator(`[data-room="${room}"]`).click();
      await recovery.locator('#restore').click(); await recovery.locator('#dialog input[name=value]').waitFor({ timeout: 15000 });
      await recovery.locator('#dialog input[name=value]').fill('cle-invalide'); await recovery.locator('#dialog-submit').click();
      await recovery.locator('#toast').filter({ hasText: /key|clé|Invalid|incorrect|decode|base58/i }).waitFor({ timeout: 15000 });
      await recovery.locator('#restore').click(); await recovery.locator('#dialog input[name=value]').fill(secrets._recoveryKey); await recovery.locator('#dialog-submit').click();
      await recovery.locator('#toast').filter({ hasText: /restaurée/ }).waitFor({ timeout: 30000 });
      await recovery.locator('#timeline').getByText(message, { exact: false }).waitFor({ timeout: 30000 });
      console.log('PASS new-device recovery and invalid-key rejection');
      const recoveredSession = JSON.parse(await recovery.evaluate(() => sessionStorage.getItem('faso-session')));
      await admin.locator('[data-view=security]').click(); await admin.locator(`[data-verify="${recoveredSession.deviceId}"]`).click();
      await recovery.locator('#dialog[open]').waitFor({ timeout: 15000 }); await recovery.locator('#dialog-submit').click();
      await admin.locator('#dialog-title').filter({ hasText: 'Comparer' }).waitFor({ timeout: 20000 });
      await recovery.locator('#dialog-title').filter({ hasText: 'Comparer' }).waitFor({ timeout: 20000 });
      assert.equal(await admin.locator('#dialog-body').textContent(), await recovery.locator('#dialog-body').textContent());
      await admin.locator('#dialog-submit').click(); await recovery.locator('#dialog-submit').click();
      await admin.locator('#toast').filter({ hasText: 'Appareil vérifié.' }).waitFor({ timeout: 20000 });
      console.log('PASS SAS device verification with matching codes');
      await c.close(); contexts.splice(contexts.indexOf(c), 1);

      const localpart = 'validation.' + Date.now(), fullName = 'Agent de validation ' + Date.now();
      await admin.locator('#enroll').click();
      const form = admin.locator('#dialog-form');
      await form.locator('[name=localpart]').fill(localpart); await form.locator('[name=matricule]').fill('BF-TEST-' + Date.now());
      await form.locator('[name=fullName]').fill(fullName); await form.locator('[name=ministry]').selectOption('MEFP');
      await form.locator('[name=direction]').fill('Validation'); await form.locator('[name=title]').fill('Agent de test');
      await form.locator('[name=password]').fill('Demo-Fictif-2026!'); await admin.locator('#dialog-submit').click();
      await admin.locator('#toast').filter({ hasText: 'Agent enrôlé.' }).waitFor();
      const d = await browser.newContext(); contexts.push(d); const agent = await login(d, localpart);
      assert.equal(await agent.locator('#classification option[value=CONFIDENTIEL]').evaluate(el => el.disabled), true);
      assert.equal((await call(agent, '/api/rooms/direct', { targetLocalpart: 'admin' })).status, 403);
      assert.equal((await call(agent, '/api/security/blind-check', undefined, 'GET')).status, 403);
      assert.equal((await call(agent, '/matrix/_matrix/client/v3/login', {})).status, 403);
      await agent.locator('[data-view=directory]').click(); await agent.locator('[data-contact=admin]').click();
      await agent.locator('#dialog input[name=value]').fill('Validation du cloisonnement'); await agent.locator('#dialog-submit').click();
      await admin.locator('[data-view=actions]').click();
      const request = admin.locator('.request-row').filter({ hasText: fullName }); await request.locator('[data-accept]').waitFor({ timeout: 20000 }); await request.locator('[data-accept]').click();
      const direct = await call(agent, '/api/rooms/direct', { targetLocalpart: 'admin' }); assert.equal(direct.status, 200);
      assert.equal((await call(agent, `/matrix/_matrix/client/v3/rooms/${encodeURIComponent(direct.data.room_id)}/send/m.room.message/plaintext`, { body: 'Interdit', msgtype: 'm.text' }, 'PUT')).status, 403);
      assert.equal((await call(agent, `/api/rooms/${encodeURIComponent(direct.data.room_id)}/send-encrypted`, { content: { faso_meta: { classification: 'CONFIDENTIEL' } } })).status, 403);
      const savedToken = JSON.parse(await agent.evaluate(() => sessionStorage.getItem('faso-session'))).portalToken;
      await admin.locator('[data-view=security]').click(); const revoke = admin.locator(`[data-revoke="${localpart}"]`); await revoke.waitFor(); await revoke.click();
      await admin.locator('#dialog-submit').click(); await admin.locator('#toast').filter({ hasText: 'Compte révoqué.' }).waitFor();
      assert.equal((await call(agent, '/api/me', undefined, 'GET', savedToken)).status, 401);
      console.log('PASS live enrollment, ministry isolation, RBAC, gateway restrictions and immediate revocation');
      await d.close(); contexts.splice(contexts.indexOf(d), 1);
      const wipeName = 'purge.' + Date.now();
      assert.equal((await call(admin, '/api/admin/enroll', { localpart: wipeName, fullName: 'Agent fictif purge', ministry: 'MTDPCE', role: 'AGENT_PUBLIC', password: 'Demo-Fictif-2026!' })).status, 201);
      const w = await browser.newContext(); contexts.push(w); const terminal = await login(w, wipeName);
      await terminal.locator('[data-view=actions]').click(); await terminal.locator('#wipe').click();
      await terminal.locator('#dialog-submit').click(); await terminal.locator('#auth').waitFor({ timeout: 20000 });
      await terminal.waitForFunction(async () => !(await indexedDB.databases()).some(db => db.name === 'faso-session' || db.name.startsWith('faso:')));
      console.log('PASS emergency account revocation and deletion of local cryptographic stores');
      await w.close(); contexts.splice(contexts.indexOf(w), 1);
    }
    await admin.screenshot({ path: path.join(artifacts, 'messages-desktop.png'), fullPage: true });
    await admin.locator('[data-view=directory]').click(); await admin.screenshot({ path: path.join(artifacts, 'annuaire-desktop.png'), fullPage: true });
    await admin.locator('[data-view=security]').click(); await admin.locator('#enroll').waitFor(); await admin.screenshot({ path: path.join(artifacts, 'securite-desktop.png'), fullPage: true });
    await admin.locator('[data-view=actions]').click(); await admin.screenshot({ path: path.join(artifacts, 'actions-desktop.png'), fullPage: true });
    await director.setViewportSize({ width: 390, height: 844 }); await director.screenshot({ path: path.join(artifacts, 'discussion-mobile.png'), fullPage: true });
    assert.equal(await director.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    if (process.env.FASO_TEST_RESTART === 'true') {
      require('child_process').execFileSync('docker', ['compose', 'restart', 'portal', 'synapse'], { cwd: path.resolve(__dirname, '..'), stdio: 'pipe' });
      for (let i = 0; i < 50; i++) { try { if ((await fetch(base + '/api/health')).ok) break; } catch {} await new Promise(r => setTimeout(r, 500)); }
      console.log('PASS container restart completed');
    }
    await director.reload(); await director.locator('#connection.online').waitFor({ timeout: 60000 });
    await director.locator(`[data-room="${room}"]`).click(); await director.locator('#timeline').getByText(message, { exact: false }).waitFor({ timeout: 30000 });
    console.log('PASS refresh with persisted local keys and server registry');
    assert.deepEqual(errors, []);
    console.log('PASS screenshots desktop/mobile and no uncaught browser exceptions');
  } catch (error) {
    for (const [i, context] of contexts.entries()) for (const [j, page] of context.pages().entries()) {
      console.log('FAILURE STATE', i, j, await page.locator('#toast').textContent().catch(() => ''));
      await page.screenshot({ path: path.join(artifacts, `failure-${i}-${j}.png`), fullPage: true }).catch(() => {});
    }
    throw error;
  } finally { await Promise.all(contexts.map(c => c.close())); await browser.close(); }
}
run().catch(e => { console.error(e); process.exitCode = 1; });
