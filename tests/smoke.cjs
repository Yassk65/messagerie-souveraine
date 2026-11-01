// Read-only smoke check: leaves the fresh demo TOTP enrollment untouched.
const { chromium } = require('../portal/node_modules/@playwright/test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
async function main() {
  const base = 'http://localhost:3000';
  let health;
  for (let i = 0; i < 240; i++) { try { health = await (await fetch(base + '/api/health')).json(); break; } catch {} await new Promise(r => setTimeout(r, 500)); }
  assert.equal(health?.demoMode, true);
  assert.equal((await (await fetch(base + '/api/demo/accounts')).json()).accounts.length, 4);
  assert.equal((await fetch(base + '/matrix/_matrix/client/versions')).status, 401);
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
    const errors = [], external = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => { if (!request.url().startsWith(base) && !request.url().startsWith('data:') && !request.url().startsWith('blob:')) external.push(request.url()); });
    await page.goto(base); await page.locator('#demo').waitFor();
    const labels = [];
    for (const lang of ['fr', 'mos', 'dyu', 'ff']) { await page.locator('#language-auth').selectOption(lang); labels.push(await page.locator('label[for=username]').textContent()); }
    assert.equal(new Set(labels).size, 4); await page.locator('#language-auth').selectOption('fr');
    const dir = path.resolve(__dirname, '../data/e2e'); fs.mkdirSync(dir, { recursive: true });
    await page.screenshot({ path: path.join(dir, 'livraison-connexion-desktop.png'), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.screenshot({ path: path.join(dir, 'livraison-connexion-mobile.png'), fullPage: true });
    assert.deepEqual(errors, []); assert.deepEqual(external, []);
    console.log('PASS fresh four-account demo, isolated Matrix, four languages, desktop/mobile and local-only assets');
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
