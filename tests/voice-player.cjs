const { chromium } = require('../portal/node_modules/@playwright/test');
const fs = require('fs');
const path = require('path');
const assert = require('node:assert/strict');
async function main() {
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await page.setContent('<main id="timeline" style="padding:16px"><div id="placeholder"></div></main>');
    await page.addStyleTag({ content: fs.readFileSync(path.resolve(__dirname, '../portal/web/styles.css'), 'utf8') });
    const source = fs.readFileSync(path.resolve(__dirname, '../portal/web/voice-player.js'), 'utf8').replace('export class VoicePlayers', 'class VoicePlayers');
    await page.addScriptTag({ content: source + '\nwindow.players = new VoicePlayers();' });
    await page.evaluate(() => {
      // A real four-second PCM audio buffer, without microphone or server fixtures.
      const buffer = new ArrayBuffer(44 + 4 * 8000 * 2), view = new DataView(buffer);
      const str = (offset, value) => [...value].forEach((c, i) => view.setUint8(offset + i, c.charCodeAt(0)));
      str(0, 'RIFF'); view.setUint32(4, buffer.byteLength - 8, true); str(8, 'WAVE'); str(12, 'fmt ');
      view.setUint32(16, 16, true); view.setUint16(20, 1, true); view.setUint16(22, 1, true);
      view.setUint32(24, 8000, true); view.setUint32(28, 16000, true); view.setUint16(32, 2, true); view.setUint16(34, 16, true);
      str(36, 'data'); view.setUint32(40, buffer.byteLength - 44, true);
      window.loads = 0; window.loadVoice = async () => { window.loads++; return URL.createObjectURL(new Blob([buffer], { type: 'audio/wav' })); };
      window.players.mount(document.querySelector('#placeholder'), 'voice-1', { info: { duration: 4000 } }, window.loadVoice);
    });
    const play = page.getByRole('button', { name: 'Écouter le message vocal', exact: true });
    await page.waitForFunction(() => !document.querySelector('.voice-play').disabled);
    assert.equal(await page.locator('.voice-time').textContent(), '0:04');
    assert.equal(await page.locator('.file-card').count(), 0);
    await play.click(); await page.getByRole('button', { name: 'Mettre le vocal en pause' }).waitFor();
    await page.waitForFunction(() => window.players.players.get('voice-1').audio.currentTime > 0.15);
    await page.evaluate(() => {
      document.querySelector('#timeline').innerHTML = '<div id="refresh"></div>';
      window.players.mount(document.querySelector('#refresh'), 'voice-1', {}, window.loadVoice);
      window.players.retain(new Set(['voice-1']));
    });
    assert.equal(await page.evaluate(() => window.players.players.get('voice-1').audio.paused), false);
    assert.equal(await page.evaluate(() => window.loads), 1);
    await page.locator('.voice-speed').click(); assert.equal(await page.evaluate(() => window.players.players.get('voice-1').audio.playbackRate), 1.5);
    await page.locator('.voice-seek').fill('500');
    assert.ok(await page.evaluate(() => window.players.players.get('voice-1').audio.currentTime >= 1.9));
    await page.getByRole('button', { name: 'Mettre le vocal en pause' }).click();
    assert.equal(await page.evaluate(() => window.players.players.get('voice-1').audio.paused), true);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    fs.mkdirSync(path.resolve(__dirname, '../data/e2e'), { recursive: true });
    await page.screenshot({ path: path.resolve(__dirname, '../data/e2e/lecteur-vocal-mobile.png') });
    await page.evaluate(() => window.players.destroy());
    assert.equal(await page.evaluate(() => window.players.players.size), 0);
    console.log('PASS vocal ready without opening a file, play/pause, seek, speed, uninterrupted refresh, single decryption, mobile layout and cleanup');
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
