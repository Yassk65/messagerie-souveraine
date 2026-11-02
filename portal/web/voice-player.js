const time = seconds => {
  if (!Number.isFinite(seconds) || seconds < 0) return '0:00';
  return `${Math.floor(seconds / 60)}:${String(Math.floor(seconds % 60)).padStart(2, '0')}`;
};
const playIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 5 11 7-11 7z"/></svg>';
const pauseIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 5h4v14H7zM15 5h4v14h-4z"/></svg>';

/** Keep audio objects alive when Matrix refreshes the surrounding timeline. */
export class VoicePlayers {
  constructor() { this.players = new Map(); }

  mount(placeholder, id, content, load) {
    let player = this.players.get(id);
    if (!player) {
      const node = document.createElement('div');
      node.className = 'voice-player';
      node.setAttribute('role', 'group'); node.setAttribute('aria-label', 'Message vocal');
      node.innerHTML = `<button type="button" class="voice-play" aria-label="Écouter le message vocal" disabled>${playIcon}</button><div class="voice-track"><div class="voice-wave" aria-hidden="true">${[8, 16, 22, 12, 28, 18, 34, 22, 14, 26, 18, 30, 12, 20, 32, 16, 24, 12, 28, 18, 10, 24, 16, 30, 20, 12, 26, 16].map(h => `<i style="height:${h}px"></i>`).join('')}</div><input class="voice-seek" type="range" min="0" max="1000" value="0" aria-label="Avancer ou reculer dans le message vocal" disabled><div class="voice-meta"><span class="voice-time">0:00</span><span class="voice-status" role="status">Préparation du vocal…</span></div></div><button type="button" class="voice-speed" aria-label="Vitesse de lecture : 1 fois">1×</button>`;
      const audio = new Audio(); audio.preload = 'metadata';
      player = { node, audio, url: null, disposed: false, duration: (content.info?.duration || 0) / 1000 };
      this.players.set(id, player);
      const button = node.querySelector('.voice-play'), seek = node.querySelector('.voice-seek');
      const status = node.querySelector('.voice-status'), clock = node.querySelector('.voice-time');
      const update = () => {
        const duration = Number.isFinite(audio.duration) ? audio.duration : player.duration;
        player.duration = duration;
        clock.textContent = audio.currentTime > 0 && !audio.ended ? `${time(audio.currentTime)} / ${time(duration)}` : time(duration);
        seek.value = duration > 0 ? Math.min(1000, audio.currentTime / duration * 1000) : 0;
        seek.disabled = !player.url || !duration;
        node.style.setProperty('--voice-progress', `${Number(seek.value) / 10}%`);
        button.innerHTML = audio.paused ? playIcon : pauseIcon;
        button.setAttribute('aria-label', audio.paused ? 'Écouter le message vocal' : 'Mettre le vocal en pause');
      };
      for (const event of ['loadedmetadata', 'durationchange', 'timeupdate', 'play', 'pause', 'ended']) audio.addEventListener(event, update);
      audio.addEventListener('error', () => { status.textContent = 'Lecture indisponible'; button.disabled = true; });
      button.onclick = async () => {
        if (!player.url) { await prepare(); return; }
        if (!audio.paused) { audio.pause(); return; }
        for (const other of this.players.values()) if (other !== player) other.audio.pause();
        try { await audio.play(); status.textContent = 'Message vocal'; }
        catch { status.textContent = 'Lecture impossible. Réessayer.'; }
      };
      seek.oninput = () => { if (player.duration) { audio.currentTime = Number(seek.value) / 1000 * player.duration; update(); } };
      node.querySelector('.voice-speed').onclick = event => {
        audio.playbackRate = audio.playbackRate === 1 ? 1.5 : audio.playbackRate === 1.5 ? 2 : 1;
        event.currentTarget.textContent = `${audio.playbackRate}×`;
        event.currentTarget.setAttribute('aria-label', `Vitesse de lecture : ${audio.playbackRate} fois`);
      };
      const prepare = async () => {
        button.disabled = true; status.textContent = 'Préparation du vocal…';
        try {
          const url = await load(content);
          if (player.disposed) { URL.revokeObjectURL(url); return; }
          player.url = url; audio.src = url; audio.load(); button.disabled = false; status.textContent = 'Message vocal'; update();
          // Older WebM notes may have neither a duration tag nor a Matrix duration.
          if (!player.duration && window.OfflineAudioContext) {
            try {
              const bytes = await (await fetch(url)).arrayBuffer();
              const decoded = await new OfflineAudioContext(1, 1, 48000).decodeAudioData(bytes);
              if (!player.disposed) { player.duration = decoded.duration; update(); }
            } catch { /* The media element can still play formats not supported by Web Audio. */ }
          }
        } catch {
          if (player.disposed) return;
          status.textContent = 'Chargement impossible. Réessayer.'; button.disabled = false;
          button.setAttribute('aria-label', 'Réessayer de charger le message vocal');
        }
      };
      prepare();
    }
    placeholder.replaceWith(player.node);
  }

  retain(visibleIds) {
    for (const [id, player] of this.players) if (!visibleIds.has(id)) player.audio.pause();
  }
  destroy() {
    for (const player of this.players.values()) {
      player.disposed = true; player.audio.pause(); player.audio.removeAttribute('src'); player.audio.load();
      if (player.url) URL.revokeObjectURL(player.url);
    }
    this.players.clear();
  }
}
