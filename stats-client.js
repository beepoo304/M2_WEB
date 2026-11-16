// M² Web — anonimowe statystyki dla panelu /admin/ (wejścia, zakładki, śledzone klucze, kanały publiczne, błędy).
(() => {
  const ENDPOINT = 'stats/collect.php';
  const SENT_KEYS = 'm2-web-stats-keys-v1', SENT_CHANNELS = 'm2-web-stats-channels-v1';
  let errors = 0, keysTimer = 0;

  function send(event) {
    try {
      const body = JSON.stringify({ ...event, screen: event.screen || document.querySelector('.nav-item.active')?.dataset.screen || '' });
      if (!navigator.sendBeacon?.(ENDPOINT, body)) fetch(ENDPOINT, { method: 'POST', body, keepalive: true }).catch(() => {});
    } catch {}
  }
  function readSet(storage, name) { try { return new Set(JSON.parse(storage.getItem(name) || '[]')); } catch { return new Set(); } }
  function writeSet(storage, name, set) { try { storage.setItem(name, JSON.stringify([...set].slice(-200))); } catch {} }

  // Klucz liczony raz na sesję; czekamy chwilę, aż aplikacja ustali nazwę węzła.
  function keysChanged(keys) {
    clearTimeout(keysTimer);
    keysTimer = setTimeout(() => {
      const sent = readSet(sessionStorage, SENT_KEYS);
      const fresh = (keys || []).filter(item => /^[a-f0-9]{64}$/i.test(item?.key || '') && !sent.has(item.key.toLowerCase()));
      if (!fresh.length) return;
      send({ type: 'keys', keys: fresh.map(item => ({ key: item.key.toLowerCase(), name: item.name || '' })) });
      fresh.forEach(item => sent.add(item.key.toLowerCase()));
      writeSet(sessionStorage, SENT_KEYS, sent);
    }, 5000);
  }
  // Tylko nazwy kanałów publicznych; klucze prywatne nigdy nie opuszczają przeglądarki.
  function channelsChanged(channels) {
    const sent = readSet(localStorage, SENT_CHANNELS);
    (channels || []).filter(item => item && !item.isPrivate && (item.name === 'public' || /^#/.test(item.name || '')) && !sent.has(item.name))
      .forEach(item => { send({ type: 'channel', name: item.name }); sent.add(item.name); });
    writeSet(localStorage, SENT_CHANNELS, sent);
  }
  function error(message, where) {
    if (++errors > 10) return;
    send({ type: 'error', message: String(message || 'Unknown error').slice(0, 400), where: String(where || '').slice(0, 120) });
  }

  window.addEventListener('error', event => error(event.message, event.filename ? `${event.filename.split('/').pop()}:${event.lineno}` : ''));
  window.addEventListener('unhandledrejection', event => error(event.reason?.message || event.reason, 'promise'));
  document.addEventListener('click', event => {
    const item = event.target.closest?.('.nav-item[data-screen]');
    if (item) send({ type: 'screen', screen: item.dataset.screen });
  }, true);
  window.addEventListener('load', () => send({ type: 'visit', referrer: document.referrer }));

  window.M2Stats = { keysChanged, channelsChanged, error };
})();
