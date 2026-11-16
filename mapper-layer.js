// Zasięg z mappera MeshCore (domyślnie meshcoresouth.pl/mapper): kolorowe heksy wg najlepszego SNR + repeatery mappera.
// Heksy, skala kolorów i rozmiary jak w mapperze; dane przez nasz mapper.php (mapper nie ma CORS). W locie ukryte.
const M2Mapper = (() => {
  const API_KEY = 'm2-web-mapper-api', ON_KEY = 'm2-web-mapper-on', OPACITY_KEY = 'm2-web-mapper-opacity';
  const DEFAULT_API = 'https://meshcoresouth.pl/mapper/api.php';
  const STOPS = ['#b2182b', '#ef8a3c', '#f2d15c', '#5fb49c', '#1b6ca8'], SNR_MIN = -8, SNR_MAX = 12;
  const HEX0 = { lat: 50, lon: 19 }, HEX_KX = 111320 * Math.cos(50 * Math.PI / 180), HEX_KY = 110574, SQ3 = Math.sqrt(3);
  const hexSize = z => z >= 17 ? 11 : z >= 16 ? 18 : z >= 15 ? 28 : z >= 14 ? 45 : z >= 13 ? 75 : z >= 12 ? 130 : z >= 11 ? 230 : z >= 10 ? 420 : z >= 9 ? 750 : z >= 8 ? 1400 : z >= 7 ? 2600 : z >= 6 ? 5000 : 9500;
  const state = { view: null, cells: null, reps: null, points: null, repeaters: null, loading: null, suspended: false, renderer: null };
  const read = (key, fallback) => { try { return localStorage.getItem(key) ?? fallback; } catch { return fallback; } };
  const write = (key, value) => { try { if (value === null) localStorage.removeItem(key); else localStorage.setItem(key, value); } catch {} };
  const api = () => read(API_KEY, '') || DEFAULT_API;
  const isOn = () => read(ON_KEY, '0') === '1';
  const opacity = () => Math.max(10, Math.min(100, Number(read(OPACITY_KEY, '70')) || 70));

  const rgb = h => [1, 3, 5].map(i => parseInt(h.slice(i, i + 2), 16));
  function color(snr) {
    const t = Math.max(0, Math.min(1, (snr - SNR_MIN) / (SNR_MAX - SNR_MIN)));
    const x = t * (STOPS.length - 1), i = Math.min(STOPS.length - 2, Math.floor(x)), f = x - i, a = rgb(STOPS[i]), b = rgb(STOPS[i + 1]);
    return '#' + a.map((v, k) => Math.round(v + (b[k] - v) * f).toString(16).padStart(2, '0')).join('');
  }
  function hexKey(lat, lon, sz) {
    const x = (lon - HEX0.lon) * HEX_KX, y = (lat - HEX0.lat) * HEX_KY;
    const q = (SQ3 / 3 * x - y / 3) / sz, r = (2 / 3 * y) / sz, s = -q - r;
    let rq = Math.round(q), rr = Math.round(r); const rs = Math.round(s);
    const dq = Math.abs(rq - q), dr = Math.abs(rr - r), ds = Math.abs(rs - s);
    if (dq > dr && dq > ds) rq = -rr - rs; else if (dr > ds) rr = -rq - rs;
    return [rq, rr];
  }
  function hexRing(q, r, sz) {
    const x = sz * SQ3 * (q + r / 2), y = sz * 1.5 * r, cla = HEX0.lat + y / HEX_KY, clo = HEX0.lon + x / HEX_KX, out = [];
    for (let i = 0; i < 6; i++) { const a = Math.PI / 180 * (60 * i - 30); out.push([cla + sz * Math.sin(a) / HEX_KY, clo + sz * Math.cos(a) / HEX_KX]); }
    return out;
  }

  async function fetchAction(action) {
    const response = await fetch(`mapper.php?action=${action}&api=${encodeURIComponent(api())}`, { cache: 'no-cache' });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !Array.isArray(data.items)) throw new Error(data.error || `HTTP ${response.status}`);
    return data.items;
  }
  function load() {
    if (state.points && state.repeaters) return Promise.resolve();
    if (!state.loading) {
      updateControls();
      state.loading = Promise.all([fetchAction('points'), fetchAction('repeaters')])
        .then(([points, repeaters]) => { state.points = points; state.repeaters = repeaters; })
        .finally(() => { state.loading = null; updateControls(); });
    }
    return state.loading;
  }

  function drawCells() {
    const view = state.view; if (!view || !state.cells || !state.points) return;
    state.cells.clearLayers();
    const zoom = view.getZoom(), sz = hexSize(zoom), bounds = view.getBounds().pad(0.25), cells = new Map();
    const edge = sz / (156543 * Math.cos(view.getCenter().lat * Math.PI / 180) / 2 ** zoom) >= 7;   // biała obwódka tylko przy dużych heksach
    for (const [lat, lon, best, pings] of state.points) {
      if (!bounds.contains([lat, lon])) continue;
      const [q, r] = hexKey(lat, lon, sz), key = q + ':' + r;
      let cell = cells.get(key); if (!cell) cells.set(key, cell = { q, r, best: null, hits: 0 });
      if (best !== null) { cell.hits += pings; if (cell.best === null || best > cell.best) cell.best = best; }
    }
    for (const cell of [...cells.values()].sort((a, b) => (a.best ?? -1e9) - (b.best ?? -1e9))) {   // mocniejsze na wierzchu
      const style = cell.best === null
        ? { renderer: state.renderer, interactive: false, stroke: false, fillColor: '#8a99a3', fillOpacity: edge ? .3 : .45 }
        : { renderer: state.renderer, interactive: false, stroke: edge, color: '#fff', weight: .6, opacity: .7, fillColor: color(cell.best), fillOpacity: cell.hits > 1 ? .8 : .6 };
      L.polygon(hexRing(cell.q, cell.r, sz), style).addTo(state.cells);
    }
  }
  function drawRepeaters() {
    if (!state.reps || !state.repeaters) return;
    state.reps.clearLayers();
    const radius = state.view.getZoom() < 9 ? 3 : 5;
    for (const [name, lat, lon, city] of state.repeaters) {
      L.circleMarker([lat, lon], { pane: 'm2-mapper-rpt', radius, color: '#fff', weight: radius > 3 ? 1.5 : 1, fillColor: '#7e57c2', fillOpacity: .95 })
        .bindPopup(`<b>${escapeHtml(name || 'Repeater')}</b>${city ? `<br><small>${escapeHtml(city)}</small>` : ''}<br><small>Mapper</small>`)
        .addTo(state.reps);
    }
  }
  function applyVisibility() {
    const view = state.view; if (!view) return;
    const visible = isOn() && !state.suspended;
    for (const name of ['m2-mapper', 'm2-mapper-rpt']) { const pane = view.getPane(name); if (pane) pane.style.display = visible ? '' : 'none'; }
    const pane = view.getPane('m2-mapper'); if (pane) pane.style.opacity = String(opacity() / 100);
    if (visible && state.points && state.cells && !state.cells.getLayers().length) { drawCells(); drawRepeaters(); }
  }
  function refresh() { if (isOn() && !state.suspended && state.points) { drawCells(); drawRepeaters(); } }

  /** Wywoływane po utworzeniu mapy Leaflet (mapRender tworzy ją przy każdym wejściu na zakładkę Map). */
  function attach(view) {
    state.view = view;
    view.createPane('m2-mapper').style.zIndex = 350;        // pod liniami i repeaterami M²
    view.createPane('m2-mapper-rpt').style.zIndex = 390;
    state.renderer = L.canvas({ pane: 'm2-mapper', padding: .3 });
    state.cells = L.layerGroup().addTo(view);
    state.reps = L.layerGroup().addTo(view);
    view.on('zoomend moveend', () => { if (state.view === view) refresh(); });
    bindControls();
    applyVisibility();
    if (isOn()) show();
  }
  function show() {
    load().then(() => { if (!state.view) return; drawCells(); drawRepeaters(); applyVisibility(); })
      .catch(error => { write(ON_KEY, '0'); applyVisibility(); updateControls(); window.mapMessage?.(`Mapper: ${error.message}`); });
  }
  function toggle() {
    write(ON_KEY, isOn() ? '0' : '1');
    applyVisibility(); updateControls();
    if (isOn()) show();
  }
  function suspend(on) { if (state.suspended === !!on) return; state.suspended = !!on; if (!on) refresh(); applyVisibility(); }

  function bindControls() {
    const button = document.getElementById('map-mapper'), range = document.getElementById('map-mapper-opacity');
    if (!button || !range) return;
    button.addEventListener('click', toggle);
    range.value = String(opacity());
    range.addEventListener('input', () => { write(OPACITY_KEY, range.value); applyVisibility(); });
    updateControls();
  }
  function updateControls() {
    const button = document.getElementById('map-mapper'), box = document.querySelector('.m2-mapper'); if (!button || !box) return;
    const on = isOn();
    button.classList.toggle('on', on); button.setAttribute('aria-pressed', String(on));
    button.textContent = state.loading ? 'Mapper…' : 'Mapper';
    box.classList.toggle('on', on);
  }
  function setApi(url) {
    const value = String(url || '').trim();
    write(API_KEY, value && value !== DEFAULT_API ? value : null);
    state.points = state.repeaters = null;
    state.cells?.clearLayers(); state.reps?.clearLayers();
    if (state.view && isOn()) show();
  }
  return { attach, suspend, setApi, api, DEFAULT_API };
})();
