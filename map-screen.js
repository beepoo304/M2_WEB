// M² Web — ekran Map: sesja śledzenia (Start/Stop/Restart), tryby, trasy, dystans, najdłuższa trasa i lot.
// Logika geometrii/dystansów: map-core.js. Ten plik łączy ją z danymi Live (app.js) i Leaflet.
const MAP_SESSION_STORAGE = 'm2-web-map-session-v1';
const MAP_HISTORY_STORAGE = 'm2-web-longest-history-v1';
const MAP_MAX_EVENTS = 5000;
const MAP_HISTORY_LIMIT = 1000;
// Podkład 1:1 jak meshcoresouth.pl/mapper (tryb „Jasny, wyszarzony”): kafelki OSM + filtr CSS na .leaflet-tile-pane.
const MAP_TILES = { url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png', maxZoom: 19, attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>' };

const mapState = {
  key: '', mode: 'ALL_FOR_SELECTED_KEY', running: false, committed: false, events: new Map(),
  directory: [], located: [], directorySource: '', directoryError: '',
  view: null, layer: null, flightLayer: null, flightFrame: 0, flight: null, fullscreen: false, startedAt: 0, name: '',
  pulseTimer: 0, pulseOn: false, pulseRing: null, messageTimer: 0, focusedKey: '',
  baselineCounts: new Map(), processedCounts: new Map()
};

function mapSnapshotBaseline() {
  mapState.baselineCounts = new Map();
  mapState.processedCounts = new Map();
  if (Array.isArray(liveState.packets)) {
    liveState.packets.forEach(packet => {
      const ident = packetIdentity(packet);
      const count = Number(packet.observation_count || 1);
      mapState.baselineCounts.set(ident, count);
      mapState.processedCounts.set(ident, count);
    });
  }
}

function mapLoadSession() {
  try {
    const s = JSON.parse(sessionStorage.getItem(MAP_SESSION_STORAGE) || 'null');
    if (!s) return;
    mapState.key = String(s.key || ''); mapState.mode = MapCore.MODES[s.mode] ? s.mode : 'ALL_FOR_SELECTED_KEY';
    mapState.running = !!s.running; mapState.committed = !!s.committed;
    mapState.startedAt = Number(s.startedAt) || 0; mapState.name = String(s.name || '');
    mapState.baselineCounts = new Map(Array.isArray(s.baseline) ? s.baseline : []);
    mapState.processedCounts = new Map(Array.isArray(s.processed) ? s.processed : []);
    (Array.isArray(s.events) ? s.events : []).forEach(e => mapState.events.set(e.id, e));
  } catch {}
}
function mapSaveSession() {
  try {
    sessionStorage.setItem(MAP_SESSION_STORAGE, JSON.stringify({
      key: mapState.key, mode: mapState.mode, running: mapState.running, committed: mapState.committed, startedAt: mapState.startedAt, name: mapState.name,
      baseline: mapState.baselineCounts ? [...mapState.baselineCounts.entries()] : [],
      processed: mapState.processedCounts ? [...mapState.processedCounts.entries()] : [],
      events: [...mapState.events.values()]
    }));
  } catch {}
}
// Historia najdłuższych tras: tylko klucz i dystans (km), maks. 1000 na klucz, najstarsze nadpisywane.
function mapLoadHistory() { try { return JSON.parse(localStorage.getItem(MAP_HISTORY_STORAGE) || '{}') || {}; } catch { return {}; } }
function mapSaveHistory(history) { try { localStorage.setItem(MAP_HISTORY_STORAGE, JSON.stringify(history)); } catch {} }
function mapCommitLongest(key, km) {
  const history = mapLoadHistory(), id = key.toUpperCase();
  const entry = history[id] || { km: [], pending: false };
  const previousBest = entry.km.reduce((max, value) => Math.max(max, value), 0);
  const record = km > previousBest;            // rekord liczony tylko względem wyników tego samego klucza
  entry.km.push(Math.round(km * 100) / 100);
  if (entry.km.length > MAP_HISTORY_LIMIT) entry.km.splice(0, entry.km.length - MAP_HISTORY_LIMIT);
  if (record) entry.pending = true;
  history[id] = entry; mapSaveHistory(history);
  return record;
}
const mapRecordPending = key => !!mapLoadHistory()[String(key).toUpperCase()]?.pending;
function mapClearPending(key) {
  const history = mapLoadHistory(), id = String(key).toUpperCase();
  if (history[id]?.pending) { history[id].pending = false; mapSaveHistory(history); }
}

function mapRoutesForPacket(packet) {
  const cached = observationMatchCache.get(String(packet.id));
  if (cached?.data?.loadSucceeded) {
    const routes = observationRoutes(cached.data);
    if (routes.length) return routes.map(r => ({ path: r.path.map(h => String(h).trim().toUpperCase()), resolved: r.resolved, observerId: String(r.observer.observer_id || '') }));
  }
  return [{ path: packetPath(packet), resolved: Array.isArray(packet.resolved_path) ? packet.resolved_path : [], observerId: String(packet.observer_id || '') }];
}

/** Wywoływane po każdym odświeżeniu Live i po pobraniu szczegółów obserwacji. */
function mapIngest() {
  if (!mapState.running || !mapState.key) return;
  let added = false;
  liveState.packets.forEach(packet => {
    const ident = packetIdentity(packet);
    const count = Number(packet.observation_count || 1);
    const baseCount = mapState.baselineCounts ? (mapState.baselineCounts.get(ident) || 0) : 0;
    const procCount = mapState.processedCounts ? (mapState.processedCounts.get(ident) || 0) : 0;
    const isNew = !mapState.baselineCounts || !mapState.baselineCounts.has(ident) || count > baseCount;
    if (!isNew || procCount >= count) return;

    mapRoutesForPacket(packet).forEach(route => {
      const matches = relationMatches({ ...packet, _parsedPath: route.path, path_json: JSON.stringify(route.path), resolved_path: route.resolved, observer_id: route.observerId });
      const event = MapCore.routeEvent({
        id: ident, hash: packet.hash, payloadType: packet.payload_type,
        timestamp: packet.timestamp || packet.first_seen, route, matches, key: mapState.key, mode: mapState.mode,
        channel: parseDecoded(packet).channel || '', channelHash: parseDecoded(packet).channelHashHex || ''
      });
      if (event && !mapState.events.has(event.id)) { mapState.events.set(event.id, event); added = true; }
    });
    if (mapState.processedCounts) {
      mapState.processedCounts.set(ident, count);
    }
  });
  if (mapState.events.size > MAP_MAX_EVENTS) {
    [...mapState.events.keys()].slice(0, mapState.events.size - MAP_MAX_EVENTS).forEach(id => mapState.events.delete(id));
  }
  if (added) { mapSaveSession(); if (currentScreen() === 'Map') updateMapView(); }
  else if (currentScreen() === 'Map') mapUpdatePanel();
}

async function mapEnsureDirectory() {
  const source = activeApiSource, cached = gpsDirectoryCache.get(source);
  const fresh = cached && Date.now() - cached.loadedAt < GPS_DIRECTORY_CACHE_MS;
  if (!fresh) {
    try {
      const response = await fetch(apiProxyUrl('directory', {}, source), { cache: 'no-store' });
      const data = await response.json();
      if (!response.ok || !Array.isArray(data.nodes)) throw new Error(data.error || `HTTP ${response.status}`);
      gpsDirectoryCache.set(source, { loadedAt: Date.now(), nodes: data.nodes });
      mapState.directoryError = '';
    } catch (error) { mapState.directoryError = error.message || 'Directory unavailable'; }
  }
  const nodes = gpsDirectoryCache.get(source)?.nodes;
  if (nodes && mapState.directorySource !== `${source}|${gpsDirectoryCache.get(source).loadedAt}`) {
    const built = MapCore.buildDirectory(nodes);
    mapState.directory = built.directory; mapState.located = built.located;
    mapState.directorySource = `${source}|${gpsDirectoryCache.get(source).loadedAt}`;
  }
}

function mapMetrics() {
  const events = [...mapState.events.values()];
  const metrics = MapCore.metrics(events, mapState.located, mapState.directory);
  // MAX HOPS jak w M²: tylko zdarzenia bez dopisanego (inferowanego) ostatniego hopa.
  const maxHops = events.filter(e => !e.inferredLastHop).reduce((max, e) => Math.max(max, e.path.length - 1), 0);
  const packets = new Set(events.map(e => e.packetId || e.id)).size;
  const edges = MapCore.edges(events, mapState.located, mapState.directory);
  return { ...metrics, packets, routes: events.length, links: edges.length, maxHops, edges };
}

const mapKm1 = value => `${Number(value || 0).toFixed(1)} km`;
const mapKeyShort = key => String(key || '').slice(0, 4).toUpperCase();
const mapSelected = () => trackedKeys.find(k => k.key.toLowerCase() === mapState.key.toLowerCase());

function mapBestKm(key) { return (mapLoadHistory()[String(key).toUpperCase()]?.km || []).reduce((max, v) => Math.max(max, v), 0); }
/** longestRouteIsNewRecord z NetworkMapViewModel: km > rekord albo nieodczytany rekord równy bieżącemu. */
function mapIsNewRecord(km) {
  if (km <= 0) return false;
  const best = mapBestKm(mapState.key);
  return km > best + 0.005 || (mapRecordPending(mapState.key) && Math.abs(km - best) < 0.01);
}

function mapStart() {
  if (!mapState.key || mapState.running) return;
  if (mapState.committed) { mapState.events.clear(); mapState.committed = false; mapState.startedAt = 0; mapState.name = ''; }
  if (!mapState.baselineCounts || mapState.baselineCounts.size === 0 || !mapState.startedAt) mapSnapshotBaseline();
  if (!mapState.startedAt) mapState.startedAt = Date.now();
  mapState.running = true; mapSaveSession();
  mapIngest(); mapUpdatePanel(); updateMapView();
  mapEnsureDirectory().then(() => currentScreen() === 'Map' && updateMapView());
}
function mapStop() {
  mapCancelFlight();
  if (!mapState.running) { mapUpdatePanel(); return; }
  mapState.running = false;
  const km = mapMetrics().longestRouteKm;
  if (!mapState.committed && km > 0) mapCommitLongest(mapState.key, km);
  mapState.committed = true; mapSaveSession(); mapUpdatePanel(); updateMapView();
}
/** Restart: anuluje lot, czyści sesję (tryb zostaje), centruje wybrany węzeł na zoom 12. */
function mapRestart() {
  mapCancelFlight();
  mapState.events.clear(); mapState.running = false; mapState.committed = false; mapState.startedAt = 0; mapState.name = '';
  mapSnapshotBaseline(); mapSaveSession(); mapUpdatePanel(); updateMapView(); mapFocusSelected();
}
function mapFocusSelected() {
  const node = mapState.located.find(n => n.key.toLowerCase() === mapState.key.toLowerCase());
  if (node && mapState.view) mapState.view.flyTo([node.lat, node.lon], 12, { duration: .8 });
}

function leaveMap() {
  mapCancelFlight();
  clearInterval(mapState.pulseTimer); clearTimeout(mapState.messageTimer);
  document.body.classList.remove('map-fs-on');
  if (mapState.view) { mapState.view.remove(); mapState.view = null; mapState.layer = null; mapState.flightLayer = null; }
  mapState.fullscreen = false;
}

const MAP_FS_ICON = '<svg viewBox="0 0 24 24" width="26" height="26" aria-hidden="true"><path fill="currentColor" d="M7 14H5v5h5v-2H7v-3zm-2-4h2V7h3V5H5v5zm12 7h-3v2h5v-5h-2v3zM14 5v2h3v3h2V5h-5z"/></svg>';
const MAP_FS_EXIT_ICON = '<svg viewBox="0 0 24 24" width="30" height="30" aria-hidden="true"><path fill="currentColor" d="M5 16h3v3h2v-5H5v2zm3-8H5v2h5V5H8v3zm6 11h2v-3h3v-2h-5v5zm2-11V5h-2v5h5V8h-3z"/></svg>';

function mapRender() {
  leaveMap();
  if (!trackedKeys.some(k => k.key.toLowerCase() === mapState.key.toLowerCase())) mapState.key = trackedKeys[0]?.key || '';
  const modeOptions = Object.entries(MapCore.MODES).map(([id, label]) => `<option value="${id}">${label}</option>`).join('');
  screen.innerHTML = `<section class="map-screen map-full m2-map">
    <div id="map-canvas" aria-label="Network map"></div>
    <div class="map-panel m2-map-panel">
      <div class="m2-field m2-key-field"><span class="m2-field-label">Tracked key</span>
        <button type="button" id="map-key-button" class="m2-select" aria-haspopup="listbox"><span id="map-key-value"></span><i aria-hidden="true">▾</i></button>
        <div id="map-key-menu" class="m2-menu" role="listbox" hidden></div></div>
      <div class="m2-map-row">
        <label class="m2-field m2-mode-field"><span class="m2-field-label">Traffic mode</span>
          <select id="map-mode" class="m2-select">${modeOptions}</select></label>
        <button type="button" id="map-export" class="m2-outline">Export</button>
        <button type="button" id="map-import" class="m2-outline">Load</button>
      </div>
      <div class="m2-map-row m2-map-actions">
        <button type="button" id="map-toggle" class="m2-pill m2-pill-primary"></button>
        <button type="button" id="map-restart" class="m2-pill m2-pill-outline"><span aria-hidden="true">↻</span> Restart</button>
      </div>
      <div id="map-status" class="m2-map-status" role="status" aria-live="polite"></div>
      <div id="map-counts" class="m2-map-line"></div>
      <div id="map-distance" class="m2-map-line"></div>
      <div class="m2-map-row m2-hops-row"><span id="map-hops" class="m2-map-line"></span>
        <button type="button" id="map-longest" class="m2-longest">Longest route <b id="map-longest-km">0.0 km</b></button></div>
      <div id="map-error" class="m2-map-error"></div>
      <div id="map-progress" class="m2-progress" hidden><span></span></div>
      <div id="map-message" class="m2-map-message"></div>
    </div>
    <button type="button" id="map-fs" class="m2-fs-button" title="Fullscreen" aria-label="Fullscreen">${MAP_FS_ICON}</button>
    <button type="button" id="map-fs-exit" class="m2-fs-exit" title="Exit fullscreen" aria-label="Exit fullscreen">${MAP_FS_EXIT_ICON}</button>
    <img class="m2-fs-logo" src="assets/m2-logo.svg" alt="M²">
    <div id="map-compass" class="m2-compass" hidden>N 000°</div>
  </section>`;
  const keyButton = document.getElementById('map-key-button'), keyMenu = document.getElementById('map-key-menu');
  keyButton.addEventListener('click', () => { if (!keyButton.disabled) keyMenu.hidden = !keyMenu.hidden; });
  keyMenu.addEventListener('click', e => {
    const item = e.target.closest('[data-map-key]'); if (!item) return;
    keyMenu.hidden = true;
    if (item.dataset.mapKey.toLowerCase() === mapState.key.toLowerCase()) return;
    mapState.key = item.dataset.mapKey; mapRestart();
  });
  document.addEventListener('click', mapCloseKeyMenu);
  document.getElementById('map-mode').addEventListener('change', e => { mapState.mode = e.target.value; mapSaveSession(); mapUpdatePanel(); });
  document.getElementById('map-toggle').addEventListener('click', () => (mapState.running || mapState.flight ? mapStop() : mapStart()));
  document.getElementById('map-restart').addEventListener('click', mapRestart);
  document.getElementById('map-longest').addEventListener('click', mapLongestClicked);
  document.getElementById('map-export').addEventListener('click', mapExportFile);
  document.getElementById('map-import').addEventListener('click', mapImportDialog);
  document.getElementById('map-fs').addEventListener('click', () => mapSetFullscreen(true));
  document.getElementById('map-fs-exit').addEventListener('click', () => mapSetFullscreen(false));
  mapUpdatePanel();
  if (typeof L === 'undefined') { mapError('The map library failed to load.'); return; }
  mapState.view = L.map('map-canvas', { zoomControl: false, attributionControl: false, zoomSnap: 1, zoomDelta: 1, wheelPxPerZoomLevel: 90, preferCanvas: true, renderer: L.canvas({ padding: .5 }) })
    .setView([50.15, 19.2], 7);
  L.control.attribution({ position: 'bottomright', prefix: false }).addTo(mapState.view);
  L.tileLayer(MAP_TILES.url, { maxZoom: MAP_TILES.maxZoom, attribution: MAP_TILES.attribution }).addTo(mapState.view);
  mapState.layer = L.layerGroup().addTo(mapState.view);
  mapState.flightLayer = L.layerGroup().addTo(mapState.view);
  mapState.pulseOn = false;
  mapState.pulseTimer = setInterval(mapPulse, 850);
  updateMapView();
  mapEnsureDirectory().then(() => { if (currentScreen() === 'Map') { updateMapView(); mapUpdatePanel(); } });
}
function mapCloseKeyMenu(e) {
  const menu = document.getElementById('map-key-menu');
  if (!menu) { document.removeEventListener('click', mapCloseKeyMenu); return; }
  if (!e.target.closest('.m2-key-field')) menu.hidden = true;
}

function mapSetFullscreen(on) {
  if (!on) mapCancelFlight();                     // jak w M²: wyjście z pełnego ekranu przerywa lot i nagrywanie
  mapState.fullscreen = on;
  document.querySelector('.m2-map')?.classList.toggle('fs', on);
  document.body.classList.toggle('map-fs-on', on);
  setTimeout(() => mapState.view?.invalidateSize(), 60);
}

function mapError(text) { const el = document.getElementById('map-error'); if (el) el.textContent = text || ''; }
/** Komunikat jak w M²: znika po 3 s. */
function mapMessage(text) {
  const el = document.getElementById('map-message'); if (!el) return;
  el.textContent = text; clearTimeout(mapState.messageTimer);
  mapState.messageTimer = setTimeout(() => { el.textContent = ''; }, 3000);
}
function mapProgress(on) { const el = document.getElementById('map-progress'); if (el) el.hidden = !on; }

/** Tylko panel — mapa Leaflet nie jest tworzona od nowa przy Start/Stop/Restart. */
function mapUpdatePanel() {
  if (currentScreen() !== 'Map') return;
  const $ = id => document.getElementById(id); if (!$('map-status')) return;
  const noKey = !trackedKeys.length, running = mapState.running, selected = mapSelected();
  $('map-key-value').innerHTML = selected ? `${escapeHtml(mapKeyShort(selected.key))}` : '<span class="m2-muted">No saved keys</span>';
  $('map-key-button').disabled = noKey;
  $('map-key-button').closest('.m2-field').classList.toggle('active', running);
  $('map-key-menu').innerHTML = trackedKeys.map(k => `<button type="button" role="option" data-map-key="${escapeHtml(k.key)}"><b>${escapeHtml(mapKeyShort(k.key))}</b> ${escapeHtml(k.name || '')}</button>`).join('');
  const mode = $('map-mode'); mode.value = mapState.mode; mode.disabled = running;
  const toggle = $('map-toggle'), stop = running || !!mapState.flight;
  toggle.innerHTML = stop ? '<span class="m2-ico-stop" aria-hidden="true"></span> Stop' : '<span aria-hidden="true">▷</span> Start';
  toggle.disabled = noKey; $('map-restart').disabled = noKey;
  const status = $('map-status');
  const loading = !mapState.located.length && !mapState.directoryError && !!mapState.key;
  status.textContent = loading ? 'Loading repeater locations…'
    : running ? `TRACKING · ${mapKeyShort(mapState.key)} · ${MapCore.MODES[mapState.mode]}`
    : `STOPPED${mapState.key ? ` · ${mapKeyShort(mapState.key)}` : ''}`;
  status.classList.toggle('tracking', running && !loading);
  const m = mapMetrics();
  $('map-counts').textContent = `Packets ${m.packets} · Routes ${m.routes} · Links ${m.links}`;
  $('map-distance').textContent = `UNIQUE LINKS DISTANCE ${mapKm1(m.totalUniqueKm)}`;
  $('map-hops').textContent = `MAX HOPS ${m.maxHops}`;
  $('map-longest-km').textContent = mapKm1(m.longestRouteKm);
  $('map-longest-km').classList.toggle('record', mapIsNewRecord(m.longestRouteKm));
  $('map-longest').disabled = m.longestRoute.length < 2;
  mapError(mapState.directoryError ? `Node directory unavailable: ${mapState.directoryError}` : '');
}

// osmdroid rysuje w fizycznych pikselach telefonu; przeliczenie na px CSS (gęstość xxhdpi ≈ 2.75).
const APK_PX = 1 / 2.75;
/** Styl krawędzi 1:1 z NetworkMapScreen.kt (kolor, grubość wg liczby obserwacji, przerywana gdy niepewna). */
function mapEdgeStyle(edge) {
  const color = edge.missingGps ? '#AB47BC' : edge.reply || edge.uncertain ? '#F0A84B' : '#42D47B';
  const confirmed = !edge.uncertain && !edge.missingGps;
  const width = (2.6 + Math.min(edge.count, 8) * .22) * (confirmed || edge.reply ? 1.4 : 1) * APK_PX;
  const alpha = edge.uncertain ? Math.min(175 + edge.count * 8, 255) / 255 : 1;
  return { color, weight: width, opacity: alpha, dashArray: edge.uncertain ? '3 2' : null, lineCap: edge.uncertain ? 'butt' : 'round' };
}
const mapSegKey = (a, b) => [a.key.toUpperCase(), b.key.toUpperCase()].sort().join('|');

function mapDrawEdges(layer, edges, sharedReply) {
  // Kolejność jak w M²: najpierw zwykłe, odpowiedzi na wierzchu; odpowiedzi pokrywające najdłuższą trasę ukryte.
  [...edges].sort((a, b) => Number(a.reply) - Number(b.reply))
    .filter(e => !(e.reply && sharedReply.has(mapSegKey(e.from, e.to))))
    .forEach(edge => {
      const style = mapEdgeStyle(edge), latlngs = [[edge.from.lat, edge.from.lon], [edge.to.lat, edge.to.lon]];
      L.polyline(latlngs, { color: '#191D1B', opacity: .85, weight: style.weight + 4 * APK_PX, lineCap: 'round', interactive: false }).addTo(layer);
      L.polyline(latlngs, { ...style, interactive: false }).addTo(layer);
    });
}
function mapDrawLongest(layer, route, sharedReply) {
  route.slice(1).forEach((b, i) => {
    const a = route[i]; if (b.missingBefore.length || b.unknownBefore) return;
    const latlngs = [[a.lat, a.lon], [b.lat, b.lon]];
    L.polyline(latlngs, { color: '#2196F3', weight: 4.2 * APK_PX, opacity: 1, lineCap: 'round', interactive: false }).addTo(layer);
    if (sharedReply.has(mapSegKey(a, b))) L.polyline(latlngs, { color: '#F0A84B', weight: 4.2 * APK_PX, opacity: 1, dashArray: '32 32', lineCap: 'butt', interactive: false }).addTo(layer);
  });
}
function mapDrawNodes(layer, edges) {
  const points = new Map();
  edges.forEach(edge => [edge.from, edge.to].forEach(p => {
    const id = p.key.toUpperCase(), prev = points.get(id);
    points.set(id, { p, uncertain: prev ? prev.uncertain && edge.uncertain : edge.uncertain });
  }));
  const selectedId = mapState.key.toUpperCase();
  const selected = mapState.located.find(n => n.key.toUpperCase() === selectedId);
  if (selected && !points.has(selectedId)) points.set(selectedId, { p: { ...selected, hash: selected.key.slice(0, 4), sourceHash: selected.key.slice(0, 4) }, uncertain: false });
  mapState.pulseRing = null;
  points.forEach(({ p, uncertain }, id) => {
    const isSelected = id === selectedId;
    if (isSelected) mapState.pulseRing = L.circleMarker([p.lat, p.lon], { radius: 22 * APK_PX, color: '#35E879', weight: 1, opacity: .6, fillColor: '#35E879', fillOpacity: .09, interactive: false }).addTo(layer);
    const tip = uncertain && p.sourceHash && p.sourceHash.toUpperCase() !== p.hash.toUpperCase() ? `${p.sourceHash} → ${p.hash}` : p.hash;
    L.circleMarker([p.lat, p.lon], { radius: (isSelected ? 16 : 12) * APK_PX, color: '#101215', weight: 1, fillColor: uncertain ? '#FFA726' : '#35E879', fillOpacity: 1 })
      .bindTooltip(escapeHtml(tip.toUpperCase()), { direction: 'top', className: 'm2-tip' }).addTo(layer);
  });
}
function mapPulse() {
  mapState.pulseOn = !mapState.pulseOn;
  // Jak w M²: pierścień 56↔44 px (inset 4/10 w ikonie 64 px).
  mapState.pulseRing?.setRadius((mapState.pulseOn ? 28 : 22) * APK_PX);
}
function mapSharedReplySegments(edges, route) {
  const routeSegs = new Set(route.slice(1).map((b, i) => mapSegKey(route[i], b)));
  return new Set(edges.filter(e => e.reply && routeSegs.has(mapSegKey(e.from, e.to))).map(e => mapSegKey(e.from, e.to)));
}

function updateMapView() {
  if (currentScreen() !== 'Map') return;
  mapUpdatePanel();
  if (!mapState.layer || mapState.flight) return;     // w trakcie lotu warstwy rysuje animacja
  const m = mapMetrics(), shared = mapSharedReplySegments(m.edges, m.longestRoute);
  mapState.layer.clearLayers();
  mapDrawEdges(mapState.layer, m.edges, shared);
  if (m.longestRoute.length > 1) mapDrawLongest(mapState.layer, m.longestRoute, shared);
  mapDrawNodes(mapState.layer, m.edges);
  const key = mapState.key.toLowerCase();
  if (key && mapState.focusedKey !== key && mapState.located.some(n => n.key.toLowerCase() === key)) { mapState.focusedKey = key; mapFocusSelected(); }
}

// ---------- Lot po najdłuższej trasie (port LaunchedEffect(animationToken) z NetworkMapScreen.kt) ----------
function mapFlightZoom(km) { return km < 1 ? 18.5 : km < 3 ? 17.5 : km < 5 ? 16.7 : km < 8 ? 15.5 : km < 20 ? 14 : km < 50 ? 12.7 : km < 100 ? 11.4 : 10; }
function mapMercY(lat) { const s = Math.sin(lat * Math.PI / 180); return .5 - Math.log((1 + s) / (1 - s)) / (4 * Math.PI); }
function mapFitSegmentZoom(a, b) {
  const size = mapState.view.getSize();
  const fx = Math.max(Math.abs(a.lon - b.lon) / 360, 1e-9), fy = Math.max(Math.abs(mapMercY(a.lat) - mapMercY(b.lat)), 1e-9);
  const w = Math.max((size.x - 260) / 2, 160), h = Math.max((size.y - 360) / 2, 240);
  return Math.min(18.5, Math.max(4, Math.min(Math.log2(w / 256 / fx), Math.log2(h / 256 / fy))));
}
function mapBearing(a, b) {
  const r = Math.PI / 180, y = Math.sin((b.lon - a.lon) * r) * Math.cos(b.lat * r);
  const x = Math.cos(a.lat * r) * Math.sin(b.lat * r) - Math.sin(a.lat * r) * Math.cos(b.lat * r) * Math.cos((b.lon - a.lon) * r);
  return (Math.atan2(y, x) / r + 360) % 360;
}
function mapBadge(layer, point, text, anchor = 1.35) {
  const icon = L.divIcon({ className: 'm2-flight-badge-wrap', html: `<div class="m2-flight-badge" style="--anchor:${anchor}">${escapeHtml(text)}</div>`, iconSize: [0, 0] });
  return L.marker([point.lat, point.lon], { icon, interactive: false, keyboard: false, zIndexOffset: 1000 }).addTo(layer);
}
function mapFade(markers, ms = 500) {
  markers.filter(Boolean).forEach(m => { const el = m.getElement()?.firstChild; if (el) { el.style.transition = `opacity ${ms}ms`; el.style.opacity = '0'; } });
  return new Promise(resolve => setTimeout(() => { markers.filter(Boolean).forEach(m => m.remove()); resolve(); }, ms));
}
function mapCancelFlight(keepRecording) {
  if (!keepRecording) mapRecCancel();
  if (!mapState.flight) return;
  mapState.flight.cancelled = true; mapState.flight = null;
  if (mapState.view) mapState.view.options.zoomSnap = 1;
  cancelAnimationFrame(mapState.flightFrame);
  mapState.flightLayer?.clearLayers();
  const compass = document.getElementById('map-compass'); if (compass) compass.hidden = true;
  updateMapView();
}

async function mapLongestClicked() {
  const m = mapMetrics();
  if (m.longestRoute.length < 2 || !mapState.view) return;
  const route = m.longestRoute.slice(), edges = m.edges, key = mapState.key;     // migawka trasy, jak w M²
  mapCancelFlight();
  mapStop();
  mapClearPending(key);
  // Jak w M²: najpierw zgoda na nagrywanie ekranu; odmowa = brak lotu.
  let stream = null;
  try { stream = await mapRecRequest(); } catch { mapMessage('Screen recording permission denied'); return; }
  mapSetFullscreen(true);
  if (!stream) { setTimeout(() => mapFly(route, edges), 180); return; }   // przeglądarka bez nagrywania ekranu — sam lot
  await new Promise(resolve => setTimeout(resolve, 120));
  mapFlightPrepare(route, edges);                 // jak prepareFlightToken w M²: kadr startowy zanim ruszy nagranie
  await new Promise(resolve => setTimeout(resolve, 880));
  if (!stream.active || !mapState.fullscreen) { stream.getTracks().forEach(t => t.stop()); mapCancelFlight(); return; }
  mapRecBegin(stream, key);
  await new Promise(resolve => setTimeout(resolve, 250));
  mapFly(route, edges, mapRecStop);
}

/** Kadr przed nagraniem: sieć i kropki bez niebieskiej trasy, widok na START (nagranie nie pokaże gotowej trasy). */
function mapFlightPrepare(route, edges) {
  const view = mapState.view; if (!view || !mapState.fullscreen) return;
  mapCancelFlight(true);
  mapState.flight = { cancelled: false, preparing: true }; mapUpdatePanel();
  view.invalidateSize();
  const shared = mapSharedReplySegments(edges, route);
  mapState.layer.clearLayers(); mapState.flightLayer.clearLayers();
  mapDrawEdges(mapState.layer, edges, shared);
  mapDrawNodes(L.layerGroup().addTo(mapState.layer), edges);
  const [a0, b0] = route;
  view.options.zoomSnap = 0;
  mapFlightMove(view, a0.lat, a0.lon, Math.min(mapFlightZoom(MapCore.distanceKm(a0.lat, a0.lon, b0.lat, b0.lon)), mapFitSegmentZoom(a0, b0)));
}

// ---------- Nagranie lotu (port ScreenRecordingService + dialog „Save animation as MP4?” z NetworkMapScreen.kt) ----------
function mapRecRequest() {
  mapRecCancel();
  if (!navigator.mediaDevices?.getDisplayMedia || typeof MediaRecorder === 'undefined') return Promise.resolve(null);
  return navigator.mediaDevices.getDisplayMedia({ video: { frameRate: 30 }, audio: false, preferCurrentTab: true, selfBrowserSurface: 'include', surfaceSwitching: 'exclude' });
}
function mapRecBegin(stream, key) {
  const type = ['video/mp4;codecs=avc1', 'video/mp4', 'video/webm;codecs=vp9', 'video/webm'].find(t => MediaRecorder.isTypeSupported(t)) || '';
  const rec = new MediaRecorder(stream, { ...(type ? { mimeType: type } : {}), videoBitsPerSecond: 12_000_000 });
  const r = { rec, stream, key, chunks: [], type: rec.mimeType || type || 'video/webm' };
  rec.ondataavailable = e => { if (e.data.size) r.chunks.push(e.data); };
  stream.getVideoTracks()[0]?.addEventListener('ended', () => { if (mapState.recorder === r) mapRecCancel(); });
  rec.start(1000); mapState.recorder = r;
}
function mapRecCancel() {
  const r = mapState.recorder; mapState.recorder = null; if (!r) return;
  try { if (r.rec.state !== 'inactive') r.rec.stop(); } catch {}
  r.stream.getTracks().forEach(t => t.stop());
}
function mapRecStop() {
  const r = mapState.recorder; mapState.recorder = null; if (!r) return;
  r.rec.onstop = () => { r.stream.getTracks().forEach(t => t.stop()); if (r.chunks.length) mapRecDialog(new Blob(r.chunks, { type: r.type }), r.key); };
  try { r.rec.stop(); } catch { r.stream.getTracks().forEach(t => t.stop()); }
}
function mapRecDialog(blob, key) {
  const ext = /mp4/.test(blob.type) ? 'mp4' : 'webm';
  const box = document.createElement('div'); box.className = 'dialog-backdrop';
  box.innerHTML = `<section class="dialog" role="dialog" aria-modal="true" aria-label="Save animation"><h3>Save animation as ${ext.toUpperCase()}?</h3><p class="dialog-note">The animated longest route will be saved in Downloads.</p><div class="dialog-actions"><button type="button" class="dialog-confirm" data-yes>YES</button><button type="button" class="dialog-cancel" data-no>NO</button></div></section>`;
  const close = () => box.remove();
  box.addEventListener('click', e => { if (e.target === box) close(); });
  box.querySelector('[data-no]').addEventListener('click', close);
  box.querySelector('[data-yes]').addEventListener('click', () => {
    close(); mapMessage('Saving screen recording…'); mapProgress(true);
    try {
      const d = new Date(), p2 = n => String(n).padStart(2, '0');
      const stamp = `${d.getFullYear()}${p2(d.getMonth() + 1)}${p2(d.getDate())}-${p2(d.getHours())}${p2(d.getMinutes())}${p2(d.getSeconds())}`;
      const name = `M2-${String(key || '').slice(0, 4).toUpperCase()}-${stamp}-flight.${ext}`;
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob); link.download = name;
      document.body.appendChild(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(link.href), 60000);
      mapMessage(`Saved ${name}`);
    } catch { mapMessage(`Cannot save ${ext.toUpperCase()}`); }
    mapProgress(false);
  });
  document.body.appendChild(box);
}
/** Klatka lotu jak L.Map.flyTo (_move): setView({animate:false}) robi _resetView, który co klatkę usuwał wszystkie kafelki — mapa znikała spod linii. */
function mapFlightMove(view, lat, lon, zoom) {
  view._move(L.latLng(lat, lon), zoom);
  view.fire('zoomend').fire('moveend');
}

async function mapFly(route, edges, onFinished) {
  mapCancelFlight(true);
  const flight = { cancelled: false }; mapState.flight = flight; mapUpdatePanel();
  const view = mapState.view, layer = mapState.layer, badges = mapState.flightLayer;
  const alive = () => !flight.cancelled && mapState.view === view;
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const frame = () => new Promise(resolve => { mapState.flightFrame = requestAnimationFrame(resolve); });
  const compass = document.getElementById('map-compass');
  try {
    view.invalidateSize(); view.options.zoomSnap = 0;   // płynny, ułamkowy zoom tylko podczas lotu
    const shared = mapSharedReplySegments(edges, route);
    layer.clearLayers(); badges.clearLayers();
    // Cała zielona sieć widoczna przez cały lot; niebieska trasa odsłaniana stopniowo, kropki nad liniami.
    mapDrawEdges(layer, edges, shared);
    const lines = L.layerGroup().addTo(layer);
    const dots = L.layerGroup().addTo(layer); mapDrawNodes(dots, edges);
    const totalKm = MapCore.measuredKm(route);
    const [a0, b0] = route;
    mapFlightMove(view, a0.lat, a0.lon, Math.min(mapFlightZoom(MapCore.distanceKm(a0.lat, a0.lon, b0.lat, b0.lon)), mapFitSegmentZoom(a0, b0)));
    let departure = mapBadge(badges, a0, `START · ${a0.hash.toUpperCase()}`);
    if (compass) compass.hidden = false;
    await sleep(900); if (!alive()) return;
    for (let index = 1; index < route.length; index++) {
      const from = route[index - 1], to = route[index];
      const distance = MapCore.distanceKm(from.lat, from.lon, to.lat, to.lon);
      const targetZoom = Math.min(mapFlightZoom(distance), mapFitSegmentZoom(from, to));
      const startZoom = view.getZoom(), bearing = mapBearing(from, to);
      const duration = Math.min((3200 + Math.min(distance, 150) * 16) * 1.3, 7300);
      const missingGps = to.missingBefore.length > 0;
      const distanceBadge = mapBadge(badges, { lat: (from.lat + to.lat) / 2, lon: (from.lon + to.lon) / 2 }, missingGps ? 'NO GPS RPT' : `${distance.toFixed(1)} km`);
      const segment = L.polyline([[from.lat, from.lon]], { color: missingGps ? '#AB47BC' : '#2196F3', weight: (missingGps ? 4.2 : 16.875) * APK_PX, opacity: 1, lineCap: 'round', interactive: false }).addTo(lines);
      const sharedSeg = shared.has(mapSegKey(from, to)) ? L.polyline([[from.lat, from.lon]], { color: '#F0A84B', weight: 16.875 * APK_PX, dashArray: '32 32', lineCap: 'butt', interactive: false }).addTo(lines) : null;
      if (compass) compass.textContent = `N ${String(Math.round(bearing) % 360).padStart(3, '0')}°`;
      let arrival = null; const t0 = performance.now(); let raw = 0;
      while (raw < 1) {
        await frame(); if (!alive()) return;
        raw = Math.min(1, (performance.now() - t0) / duration);
        const t = raw * raw * (3 - 2 * raw);
        const lat = from.lat + (to.lat - from.lat) * t, lon = from.lon + (to.lon - from.lon) * t;
        mapFlightMove(view, lat, lon, startZoom + (targetZoom - startZoom) * t);
        segment.setLatLngs([[from.lat, from.lon], [lat, lon]]); sharedSeg?.setLatLngs([[from.lat, from.lon], [lat, lon]]);
        if (!arrival && raw >= .8) {
          const last = index === route.length - 1;
          arrival = mapBadge(badges, to, `${last ? 'FINISH → ' : ''}HOP ${to.hopIndex} · ${to.hash.toUpperCase()}`);
          if (last) mapBadge(badges, to, `LONGEST ROUTE · ${totalKm.toFixed(2)} km`, 2.65);
        }
      }
      await mapFade([departure, distanceBadge]); if (!alive()) return;
      departure = arrival;
      await sleep(650); if (!alive()) return;
    }
    await sleep(800); if (!alive()) return;
    view.options.zoomSnap = 1;
    view.fitBounds(route.map(p => [p.lat, p.lon]), { padding: [90, 90], animate: true });
    await sleep(4000); if (!alive()) return;
    await sleep(250); if (!alive()) return;
    onFinished?.();
    mapState.flight = null;
    if (compass) compass.hidden = true;
    badges.clearLayers(); updateMapView();
  } finally {
    if (mapState.flight === flight && flight.cancelled) mapState.flight = null;
  }
}

function renderMap() { mapRender(); }

// ---------- Plik mapy .m2map (port MapFileStore z M² Android) ----------
function mapEventToFile(e) {
  return {
    packetId: e.packetId ?? e.id, packetHash: e.hash || '', payloadType: Number(e.payloadType ?? -1), timestamp: e.timestamp || '',
    observedAt: e.observedAt || 0, path: e.path, uncertainAttribution: !!e.uncertainAttribution, longestRouteEligible: !!e.longestRouteEligible,
    logicalDestinationUnavailable: !!e.logicalDestinationUnavailable, replyToSelected: !!e.replyToSelected, inferredLastHop: !!e.inferredLastHop,
    closestObservedReply: !!e.closestObservedReply, resolvedPath: e.resolvedPath || [], acceptedKeys: e.acceptedKeys || [mapState.key]
  };
}
function mapEventFromFile(e, index) {
  const path = (Array.isArray(e.path) ? e.path : []).map(h => String(h).toUpperCase());
  return {
    id: `${e.packetId}|${path.join('>')}|${index}`, packetId: e.packetId, hash: e.packetHash || '', payloadType: e.payloadType, timestamp: e.timestamp || '',
    observedAt: e.observedAt || 0, path, resolvedPath: Array.isArray(e.resolvedPath) ? e.resolvedPath.map(String) : [],
    longestRouteEligible: e.longestRouteEligible !== false, replyToSelected: !!e.replyToSelected, uncertainAttribution: !!e.uncertainAttribution,
    logicalDestinationUnavailable: !!e.logicalDestinationUnavailable, inferredLastHop: !!e.inferredLastHop, closestObservedReply: !!e.closestObservedReply,
    acceptedKeys: Array.isArray(e.acceptedKeys) ? e.acceptedKeys : []
  };
}
const mapDateStamp = d => `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
function mapNextFileName() {
  const stamp = `${mapKeyShort(mapState.key)}_${mapDateStamp(new Date())}`;
  const used = JSON.parse(localStorage.getItem('m2-web-map-files-v1') || '[]');
  let n = 1; while (used.includes(`${stamp}_${String(n).padStart(3, '0')}`)) n++;
  const name = `${stamp}_${String(n).padStart(3, '0')}`;
  try { localStorage.setItem('m2-web-map-files-v1', JSON.stringify([...used, name].slice(-500))); } catch {}
  return name;
}
function mapExportFile() {
  if (!mapState.key || !mapState.events.size) { mapMessage('No map to save'); return; }
  mapMessage('Exporting map…'); mapProgress(true);
  try {
    const name = mapNextFileName();
    const session = {
      key: mapState.key, filter: 'ANY', trackingMode: mapState.mode, running: false, startedAt: mapState.startedAt || 0,
      baseline: Object.fromEntries(mapState.baselineCounts || []), routingRevision: 0,
      capturedPacketIds: [...new Set([...mapState.events.values()].map(e => e.packetId ?? e.id))], pendingRechecks: [],
      events: [...mapState.events.values()].map(mapEventToFile)
    };
    const blob = new Blob([JSON.stringify({ format: 'M2_MAP', version: 1, name, session })], { type: 'application/octet-stream' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob); link.download = `${name}.m2map`;
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    mapMessage(`Map exported to Downloads/${name}.m2map`);
  } catch { mapMessage('Cannot save map'); }
  finally { mapProgress(false); }
}
function mapImportFile(file) {
  mapMessage('Loading map…'); mapProgress(true);
  const reader = new FileReader();
  reader.onerror = () => { mapProgress(false); mapMessage('Cannot read map file'); };
  reader.onload = () => {
    mapProgress(false);
    let parsed;
    try { parsed = JSON.parse(String(reader.result)); } catch { mapMessage('Cannot read map file'); return; }
    const session = parsed?.session;
    if (parsed?.format !== 'M2_MAP' || parsed.version !== 1 || !/^[0-9a-f]{64}$/i.test(String(session?.key || '')) || !Array.isArray(session?.events)) { mapMessage('Cannot load map'); return; }
    mapCancelFlight();
    if (!trackedKeys.some(k => k.key.toLowerCase() === session.key.toLowerCase())) {
      trackedKeys.push({ key: session.key.toLowerCase(), name: '', counterStartedAt: Date.now(), packetCount: 0, seenPacketIds: [] });
      if (typeof saveTrackedKeys === 'function') saveTrackedKeys();
    }
    mapState.key = trackedKeys.find(k => k.key.toLowerCase() === session.key.toLowerCase()).key;
    if (MapCore.MODES[session.trackingMode]) mapState.mode = session.trackingMode;
    mapState.events.clear();
    session.events.map(mapEventFromFile).filter(e => e.path.length > 1).forEach(e => mapState.events.set(e.id, e));
    mapState.running = false; mapState.committed = true; mapState.startedAt = Number(session.startedAt) || 0;
    mapState.name = String(parsed.name || file.name.replace(/\.m2map$/i, ''));
    mapState.focusedKey = '';
    mapSaveSession(); mapUpdatePanel(); updateMapView();
    const m = mapMetrics();
    if (m.edges.length && mapState.view) {
      const pts = m.edges.flatMap(e => [[e.from.lat, e.from.lon], [e.to.lat, e.to.lon]]);
      mapState.focusedKey = mapState.key.toLowerCase();
      mapState.view.fitBounds(pts, { padding: [40, 40] });
    }
    mapMessage('Map loaded');
  };
  reader.readAsText(file);
}
function mapImportDialog() {
  const input = document.createElement('input');
  input.type = 'file'; input.accept = '.m2map,application/octet-stream,application/json';
  input.addEventListener('change', () => { if (input.files?.[0]) mapImportFile(input.files[0]); });
  input.click();
}

mapLoadSession();
