// M² Web — ekran Map: sesja śledzenia (Start/Stop/Restart), tryby, trasy, dystans, najdłuższa trasa i lot.
// Logika geometrii/dystansów: map-core.js. Ten plik łączy ją z danymi Live (app.js) i Leaflet.
const MAP_SESSION_STORAGE = 'm2-web-map-session-v1';
const MAP_HISTORY_STORAGE = 'm2-web-longest-history-v1';
const MAP_MAX_EVENTS = 5000;
const MAP_HISTORY_LIMIT = 1000;
const MAP_COLORS = { route: '#2fb866', reply: '#e0902f', gps: '#ab47bc', longest: '#2196f3', record: '#ff6565' };
const MAP_LINE = { route: { weight: 2.25, opacity: .6 }, gps: { weight: 1.75, opacity: .55, dashArray: '5 6' }, longest: { weight: 4.5, opacity: .9 } };
// Podkład 1:1 jak meshcoresouth.pl/mapper (tryb „Jasny, wyszarzony”): kafelki OSM + filtr CSS na .leaflet-tile-pane.
const MAP_TILES = { url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png', maxZoom: 19, attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>' };

const mapState = {
  key: '', mode: 'ALL_FOR_SELECTED_KEY', running: false, committed: false, events: new Map(),
  directory: [], located: [], directorySource: '', directoryError: '',
  view: null, layer: null, flightLayer: null, flightFrame: 0, fitted: false,
  edgeLines: new Map(), nodeDots: new Map(), longestLine: null, selectedDot: null, panelOpen: typeof innerWidth === 'number' ? innerWidth >= 640 : true,
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
    mapState.baselineCounts = new Map(Array.isArray(s.baseline) ? s.baseline : []);
    mapState.processedCounts = new Map(Array.isArray(s.processed) ? s.processed : []);
    (Array.isArray(s.events) ? s.events : []).forEach(e => mapState.events.set(e.id, e));
  } catch {}
}
function mapSaveSession() {
  try {
    sessionStorage.setItem(MAP_SESSION_STORAGE, JSON.stringify({
      key: mapState.key, mode: mapState.mode, running: mapState.running, committed: mapState.committed,
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
  const maxHops = events.reduce((max, e) => Math.max(max, e.path.length - 1), 0);
  const packets = new Set(events.map(e => e.packetId || e.id)).size;
  const channelPackets = new Set(events.filter(event => event.channel || event.channelHash).map(event => event.packetId)).size;
  return { ...metrics, packets, routes: events.length, maxHops, channelPackets, edges: MapCore.edges(events, mapState.located, mapState.directory) };
}

const mapKm = value => `${Number(value || 0).toFixed(2)} km`;

function mapStart() {
  if (!mapState.key || mapState.running) return;
  if (mapState.committed) {
    mapState.events.clear(); mapState.committed = false; mapState.fitted = false;
    mapSnapshotBaseline();
  } else if (!mapState.baselineCounts || mapState.baselineCounts.size === 0) {
    mapSnapshotBaseline();
  }
  mapState.running = true; mapSaveSession();
  mapIngest(); mapRender(); mapEnsureDirectory().then(() => currentScreen() === 'Map' && updateMapView());
}
function mapStop() {
  if (!mapState.running) return;
  mapState.running = false;
  const km = mapMetrics().longestRouteKm;
  if (!mapState.committed && km > 0) { mapCommitLongest(mapState.key, km); }
  mapState.committed = true; mapSaveSession(); mapRender();
}
function mapRestart() {
  mapState.events.clear(); mapState.running = false; mapState.committed = false; mapState.fitted = false;
  mapSnapshotBaseline();
  mapSaveSession(); mapRender();
}

function leaveMap() {
  cancelAnimationFrame(mapState.flightFrame);
  if (mapState.view) { mapState.view.remove(); mapState.view = null; mapState.layer = null; mapState.flightLayer = null; }
  mapState.edgeLines.clear(); mapState.nodeDots.clear(); mapState.longestLine = null; mapState.selectedDot = null;
}

function mapRender() {
  leaveMap();
  if (!trackedKeys.some(k => k.key.toLowerCase() === mapState.key.toLowerCase())) { mapState.key = trackedKeys[0]?.key || ''; }
  // M² always shows the map; without saved keys the selector is empty and Start is unavailable.
  const noKey = !trackedKeys.length;
  const keyOptions = noKey ? '<option value="">No saved keys</option>' : trackedKeys.map(k => `<option value="${escapeHtml(k.key)}" ${k.key.toLowerCase() === mapState.key.toLowerCase() ? 'selected' : ''}>${escapeHtml(k.name || 'Unnamed')} · ${escapeHtml(k.key.slice(0, 4).toUpperCase())}</option>`).join('');
  const modeOptions = Object.entries(MapCore.MODES).map(([id, label]) => `<option value="${id}" ${id === mapState.mode ? 'selected' : ''}>${label}</option>`).join('');
  const lock = mapState.running ? 'disabled' : '';
  screen.innerHTML = `<section class="map-screen map-full">
    <div id="map-canvas" aria-label="Network map"></div>
    <div class="map-panel ${mapState.panelOpen ? '' : 'collapsed'}">
      <div class="map-panel-head">
        <div><div class="eyebrow">NETWORK MAP</div><b class="map-panel-title">Map</b></div>
        <button type="button" id="map-panel-toggle" class="map-panel-toggle" aria-expanded="${mapState.panelOpen}" title="Show / hide panel">${mapState.panelOpen ? '−' : '+'}</button>
      </div>
      <div class="map-panel-body">
        <div class="map-controls">
          <label>Tracked key<select id="map-key" ${lock || (noKey ? 'disabled' : '')}>${keyOptions}</select></label>
          <label>Tracking mode<select id="map-mode" ${lock}>${modeOptions}</select></label>
        </div>
        <div class="map-buttons">
          <button type="button" id="map-toggle" class="${mapState.running ? 'map-stop' : 'map-start'}" ${noKey ? 'disabled' : ''}>${mapState.running ? 'Stop' : 'Start'}</button>
          <button type="button" id="map-restart" ${noKey ? 'disabled' : ''}>Restart</button>
          <button type="button" id="map-export" title="Export map file">Export</button>
          <button type="button" id="map-import" title="Load map file">Load</button>
        </div>
        <div class="map-counters">
          <div><span>Packets</span><b id="map-packets">0</b></div><div><span>Routes</span><b id="map-routes">0</b></div><div><span>Links</span><b id="map-links">0</b></div>
          <div><span>MAX HOPS</span><b id="map-hops">0</b></div><div><span>Channel packets</span><b id="map-channel-packets">0</b></div><div><span>Distance</span><b id="map-distance">0.00 km</b></div>
        </div>
        <button type="button" id="map-longest" class="longest-tile"><span>Longest route</span><b id="map-longest-km">0.00 km</b></button>
        <p id="map-status" class="map-status" role="status" aria-live="polite"></p>
      </div>
    </div>
    <div class="map-legend"><span style="--c:${MAP_COLORS.route}">Confirmed route</span><span style="--c:${MAP_COLORS.reply}">Reply to key</span><span style="--c:${MAP_COLORS.longest}">Longest route</span><span style="--c:${MAP_COLORS.gps}">RPT without GPS · 0 km</span></div>
  </section>`;
  document.getElementById('map-panel-toggle').addEventListener('click', e => {
    mapState.panelOpen = !mapState.panelOpen;
    e.currentTarget.closest('.map-panel').classList.toggle('collapsed', !mapState.panelOpen);
    e.currentTarget.textContent = mapState.panelOpen ? '−' : '+'; e.currentTarget.setAttribute('aria-expanded', mapState.panelOpen);
  });
  document.getElementById('map-key').addEventListener('change', e => { mapState.key = e.target.value; mapRestart(); });
  document.getElementById('map-mode').addEventListener('change', e => { mapState.mode = e.target.value; mapRestart(); });
  document.getElementById('map-toggle').addEventListener('click', () => (mapState.running ? mapStop() : mapStart()));
  document.getElementById('map-restart').addEventListener('click', mapRestart);
  document.getElementById('map-longest').addEventListener('click', mapFlight);
  document.getElementById('map-export').addEventListener('click', mapExportFile);
  document.getElementById('map-import').addEventListener('click', mapImportDialog);
  if (typeof L === 'undefined') { document.getElementById('map-status').textContent = 'The map library failed to load.'; return; }
  mapState.view = L.map('map-canvas', { zoomControl: false, attributionControl: false, worldCopyJump: false, preferCanvas: true, renderer: L.canvas({ padding: .4 }) }).setView([52.0, 19.5], 6);
  L.control.zoom({ position: 'topright' }).addTo(mapState.view);
  L.control.attribution({ position: 'bottomright', prefix: false }).addTo(mapState.view);
  L.tileLayer(MAP_TILES.url, { maxZoom: MAP_TILES.maxZoom, attribution: MAP_TILES.attribution }).addTo(mapState.view);
  mapState.layer = L.layerGroup().addTo(mapState.view);
  mapState.flightLayer = L.layerGroup().addTo(mapState.view);
  mapState.fitted = false;
  updateMapView();
  mapEnsureDirectory().then(() => currentScreen() === 'Map' && updateMapView());
}

/** Marginesy dopasowania widoku tak, by trasy nie chowały się pod panelem i dolną nawigacją. */
function mapFitPadding() {
  const panel = document.querySelector('.map-panel'), wide = innerWidth >= 800;
  const left = panel && wide ? panel.getBoundingClientRect().right + 24 : 28;
  const top = panel && !wide ? panel.getBoundingClientRect().bottom + 16 : 28;
  return { paddingTopLeft: [left, top], paddingBottomRight: [60, wide ? 120 : 100] };
}

function mapLabel(point) { return escapeHtml(point.name || point.hash); }

function updateMapView() {
  if (currentScreen() !== 'Map' || !mapState.layer) return;
  const m = mapMetrics();
  const set = (id, text) => { const el = document.getElementById(id); if (el) el.textContent = text; };
  set('map-packets', m.packets); set('map-routes', m.routes); set('map-links', m.uniqueLinks); set('map-hops', m.maxHops); set('map-channel-packets', m.channelPackets);
  set('map-distance', mapKm(m.totalUniqueKm)); set('map-longest-km', mapKm(m.longestRouteKm));
  document.getElementById('map-longest-km')?.classList.toggle('record-km', mapRecordPending(mapState.key));
  const status = document.getElementById('map-status');
  if (status) {
    status.textContent = !trackedKeys.length ? 'Add a full public key in Settings to track its routes, repeaters and distances.'
      : mapState.directoryError ? `Node directory unavailable: ${mapState.directoryError}`
      : !mapState.running && !mapState.events.size ? 'Press Start to collect routes for the selected key.'
      : mapState.running ? 'Tracking… routes are added with every Live refresh.' : mapState.committed ? 'Stopped. The longest route of this session was saved.' : '';
  }
  // Rysowanie przyrostowe: istniejące linie/punkty zostają, aktualizowane są tylko zmiany (brak migania przy odświeżeniu Live).
  const bounds = [], seenEdges = new Set(), seenDots = new Set();
  const dotColor = new Map();
  const pointId = point => `${point.lat.toFixed(5)},${point.lon.toFixed(5)}`;
  const claimDot = (point, color) => {
    const id = pointId(point), prev = dotColor.get(id);
    // priorytet koloru punktu: zwykła trasa > odpowiedź > brak GPS
    if (!prev || (prev.color === MAP_COLORS.gps && color !== MAP_COLORS.gps) || (prev.color === MAP_COLORS.reply && color === MAP_COLORS.route)) dotColor.set(id, { point, color });
  };
  m.edges.forEach(edge => {
    const kind = edge.missingGps ? 'gps' : edge.reply ? 'reply' : 'route';
    const color = MAP_COLORS[kind], style = edge.missingGps ? MAP_LINE.gps : MAP_LINE.route;
    const latlngs = [[edge.from.lat, edge.from.lon], [edge.to.lat, edge.to.lon]];
    seenEdges.add(edge.id);
    const line = mapState.edgeLines.get(edge.id);
    if (line) line.setLatLngs(latlngs);
    else mapState.edgeLines.set(edge.id, L.polyline(latlngs, { color, lineCap: 'round', ...style }).addTo(mapState.layer));
    claimDot(edge.from, color); claimDot(edge.to, color);
    bounds.push(...latlngs);
  });
  mapState.edgeLines.forEach((line, id) => { if (!seenEdges.has(id)) { mapState.layer.removeLayer(line); mapState.edgeLines.delete(id); } });
  dotColor.forEach(({ point, color }, id) => {
    seenDots.add(id);
    const dot = mapState.nodeDots.get(id);
    if (dot) { if (dot.options.color !== color) dot.setStyle({ color }); }
    else mapState.nodeDots.set(id, L.circleMarker([point.lat, point.lon], { radius: 4.5, color, weight: 2, opacity: .9, fillColor: '#ffffff', fillOpacity: 1 })
      .bindTooltip(mapLabel(point), { direction: 'top', className: 'm2-tip' }).addTo(mapState.layer));
  });
  mapState.nodeDots.forEach((dot, id) => { if (!seenDots.has(id)) { mapState.layer.removeLayer(dot); mapState.nodeDots.delete(id); } });
  const longest = m.longestRoute.length > 1 ? m.longestRoute.map(p => [p.lat, p.lon]) : null;
  if (longest && mapState.longestLine) mapState.longestLine.setLatLngs(longest).bringToFront();
  else if (longest) mapState.longestLine = L.polyline(longest, { color: MAP_COLORS.longest, lineCap: 'round', ...MAP_LINE.longest }).addTo(mapState.layer);
  else if (mapState.longestLine) { mapState.layer.removeLayer(mapState.longestLine); mapState.longestLine = null; }
  const selected = mapState.located.find(n => n.key.toLowerCase() === mapState.key.toLowerCase());
  if (selected && !mapState.selectedDot) mapState.selectedDot = L.circleMarker([selected.lat, selected.lon], { radius: 7, color: '#fff', weight: 2, fillColor: MAP_COLORS.route, fillOpacity: 1 }).bindTooltip(escapeHtml(selected.name || selected.key.slice(0, 4)), { className: 'm2-tip' }).addTo(mapState.layer);
  else if (selected) mapState.selectedDot.setLatLng([selected.lat, selected.lon]).bringToFront();
  else if (mapState.selectedDot) { mapState.layer.removeLayer(mapState.selectedDot); mapState.selectedDot = null; }
  if (bounds.length && !mapState.fitted) { mapState.view.fitBounds(bounds, { ...mapFitPadding(), maxZoom: 11 }); mapState.fitted = true; }
}

/** Animowany lot po najdłuższej trasie: północ u góry, bieżący odcinek i dystans, na końcu suma. */
function mapFlight() {
  const m = mapMetrics();
  const route = m.longestRoute;
  const status = document.getElementById('map-status');
  if (route.length < 2) { if (status) status.textContent = 'No confirmed longest route yet.'; return; }
  mapClearPending(mapState.key);
  document.getElementById('map-longest-km')?.classList.remove('record-km');   // czerwony do pierwszego otwarcia
  cancelAnimationFrame(mapState.flightFrame);
  mapState.flightLayer.clearLayers();
  const segments = route.slice(1).map((b, i) => ({ a: route[i], b, km: MapCore.distanceKm(route[i].lat, route[i].lon, b.lat, b.lon) }));
  const total = segments.reduce((s, x) => s + x.km, 0);
  const duration = Math.min(25000, Math.max(6000, total * 40));
  const trail = L.polyline([[route[0].lat, route[0].lon]], { color: MAP_COLORS.longest, weight: 5, opacity: .95, lineCap: 'round' }).addTo(mapState.flightLayer);
  const plane = L.circleMarker([route[0].lat, route[0].lon], { radius: 8, color: '#fff', weight: 2, fillColor: MAP_COLORS.longest, fillOpacity: 1 }).addTo(mapState.flightLayer);
  const badge = L.tooltip({ permanent: true, direction: 'top', className: 'm2-tip m2-badge', offset: [0, -10] }).setContent('').setLatLng([route[0].lat, route[0].lon]).addTo(mapState.flightLayer);
  mapState.view.setView([route[0].lat, route[0].lon], 9, { animate: false });
  const t0 = performance.now();
  const frame = now => {
    if (!mapState.view) return;
    const done = Math.min(1, (now - t0) / duration);
    let remaining = done * total, covered = 0, index = 0;
    while (index < segments.length - 1 && remaining > segments[index].km) { remaining -= segments[index].km; covered += segments[index].km; index++; }
    const seg = segments[index], f = seg.km ? Math.min(1, remaining / seg.km) : 1;
    const lat = seg.a.lat + (seg.b.lat - seg.a.lat) * f, lon = seg.a.lon + (seg.b.lon - seg.a.lon) * f;
    const points = [[route[0].lat, route[0].lon], ...segments.slice(0, index).map(s => [s.b.lat, s.b.lon]), [lat, lon]];
    trail.setLatLngs(points); plane.setLatLng([lat, lon]); badge.setLatLng([lat, lon]);
    badge.setContent(done >= 1 ? `TOTAL ${mapKm(total)}` : `${escapeHtml(seg.a.hash)} → ${escapeHtml(seg.b.hash)} · ${mapKm(seg.km)}`);
    mapState.view.panTo([lat, lon], { animate: false });
    if (done < 1) mapState.flightFrame = requestAnimationFrame(frame);
    else mapState.view.fitBounds(route.map(p => [p.lat, p.lon]), { ...mapFitPadding(), maxZoom: 11 });
  };
  mapState.flightFrame = requestAnimationFrame(frame);
}

function renderMap() { mapRender(); }

/** Eksport/import sesji mapy (port MapFileStore z M² Android) — plik M2-XXXX-map.json. */
function mapExportFile() {
  const selectedName = trackedKeys.find(k => k.key.toLowerCase() === mapState.key.toLowerCase())?.name || 'key';
  const cleanName = (selectedName || 'key').replace(/[^a-zA-Z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 12);
  const payload = {
    key: mapState.key, filter: '', trackingMode: mapState.mode, running: false,
    startedAt: mapState.events.size ? Date.now() : 0, events: [...mapState.events.values()]
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `M2-${cleanName || 'key'}-map.json`;
  link.click(); URL.revokeObjectURL(link.href);
}
function mapImportFile(file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const parsed = JSON.parse(String(reader.result));
      const events = Array.isArray(parsed.events) ? parsed.events : [];
      mapState.key = trackedKeys.some(k => k.key.toLowerCase() === String(parsed.key || '').toLowerCase()) ? parsed.key : (trackedKeys[0]?.key || mapState.key);
      if (MapCore && MapCore.MODES && MapCore.MODES[parsed.trackingMode]) mapState.mode = parsed.trackingMode;
      mapState.events.clear();
      events.forEach(event => mapState.events.set(event.id, event));
      mapState.running = false; mapState.committed = false; mapState.fitted = false;
      mapSaveSession(); mapRender();
    } catch { const status = document.getElementById('map-status'); if (status) status.textContent = 'The selected map file is not valid.'; }
  };
  reader.readAsText(file);
}
function mapImportDialog() {
  const input = document.createElement('input');
  input.type = 'file'; input.accept = 'application/json,.json';
  input.addEventListener('change', () => { if (input.files?.[0]) mapImportFile(input.files[0]); });
  input.click();
}

mapLoadSession();
