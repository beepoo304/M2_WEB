// M² Web — logika mapy (czyste funkcje, bez DOM).
// Port z M² Android: MeshPath, NodeGpsPolicy, RouteTrackingPolicy, MapRouteMapper.
// Zasada: nieznane GPS nigdy nie dowodzi połączenia; odległość to suma unikalnych, nieskierowanych linków.
(function (root) {
  'use strict';

  const REL = { source: 'SOURCE', end: 'LAST RECORDED HOP', route: 'IN ROUTE', observer: 'REPORTED BY', reply: 'REPLY TO' };
  const MODES = {
    STARTS_AT_KEY: 'Starts at key',
    ENDS_AT_KEY: 'Last recorded hop',
    RELATED_TO_KEY: 'Related to key',
    REPORTED_BY_KEY: 'Reported by key',
    ALL_FOR_SELECTED_KEY: 'All for selected key'
  };

  const sameKey = (a, b) => String(a || '').toLowerCase() === String(b || '').toLowerCase();
  const startsWithHash = (key, hash) => String(key || '').toLowerCase().startsWith(String(hash || '').toLowerCase());
  // Jak Kotlin: brak hasha (pusta ścieżka) nigdy nie pasuje do klucza.
  const matchesHop = (key, hash) => hash != null && hash !== '' && startsWithHash(key, hash);

  function isReliableHop(value) {
    const text = String(value ?? '');
    return text.length >= 4 && text.length <= 64 && text.length % 2 === 0 && /^[0-9a-f]+$/i.test(text);
  }
  const isTrackable = path => Array.isArray(path) && path.every(isReliableHop);

  function hasValidGps(node) {
    if (node == null || node.lat == null || node.lon == null) return false;
    const lat = Number(node.lat), lon = Number(node.lon);
    return Number.isFinite(lat) && Number.isFinite(lon) && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180 &&
      !(Math.abs(lat) < 0.01 && Math.abs(lon) < 0.01);
  }

  function distanceKm(aLat, aLon, bLat, bLon) {
    const rad = d => d * Math.PI / 180;
    const dLat = rad(bLat - aLat), dLon = rad(bLon - aLon);
    const v = Math.min(1, Math.max(0, Math.sin(dLat / 2) ** 2 + Math.cos(rad(aLat)) * Math.cos(rad(bLat)) * Math.sin(dLon / 2) ** 2));
    return 6371 * 2 * Math.atan2(Math.sqrt(v), Math.sqrt(1 - v));
  }

  /** Katalog z API (/api/nodes) -> katalog GPS (wszystkie węzły) i lista węzłów z poprawnym GPS. */
  function buildDirectory(rawNodes) {
    const directory = [], located = [];
    (Array.isArray(rawNodes) ? rawNodes : []).forEach(node => {
      const key = String(node?.public_key || '').toUpperCase();
      if (key.length !== 64 || !isReliableHop(key)) return;
      const gps = hasValidGps(node);
      directory.push({ key, hasGps: gps, isRepeater: String(node.role || '').toLowerCase() === 'repeater', name: String(node.name || '').trim() });
      if (gps) located.push({ key, lat: Number(node.lat), lon: Number(node.lon), name: String(node.name || '').trim() });
    });
    return { directory, located };
  }

  /** RPT bez GPS potwierdzamy tylko dla jednoznacznego, znanego repeatera. */
  function confirmedMissingGps(hash, directory, resolvedKey = '') {
    if (!isReliableHop(hash)) return false;
    const seen = new Set();
    const candidates = directory.filter(n => startsWithHash(n.key, hash)).filter(n => !seen.has(n.key.toUpperCase()) && seen.add(n.key.toUpperCase()));
    let node;
    if (resolvedKey) {
      if (!startsWithHash(resolvedKey, hash)) return false;
      const exact = candidates.filter(n => sameKey(n.key, resolvedKey));
      node = exact.length === 1 ? exact[0] : null;
    } else node = candidates.length === 1 ? candidates[0] : null;
    return !!node && node.isRepeater && !node.hasGps;
  }

  /** Ścieżka hashy -> punkty na mapie. Brak GPS (potwierdzony) = skrót 0 km, nieznany hash = przerwa. */
  function resolve(path, nodes, resolvedPath = [], directory = []) {
    if (!isTrackable(path)) return [];
    const ambiguous = path.some((hash, index) => {
      if (resolvedPath[index]) return false;
      return new Set(nodes.filter(n => startsWithHash(n.key, hash)).map(n => n.key.toUpperCase())).size > 1;
    });
    if (ambiguous) return [];
    const result = [];
    let missing = [], unknown = false;
    path.forEach((hash, index) => {
      const full = String(resolvedPath[index] || '');
      const seen = new Set();
      const candidates = nodes.filter(n => startsWithHash(n.key, hash)).filter(n => !seen.has(n.key.toUpperCase()) && seen.add(n.key.toUpperCase()));
      let node = null;
      if (full.length === 64 && startsWithHash(full, hash)) {
        const exact = candidates.filter(n => sameKey(n.key, full));
        node = exact.length === 1 ? exact[0] : null;
      } else if (!full) node = candidates.length === 1 ? candidates[0] : null;
      if (!node) {
        if (confirmedMissingGps(hash, directory, full)) missing.push(hash); else unknown = true;
      } else {
        result.push({
          key: node.key, name: node.name || '', lat: node.lat, lon: node.lon, hash: node.key.slice(0, 4),
          sourceHash: hash, hopIndex: index,
          missingBefore: result.length === 0 ? [] : missing.slice(),
          unknownBefore: result.length > 0 && unknown
        });
        missing = []; unknown = false;
      }
    });
    return result;
  }

  const measuredKm = route => route.slice(1).reduce((sum, b, i) => {
    const a = route[i];
    return b.missingBefore.length === 0 && !b.unknownBefore ? sum + distanceKm(a.lat, a.lon, b.lat, b.lon) : sum;
  }, 0);

  const edgeId = (a, b) => [a.key.toUpperCase(), b.key.toUpperCase()].sort().join('|');

  function splitAtUnknown(route) {
    const groups = [];
    route.forEach(point => {
      if (!groups.length || point.unknownBefore) groups.push([]);
      groups[groups.length - 1].push(point);
    });
    return groups;
  }

  function withoutLoops(route) {
    const result = [];
    route.forEach(point => {
      const previous = result.findIndex(p => sameKey(p.key, point.key));
      if (previous >= 0) result.length = previous + 1; else result.push(point);
    });
    return result;
  }

  /** Unikalne linki fizyczne (nieskierowane); count = ile razy zaobserwowane. */
  function edges(events, nodes, directory) {
    const result = new Map();
    events.filter(e => isTrackable(e.path)).forEach(event => {
      const route = resolve(event.path, nodes, event.resolvedPath, directory);
      route.slice(1).forEach((b, i) => {
        const a = route[i];
        if (b.unknownBefore) return;
        const missing = b.missingBefore.length > 0;
        const id = `${missing ? 'gps' : event.replyToSelected ? 'reply' : 'route'}:${edgeId(a, b)}`;
        const previous = result.get(id);
        if (previous) previous.count += 1;
        else result.set(id, { id, from: a, to: b, count: 1, reply: !!event.replyToSelected, missingGps: missing });
      });
    });
    return [...result.values()];
  }

  function metrics(events, nodes, directory) {
    const seen = new Set();
    let totalUniqueKm = 0;
    edges(events, nodes, directory).filter(e => !e.missingGps).forEach(e => {
      const id = edgeId(e.from, e.to);
      if (!seen.has(id)) { seen.add(id); totalUniqueKm += distanceKm(e.from.lat, e.from.lon, e.to.lat, e.to.lon); }
    });
    const routes = events.filter(e => e.longestRouteEligible && !e.replyToSelected && isTrackable(e.path))
      .flatMap(e => splitAtUnknown(resolve(e.path, nodes, e.resolvedPath, directory)))
      .map(withoutLoops).filter(r => r.length > 1);
    let longest = [], longestKm = 0;
    routes.forEach(r => { const km = measuredKm(r); if (km > longestKm) { longest = r; longestKm = km; } });
    return { totalUniqueKm, longestRouteKm: longestKm, longestRoute: longest, uniqueLinks: seen.size };
  }

  /** Relacje (tablica {relation,key}) -> czy obserwacja należy do wybranego klucza w danym trybie. */
  function accepts(matches, key, mode) {
    const has = rel => matches.some(m => m.relation === rel && sameKey(m.key, key));
    const source = has(REL.source), end = has(REL.end), inside = has(REL.route), reported = has(REL.observer);
    // Zapisany observer potwierdza TĘ obserwację odpowiedzi, nawet gdy adresat nie jest na ścieżce RF.
    const confirmedReply = has(REL.reply) && matches.some(m => m.relation === REL.observer);
    switch (mode) {
      case 'STARTS_AT_KEY': return source;
      case 'ENDS_AT_KEY': return end;
      case 'RELATED_TO_KEY': return source || end || inside || confirmedReply;
      case 'REPORTED_BY_KEY': return reported;
      case 'ALL_FOR_SELECTED_KEY': return source || end || inside || reported || confirmedReply;
      default: return false;
    }
  }

  /**
   * Obserwacja pakietu -> zdarzenie trasy (albo null).
   * input: { id, hash, payloadType, timestamp, route:{path,resolved,observerId}, matches, key, mode }
   */
  function routeEvent(input) {
    const { route, matches, key, mode } = input;
    if (!isTrackable(route.path)) return null;
    if (!accepts(matches, key, mode)) return null;
    const path = route.path.map(h => String(h).toUpperCase());
    const resolved = path.map((_, i) => String(route.resolved?.[i] || ''));
    const sourceKeys = [...new Map(matches.filter(m => m.relation === REL.source).map(m => [String(m.key).toLowerCase(), String(m.key)])).values()];
    const source = sourceKeys.length === 1 ? sourceKeys[0] : null;
    if (source && !matchesHop(source, path[0])) { path.unshift(source.slice(0, 4).toUpperCase()); resolved.unshift(source); }
    // Pakiet źródłowy z pustą ścieżką RF to nadal potwierdzone bezpośrednie połączenie źródło -> observer.
    const observer = String(route.observerId || '');
    const selectedIsSource = matches.some(m => m.relation === REL.source && sameKey(m.key, key));
    const observerIsSelected = sameKey(observer, key);
    const observerIsExplicit = observer.length === 64 && isReliableHop(observer);
    if ((observerIsSelected || (selectedIsSource && observerIsExplicit)) && !matchesHop(observer, path[path.length - 1])) {
      path.push(observer.slice(0, 4).toUpperCase()); resolved.push(observer);
    }
    if (path.length < 2) return null;
    const reply = matches.some(m => m.relation === REL.reply && sameKey(m.key, key));
    return {
      id: `${input.id}|${path.join('>')}|${observer.toLowerCase()}`,
      packetId: input.id, hash: input.hash, payloadType: input.payloadType, timestamp: input.timestamp,
      path, resolvedPath: resolved, longestRouteEligible: !reply, replyToSelected: reply
    };
  }

  const api = { REL, MODES, isReliableHop, isTrackable, hasValidGps, distanceKm, buildDirectory, confirmedMissingGps, resolve, measuredKm, edges, splitAtUnknown, withoutLoops, metrics, accepts, routeEvent };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else { root.M2MapCore = api; root.MapCore = api; }
})(typeof window !== 'undefined' ? window : globalThis);
