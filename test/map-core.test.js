const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('../map-core.js');

const key = prefix => (prefix + 'ab'.repeat(32)).slice(0, 64).toUpperCase();
const A = key('0A01'), B = key('0B02'), C = key('0C03'), D = key('0D04');
const near = (actual, expected, eps = 0.5) => assert.ok(Math.abs(actual - expected) < eps, `${actual} != ${expected}`);

const nodes = [
  { key: A, lat: 52, lon: 21, name: 'A' },
  { key: B, lat: 52, lon: 22, name: 'B' },
  { key: C, lat: 53, lon: 22, name: 'C' }
];
const directory = [
  ...nodes.map(n => ({ key: n.key, hasGps: true, isRepeater: true })),
  { key: D, hasGps: false, isRepeater: true }
];
const ev = (path, extra = {}) => ({ id: 'p', path, resolvedPath: path.map(() => ''), longestRouteEligible: true, replyToSelected: false, ...extra });

test('isReliableHop: 2-4+ bajty, parzysta długość, tylko hex', () => {
  assert.equal(core.isReliableHop('0A01'), true);
  assert.equal(core.isReliableHop('0A'), false);     // 1 bajt = niejednoznaczny
  assert.equal(core.isReliableHop('0A0'), false);
  assert.equal(core.isReliableHop('ZZZZ'), false);
  assert.equal(core.isTrackable(['0A01', '0B']), false);
});

test('distanceKm: 1° długości geograficznej na 52°N ≈ 68.5 km', () => {
  near(core.distanceKm(52, 21, 52, 22), 68.5, 0.3);
  assert.equal(core.distanceKm(52, 21, 52, 21), 0);
});

test('hasValidGps odrzuca null, 0/0 i wartości spoza zakresu', () => {
  assert.equal(core.hasValidGps({ lat: 52, lon: 21 }), true);
  assert.equal(core.hasValidGps({ lat: null, lon: null }), false);
  assert.equal(core.hasValidGps({ lat: 0, lon: 0 }), false);
  assert.equal(core.hasValidGps({ lat: 91, lon: 0 }), false);
});

test('buildDirectory: katalog zawiera też węzły bez GPS, lista lokalizacji tylko z GPS', () => {
  const r = core.buildDirectory([
    { public_key: A.toLowerCase(), lat: 52, lon: 21, role: 'repeater', name: 'A' },
    { public_key: D, lat: 0, lon: 0, role: 'repeater' },
    { public_key: 'short', lat: 1, lon: 1 }
  ]);
  assert.equal(r.directory.length, 2);
  assert.equal(r.located.length, 1);
  assert.equal(r.located[0].key, A);
});

test('resolve: trasa A-B-C daje 3 punkty i sumę dwóch odcinków', () => {
  const route = core.resolve(['0A01', '0B02', '0C03'], nodes, [], directory);
  assert.equal(route.length, 3);
  near(core.measuredKm(route), 68.5 + 111.2, 1);
});

test('resolve: niejednoznaczny prefiks bez resolved_path unieważnia trasę', () => {
  const twin = [...nodes, { key: key('0A01').replace(/.$/, 'F'), lat: 50, lon: 20, name: 'twin' }];
  assert.deepEqual(core.resolve(['0A01', '0B02'], twin, [], directory), []);
  // resolved_path usuwa niejednoznaczność
  assert.equal(core.resolve(['0A01', '0B02'], twin, [A, ''], directory).length, 2);
});

test('RPT bez GPS to skrót 0 km, a nie połączenie', () => {
  const route = core.resolve(['0A01', '0D04', '0B02'], nodes, [], directory);
  assert.equal(route.length, 2);
  assert.deepEqual(route[1].missingBefore, ['0D04']);
  assert.equal(core.measuredKm(route), 0);
  const e = core.edges([ev(['0A01', '0D04', '0B02'])], nodes, directory);
  assert.equal(e.length, 1);
  assert.equal(e[0].missingGps, true);
  assert.equal(core.metrics([ev(['0A01', '0D04', '0B02'])], nodes, directory).totalUniqueKm, 0);
});

test('nieznany hash przerywa trasę i nie tworzy połączenia', () => {
  const route = core.resolve(['0A01', '0E05', '0B02'], nodes, [], directory);
  assert.equal(route.length, 2);
  assert.equal(route[1].unknownBefore, true);
  assert.equal(core.edges([ev(['0A01', '0E05', '0B02'])], nodes, directory).length, 0);
  assert.equal(core.splitAtUnknown(route).length, 2);
});

test('metrics: ten sam link w obu kierunkach i powtórzenia liczą się raz', () => {
  const events = [ev(['0A01', '0B02']), ev(['0B02', '0A01']), ev(['0A01', '0B02'])];
  const m = core.metrics(events, nodes, directory);
  near(m.totalUniqueKm, 68.5, 0.3);
  assert.equal(m.uniqueLinks, 1);
  near(m.longestRouteKm, 68.5, 0.3);
});

test('metrics: najdłuższa trasa pomija pętle i odpowiedzi', () => {
  const loop = ev(['0A01', '0B02', '0A01', '0C03']);          // A-B-A-C => bez pętli: A-C
  const reply = ev(['0A01', '0B02', '0C03'], { replyToSelected: true, longestRouteEligible: false });
  const m = core.metrics([loop, reply], nodes, directory);
  assert.deepEqual(m.longestRoute.map(p => p.key), [A, C]);
  assert.ok(m.longestRouteKm > 0);
});

test('metrics: trasy z 1-bajtowym hashem są wykluczone', () => {
  const m = core.metrics([ev(['0A', '0B02'])], nodes, directory);
  assert.equal(m.longestRouteKm, 0);
  assert.equal(m.totalUniqueKm, 0);
});

const M = (relation, k) => ({ relation, key: k });
test('accepts: tryby śledzenia', () => {
  const src = [M(core.REL.source, A)];
  assert.equal(core.accepts(src, A, 'STARTS_AT_KEY'), true);
  assert.equal(core.accepts(src, A, 'ENDS_AT_KEY'), false);
  assert.equal(core.accepts([M(core.REL.end, A)], A, 'ENDS_AT_KEY'), true);
  assert.equal(core.accepts([M(core.REL.route, A)], A, 'RELATED_TO_KEY'), true);
  assert.equal(core.accepts([M(core.REL.route, A)], A, 'STARTS_AT_KEY'), false);
  assert.equal(core.accepts([M(core.REL.observer, A)], A, 'REPORTED_BY_KEY'), true);
  assert.equal(core.accepts([M(core.REL.observer, A)], A, 'RELATED_TO_KEY'), false);
  assert.equal(core.accepts([M(core.REL.observer, A)], A, 'ALL_FOR_SELECTED_KEY'), true);
  assert.equal(core.accepts([M(core.REL.route, B)], A, 'ALL_FOR_SELECTED_KEY'), false);   // inny klucz
  assert.equal(core.accepts([], A, 'NIEZNANY'), false);
});

test('accepts: odpowiedź liczy się dopiero z zapisanym observerem', () => {
  assert.equal(core.accepts([M(core.REL.reply, A)], A, 'RELATED_TO_KEY'), false);
  assert.equal(core.accepts([M(core.REL.reply, A), M(core.REL.observer, B)], A, 'RELATED_TO_KEY'), true);
});

const base = { id: '42', hash: 'h', payloadType: 2, timestamp: 't', key: A, mode: 'ALL_FOR_SELECTED_KEY' };

test('routeEvent: źródło dopisywane na początek ścieżki', () => {
  const e = core.routeEvent({ ...base, route: { path: ['0B02', '0C03'], resolved: [B, C], observerId: '' }, matches: [M(core.REL.source, A)] });
  assert.deepEqual(e.path, ['0A01', '0B02', '0C03']);
  assert.equal(e.resolvedPath[0], A);
  assert.equal(e.longestRouteEligible, true);
});

test('routeEvent: wybrany observer dopisywany na koniec', () => {
  const e = core.routeEvent({ ...base, route: { path: ['0B02', '0C03'], resolved: [], observerId: A }, matches: [M(core.REL.observer, A)] });
  assert.deepEqual(e.path, ['0B02', '0C03', '0A01']);
});

test('routeEvent: pakiet źródłowy z pustą ścieżką to bezpośrednie połączenie do observera', () => {
  const e = core.routeEvent({ ...base, route: { path: [], resolved: [], observerId: B }, matches: [M(core.REL.source, A)] });
  assert.deepEqual(e.path, ['0A01', '0B02']);
});

test('routeEvent: pojedynczy punkt, obca relacja i niepewna ścieżka dają null', () => {
  assert.equal(core.routeEvent({ ...base, route: { path: ['0B02'], resolved: [], observerId: '' }, matches: [M(core.REL.route, A)] }), null);
  assert.equal(core.routeEvent({ ...base, route: { path: ['0B02', '0C03'], resolved: [], observerId: '' }, matches: [M(core.REL.route, B)] }), null);
  assert.equal(core.routeEvent({ ...base, route: { path: ['0B', '0C03'], resolved: [], observerId: '' }, matches: [M(core.REL.route, A)] }), null);
});

test('routeEvent: odpowiedź nie jest brana do najdłuższej trasy', () => {
  const e = core.routeEvent({ ...base, route: { path: ['0B02', '0C03'], resolved: [], observerId: B }, matches: [M(core.REL.reply, A), M(core.REL.observer, B)] });
  assert.equal(e.replyToSelected, true);
  assert.equal(e.longestRouteEligible, false);
});

test('routeEvent: id odróżnia obserwacje tego samego pakietu', () => {
  const mk = observerId => core.routeEvent({ ...base, route: { path: ['0B02', '0C03'], resolved: [], observerId }, matches: [M(core.REL.route, A)] });
  assert.notEqual(mk(B).id, mk(C).id);
  assert.equal(mk(B).id, mk(B).id);
});
