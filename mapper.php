<?php
// Proxy dla mappera MeshCore (np. meshcoresouth.pl/mapper/api.php): ich API nie ma CORS.
// action=points → [[lat, lon, najlepszy snr|null, pingi], …] (null = bez odpowiedzi), action=repeaters → [[name, lat, lon, city], …].
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
if (extension_loaded('zlib') && !ini_get('zlib.output_compression')) ob_start('ob_gzhandler');   // ~1 MB heksów → ~260 KB

const M2_MAPPER_DEFAULT = 'https://meshcoresouth.pl/mapper/api.php';
const M2_MAPPER_TTL = ['points' => 600, 'repeaters' => 1800];
const M2_MAPPER_MAX_FILES = 6;   // kopie różnych API mappera — najstarsze kasowane

function m2_mapper_fail(int $code, string $message): void {
    http_response_code($code);
    echo json_encode(['error' => $message]);
    exit;
}

$action = (string) ($_GET['action'] ?? '');
if (!isset(M2_MAPPER_TTL[$action])) m2_mapper_fail(400, 'Unsupported action');
$api = trim((string) ($_GET['api'] ?? M2_MAPPER_DEFAULT));
$parts = parse_url($api);
$host = strtolower((string) ($parts['host'] ?? ''));
$isPublicHost = $host !== '' && strpos($host, '.') !== false
    && !preg_match('/(^|\.)(localhost|local|internal|test|lan)$/', $host)
    && !filter_var($host, FILTER_VALIDATE_IP);
if (($parts['scheme'] ?? '') !== 'https' || !$isPublicHost || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment']) || isset($parts['port'])) {
    m2_mapper_fail(400, 'Mapper API must be a public HTTPS address');
}

$cacheDir = __DIR__ . '/stats/data';
$cache = $cacheDir . '/mapper-' . $action . '-' . substr(hash('sha256', $api), 0, 16) . '.json';
if (is_file($cache) && time() - (int) filemtime($cache) < M2_MAPPER_TTL[$action]) {
    header('Cache-Control: public, max-age=120');
    readfile($cache);
    exit;
}

// Tylko jedno zapytanie naraz pobiera z mappera; reszta dostaje starą kopię albo czeka na świeżą.
$lock = is_dir($cacheDir) ? @fopen($cache . '.lock', 'c') : false;
if ($lock && !flock($lock, LOCK_EX | LOCK_NB)) {
    if (is_file($cache)) { header('Cache-Control: public, max-age=60'); readfile($cache); exit; }
    flock($lock, LOCK_EX);
    if (is_file($cache) && time() - (int) filemtime($cache) < M2_MAPPER_TTL[$action]) {
        header('Cache-Control: public, max-age=120');
        readfile($cache);
        exit;
    }
}
@set_time_limit(120);

function m2_cut(string $s): string { return function_exists('mb_substr') ? mb_substr($s, 0, 64) : substr($s, 0, 64); }

function m2_mapper_get(string $url): array {
    $curl = curl_init($url);
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 8, CURLOPT_TIMEOUT => 25, CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4, CURLOPT_ENCODING => '',
        CURLOPT_HTTPHEADER => ['Accept: application/json'], CURLOPT_USERAGENT => 'M2-Web',
    ]);
    $body = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    if ($body === false || $status < 200 || $status >= 300) throw new RuntimeException($status ? "Mapper returned HTTP $status" : 'Mapper unreachable: ' . curl_error($curl));
    $data = json_decode((string) $body, true);
    if (!is_array($data) || empty($data['ok'])) throw new RuntimeException('Mapper returned invalid JSON');
    return $data;
}

try {
    $out = [];
    if ($action === 'points') {
        // Wiersz mappera: [id, ts, lat, lon, rpt, snr, usnr, rssi, user, acc, nf, profil]; pobieranie stronami po 20 000.
        $since = 0;
        for ($page = 0; $page < 25; $page++) {
            $data = m2_mapper_get($api . '?action=points&since=' . $since . '&limit=20000');
            foreach ((array) ($data['points'] ?? []) as $p) {
                if (!is_array($p) || !is_numeric($p[2] ?? null) || !is_numeric($p[3] ?? null)) continue;
                $hit = ($p[4] ?? null) !== null && is_numeric($p[5] ?? null);
                // Najmniejszy heks mappera ma 11 m — punkty w siatce ~10 m sklejamy, zostaje najlepszy SNR i liczba pingów.
                $k = round((float) $p[2], 4) . ',' . round((float) $p[3], 4);
                $c = $out[$k] ?? [round((float) $p[2], 4), round((float) $p[3], 4), null, 0];
                if ($hit && ($c[2] === null || (float) $p[5] > $c[2])) $c[2] = round((float) $p[5], 2);
                $c[3]++; $out[$k] = $c;
                $since = max($since, (int) ($p[0] ?? 0));
            }
            if (empty($data['more'])) break;
        }
    } else {
        $data = m2_mapper_get($api . '?action=repeaters');
        foreach ((array) ($data['repeaters'] ?? []) as $r) {
            if (!is_array($r) || !is_numeric($r['lat'] ?? null) || !is_numeric($r['lon'] ?? null)) continue;
            $out[] = [m2_cut((string) ($r['name'] ?? '')), round((float) $r['lat'], 5), round((float) $r['lon'], 5), m2_cut((string) ($r['city'] ?? ''))];
        }
    }
    $json = json_encode(['ok' => true, 'at' => time(), 'items' => array_values($out)], JSON_UNESCAPED_UNICODE);
    if (is_dir($cacheDir)) {
        @file_put_contents($cache, $json, LOCK_EX);
        $files = glob($cacheDir . '/mapper-*.json') ?: [];
        if (count($files) > M2_MAPPER_MAX_FILES) {
            usort($files, fn($a, $b) => filemtime($a) <=> filemtime($b));
            foreach (array_slice($files, 0, count($files) - M2_MAPPER_MAX_FILES) as $old) {
                if ($old !== $cache) { @unlink($old); @unlink($old . '.lock'); }
            }
        }
    }
    header('Cache-Control: public, max-age=120');
    echo $json;
} catch (Throwable $e) {
    if (is_file($cache)) { readfile($cache); exit; }   // stara kopia lepsza niż nic
    m2_mapper_fail(502, $e->getMessage());
}
