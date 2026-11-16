<?php
declare(strict_types=1);

// Same-origin proxy for configurable public MeshCore API sources.
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

// Anonimowa statystyka zapytań (panel /admin/). Odpowiedź idzie do klienta przed zapisem.
$m2StatsStart = microtime(true);
ob_start();
register_shutdown_function(static function () use ($m2StatsStart): void {
    $status = (int) http_response_code();
    $body = (string) ob_get_contents();
    ob_end_flush();
    if (function_exists('fastcgi_finish_request')) fastcgi_finish_request();
    if (!is_file(__DIR__ . '/stats/lib.php')) return;
    require_once __DIR__ . '/stats/lib.php';
    $resource = (string) ($_GET['resource'] ?? '');
    // Odpytywanie co kilka sekund: zapisujemy próbkę z wagą, błędy zawsze.
    $weight = $status >= 400 ? 1 : (['packets' => 20, 'directory' => 5][$resource] ?? 1);
    if ($weight > 1 && random_int(1, $weight) !== 1) return;
    $error = null;
    if ($status >= 400) { $decoded = json_decode($body, true); $error = is_array($decoded) ? ($decoded['error'] ?? null) : null; }
    m2_stats_log('api', [
        'resource' => $resource, 'weight' => $weight, 'status' => $status, 'message' => $error,
        'ms' => (int) round((microtime(true) - $m2StatsStart) * 1000),
        'source' => parse_url((string) ($_GET['source'] ?? 'https://live.meshcorekk.xyz'), PHP_URL_HOST) ?: null,
        'pkey' => $_GET['id'] ?? null,
    ]);
});

$resource = $_GET['resource'] ?? '';
$source = trim((string) ($_GET['source'] ?? 'https://live.meshcorekk.xyz'));
$parts = parse_url($source);
$host = strtolower((string) ($parts['host'] ?? ''));
$isPublicHost = $host !== ''
    && strpos($host, '.') !== false
    && !in_array($host, ['localhost', 'localhost.localdomain'], true)
    && !preg_match('/(^|\.)(local|internal|test|lan)$/', $host)
    && !filter_var($host, FILTER_VALIDATE_IP);
if (($parts['scheme'] ?? '') !== 'https' || !$isPublicHost || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
    http_response_code(400);
    echo json_encode(['error' => 'API source must be a public HTTPS base URL']);
    exit;
}
$base = rtrim($source, '/');
function fetchJsonResource(string $url): array {
    $curl = curl_init($url);
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_HTTPHEADER => ['Accept: application/json', 'Cache-Control: no-cache'],
    ]);
    $body = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    $error = curl_error($curl);
    if ($body === false || $status < 200 || $status >= 300) throw new RuntimeException($error !== '' ? $error : "Upstream returned HTTP $status");
    $data = json_decode($body, true);
    if (!is_array($data)) throw new RuntimeException('Upstream returned invalid JSON');
    return $data;
}
if ($resource === 'neighbours') {
    $key = strtolower((string) ($_GET['id'] ?? ''));
    if (!preg_match('/^[a-f0-9]{64}$/', $key)) {
        http_response_code(400);
        echo json_encode(['error' => 'A full 64-character public key is required']);
        exit;
    }
    try {
        $detail = fetchJsonResource($base . '/api/nodes/' . $key);
        $health = fetchJsonResource($base . '/api/nodes/' . $key . '/health');
        $directory = fetchJsonResource($base . '/api/nodes?limit=3000');
        $names = [];
        foreach (($directory['nodes'] ?? []) as $node) {
            $nodeKey = strtolower((string) ($node['public_key'] ?? ''));
            if (preg_match('/^[a-f0-9]{64}$/', $nodeKey)) $names[strtoupper(substr($nodeKey, 0, 4))][] = trim((string) ($node['name'] ?? 'Unknown RPT'));
        }
        $counts = [];
        foreach (($detail['recentAdverts'] ?? []) as $advert) foreach (($advert['observations'] ?? []) as $observation) {
            $path = json_decode((string) ($observation['path_json'] ?? '[]'), true);
            $first = strtoupper(trim((string) (is_array($path) ? ($path[0] ?? '') : '')));
            if (preg_match('/^[A-F0-9]{4,}$/', $first)) {
                $hash = substr($first, 0, 4);
                $counts[$hash] = ($counts[$hash] ?? 0) + 1;
            }
        }
        $neighbours = [];
        foreach ($counts as $hash => $count) {
            $candidates = $names[$hash] ?? [];
            $neighbours[] = ['hash' => $hash, 'name' => count($candidates) === 1 ? $candidates[0] : (count($candidates) ? 'Ambiguous RPT' : 'Unknown RPT'), 'count' => $count];
        }
        usort($neighbours, fn(array $left, array $right) => $right['count'] <=> $left['count']);
        echo json_encode(['node' => $detail['node'] ?? [], 'stats' => $health['stats'] ?? ($detail['stats'] ?? []), 'neighbours' => $neighbours], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    } catch (Throwable $error) {
        http_response_code(502);
        echo json_encode(['error' => $error->getMessage()]);
    }
    exit;
}
if ($resource === 'packet') {
    $id = (string) ($_GET['id'] ?? '');
    if (!preg_match('/^[0-9]{1,20}$/', $id)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid packet id']);
        exit;
    }
    $url = $base . '/api/packets/' . $id;
} elseif ($resource === 'node') {
    $key = strtolower((string) ($_GET['id'] ?? ''));
    if (!preg_match('/^[a-f0-9]{64}$/', $key)) {
        http_response_code(400);
        echo json_encode(['error' => 'A full 64-character public key is required']);
        exit;
    }
    // Match the Android M² node-name lookup: fetch the public node directory,
    // then accept only an exact public-key match.
    $url = $base . '/api/nodes?limit=3000';
} elseif ($resource === 'directory') {
    // M² uses the public directory only to confirm that a unique repeater
    // really has no valid GPS position before showing a NO GPS marker.
    $url = $base . '/api/nodes?limit=3000';
} elseif ($resource === 'channel') {
    $name = trim((string) ($_GET['name'] ?? ''));
    if ($name === '' || strlen($name) > 128 || preg_match('/[\x00-\x1F]/', $name)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid channel name']);
        exit;
    }
    $url = $base . '/api/channels/' . rawurlencode($name) . '/messages?limit=250';
} elseif ($resource === 'packets') {
    $limit = filter_var($_GET['limit'] ?? 250, FILTER_VALIDATE_INT);
    $limit = max(1, min(250, $limit === false ? 250 : $limit));
    $url = $base . '/api/packets?limit=' . $limit;
} else {
    http_response_code(400);
    echo json_encode(['error' => 'Unsupported resource']);
    exit;
}

$curl = curl_init($url);
curl_setopt_array($curl, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_CONNECTTIMEOUT => 5,
    CURLOPT_TIMEOUT => 12,
    CURLOPT_HTTPHEADER => ['Accept: application/json', 'Cache-Control: no-cache'],
]);
$body = curl_exec($curl);
$status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
$error = curl_error($curl);

if ($body === false || $status < 200 || $status >= 300) {
    http_response_code(502);
    echo json_encode(['error' => $error !== '' ? $error : 'Upstream packet feed unavailable', 'upstream_status' => $status]);
    exit;
}

if ($resource === 'node') {
    $data = json_decode($body, true);
    $nodes = is_array($data['nodes'] ?? null) ? $data['nodes'] : [];
    foreach ($nodes as $node) {
        if (strtolower((string) ($node['public_key'] ?? '')) === $key) {
            $name = trim((string) ($node['name'] ?? ''));
            if ($name === '') {
                http_response_code(404);
                echo json_encode(['error' => 'The matching node has no advertised name']);
                exit;
            }
            echo json_encode(['key' => strtoupper($key), 'name' => $name], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            exit;
        }
    }
    http_response_code(404);
    echo json_encode(['error' => 'Public key not found in the MeshCore node directory']);
    exit;
}

http_response_code(200);
echo $body;
