<?php
declare(strict_types=1);

// Zdarzenia z przeglądarki (navigator.sendBeacon): wejście, zakładka, śledzone klucze, kanały publiczne, błędy JS.
require __DIR__ . '/lib.php';

header('Cache-Control: no-store');
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { http_response_code(405); exit; }
$raw = (string) file_get_contents('php://input', false, null, 0, 8192);
$event = json_decode($raw, true);
if (!is_array($event)) { http_response_code(400); exit; }

$db = m2_stats_db();
if ($db) {
    $recent = $db->prepare('SELECT COUNT(*) FROM m2_events WHERE vid = ? AND ts > ? AND kind <> ?');
    // Zapytania Live przez api.php nie wliczają się do limitu — wcześniej zjadały go i klucze dostawały 429.
    $recent->execute([m2_visitor_id(), time() - 60, 'api']);
    if ((int) $recent->fetchColumn() > 120) { http_response_code(429); exit; }
}

$screens = ['Live', 'My log', 'Channels', 'Map', 'Settings', 'Guide'];
$screen = in_array($event['screen'] ?? '', $screens, true) ? $event['screen'] : null;
switch ($event['type'] ?? '') {
    case 'visit':
        $referrer = parse_url((string) ($event['referrer'] ?? ''), PHP_URL_HOST);
        $own = strtolower((string) ($_SERVER['HTTP_HOST'] ?? ''));
        $referrer = is_string($referrer) && strtolower($referrer) !== $own ? preg_replace('/^www\./i', '', strtolower($referrer)) : null;
        m2_stats_log('visit', ['screen' => $screen, 'referrer' => $referrer]);
        break;
    case 'screen':
        if ($screen) m2_stats_log('screen', ['screen' => $screen]);
        break;
    case 'keys':
        foreach (array_slice((array) ($event['keys'] ?? []), 0, 10) as $item) {
            if (is_array($item) && preg_match('/^[a-f0-9]{64}$/i', (string) ($item['key'] ?? ''))) {
                m2_stats_log('key', ['pkey' => $item['key'], 'pname' => $item['name'] ?? null, 'screen' => $screen]);
                m2_keys_hit((string) $item['key'], isset($item['name']) ? (string) $item['name'] : null);
            }
        }
        break;
    case 'channel':
        $name = trim((string) ($event['name'] ?? ''));
        if ($name === 'public' || preg_match('/^#[\p{L}\p{N}_\-]{1,40}$/u', $name)) m2_stats_log('channel', ['pname' => $name]);
        break;
    case 'error':
        m2_stats_log('jserror', ['screen' => $screen, 'message' => $event['message'] ?? 'Unknown error', 'source' => $event['where'] ?? null]);
        break;
    default:
        http_response_code(400); exit;
}
http_response_code(204);
