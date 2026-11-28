<?php
declare(strict_types=1);

// M² Web — panel administratora: logowanie i statystyki strony.
require __DIR__ . '/../stats/lib.php';

header('Cache-Control: no-store');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex, nofollow');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'");

const M2_ADMIN_IDLE = 1800;
const M2_ADMIN_MAX_FAILS = 5;
const M2_ADMIN_LOCK = 900;
const M2_ADMIN_SECTIONS = [
    'tiles' => 'Podsumowanie', 'chart' => 'Wejścia dzień po dniu', 'keys' => 'Najczęściej sprawdzane klucze', 'keydb' => 'Baza kluczy',
    'countries' => 'Kraje', 'cities' => 'Miasta', 'channels' => 'Dodawane kanały publiczne',
    'sources' => 'Źródła danych API',
    'errors' => 'Ostatnie błędy',
];

/** Wyczyszczenie sekcji = zapamiętany moment; sekcja pokazuje tylko nowsze dane (pozostałe sekcje bez zmian). */
function m2_admin_cuts(?array $save = null): array {
    $file = m2_stats_dir() . '/cuts.json';
    if ($save !== null) { @file_put_contents($file, json_encode($save), LOCK_EX); return $save; }
    $cuts = is_file($file) ? json_decode((string) file_get_contents($file), true) : [];
    return is_array($cuts) ? $cuts : [];
}

$https = ($_SERVER['HTTPS'] ?? '') !== '' && ($_SERVER['HTTPS'] ?? '') !== 'off';
session_name('m2admin');
session_set_cookie_params(['lifetime' => 0, 'path' => dirname($_SERVER['SCRIPT_NAME']) . '/', 'secure' => $https, 'httponly' => true, 'samesite' => 'Strict']);
session_start();
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));

function h($value): string { return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8'); }
function n($value): string { return number_format((float) $value, 0, ',', ' '); }
function csrf_ok(): bool { return hash_equals((string) $_SESSION['csrf'], (string) ($_POST['csrf'] ?? '')); }

$config = m2_stats_config();
$configured = !empty($config['admin_user']) && !empty($config['admin_hash']);
$db = m2_stats_db();
$ipHash = m2_ip_hash(m2_client_ip());
$loginError = '';

if (!empty($_SESSION['admin']) && time() - (int) ($_SESSION['seen'] ?? 0) > M2_ADMIN_IDLE) {
    $_SESSION = ['csrf' => bin2hex(random_bytes(16))];
    session_regenerate_id(true);
    $loginError = 'Sesja wygasła, zaloguj się ponownie.';
}

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $action = (string) ($_POST['action'] ?? '');
    if (!csrf_ok()) {
        $loginError = 'Formularz wygasł, spróbuj ponownie.';
    } elseif ($action === 'logout') {
        $_SESSION = [];
        session_destroy();
        header('Location: ./'); exit;
    } elseif ($action === 'login' && $configured && $db) {
        $fails = $db->prepare('SELECT COUNT(*) FROM m2_logins WHERE iphash = ? AND ok = 0 AND ts > ?');
        $fails->execute([$ipHash, time() - M2_ADMIN_LOCK]);
        if ((int) $fails->fetchColumn() >= M2_ADMIN_MAX_FAILS) {
            $loginError = 'Zbyt wiele nieudanych prób. Spróbuj ponownie za 15 minut.';
        } else {
            $ok = hash_equals((string) $config['admin_user'], (string) ($_POST['user'] ?? ''))
                & password_verify((string) ($_POST['password'] ?? ''), (string) $config['admin_hash']);
            $db->prepare('INSERT INTO m2_logins (ts, iphash, ok) VALUES (?, ?, ?)')->execute([time(), $ipHash, $ok ? 1 : 0]);
            if ($ok) {
                session_regenerate_id(true);
                $_SESSION['admin'] = true;
                $_SESSION['seen'] = time();
                $_SESSION['csrf'] = bin2hex(random_bytes(16));
                header('Location: ./'); exit;
            }
            usleep(400000);
            $loginError = 'Nieprawidłowy login lub hasło.';
        }
    } elseif ($action === 'clear' && !empty($_SESSION['admin']) && $db) {
        $section = (string) ($_POST['section'] ?? '');
        $back = '?p=' . rawurlencode((string) ($_POST['p'] ?? '7'));
        $fails = $db->prepare('SELECT COUNT(*) FROM m2_logins WHERE iphash = ? AND ok = 0 AND ts > ?');
        $fails->execute([$ipHash, time() - M2_ADMIN_LOCK]);
        if ((int) $fails->fetchColumn() >= M2_ADMIN_MAX_FAILS) {
            $_SESSION['flash'] = ['bad', 'Zbyt wiele błędnych haseł. Spróbuj ponownie za 15 minut.'];
        } elseif (!password_verify((string) ($_POST['password'] ?? ''), (string) $config['admin_hash'])) {
            $db->prepare('INSERT INTO m2_logins (ts, iphash, ok) VALUES (?, ?, ?)')->execute([time(), $ipHash, 0]);
            usleep(400000);
            $_SESSION['flash'] = ['bad', 'Błędne hasło — nic nie zostało wyczyszczone.'];
        } elseif ($section === 'all') {
            $db->exec('DELETE FROM m2_events');
            try { $db->exec('DELETE FROM m2_keys'); } catch (Throwable $e) {}
            m2_admin_cuts([]);
            $_SESSION['flash'] = ['ok', 'Wyczyszczono wszystkie statystyki.'];
        } elseif ($section === 'keydb') {
            try { $db->exec('DELETE FROM m2_keys'); } catch (Throwable $e) {}
            $_SESSION['flash'] = ['ok', 'Wyczyszczono bazę kluczy.'];
        } elseif (isset(M2_ADMIN_SECTIONS[$section])) {
            $cuts = m2_admin_cuts();
            $cuts[$section] = time();
            m2_admin_cuts($cuts);
            $_SESSION['flash'] = ['ok', 'Wyczyszczono sekcję „' . M2_ADMIN_SECTIONS[$section] . '”.'];
        }
        header('Location: ./' . $back); exit;
    }
}

function page_start(string $title): void { ?>
<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?= h($title) ?></title>
<style>
:root { --bg:#111315; --surface:#181b1f; --variant:#22272b; --outline:#3a4146; --text:#e7ebe8; --muted:#a3aba7; --primary:#42d47b; --orange:#f0a84b; --red:#ff6565; --blue:#2196f3; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:14px/1.45 "Segoe UI",system-ui,sans-serif; }
a { color:var(--primary); }
header { display:flex; align-items:center; gap:12px; flex-wrap:wrap; padding:12px 18px; background:var(--surface); border-bottom:1px solid var(--outline); position:sticky; top:0; z-index:2; }
header h1 { margin:0; font-size:16px; letter-spacing:.02em; }
header .spacer { flex:1; }
main { max-width:1200px; margin:0 auto; padding:18px; }
.periods a { display:inline-block; padding:6px 12px; border:1px solid var(--outline); border-radius:999px; text-decoration:none; color:var(--muted); margin-right:4px; }
.periods a:hover { color:var(--text); border-color:var(--muted); }
.periods a.on { color:#06210f; background:var(--primary); border-color:var(--primary); font-weight:700; box-shadow:0 0 0 2px rgba(66,212,123,.35); }
.range { color:var(--muted); margin-bottom:10px; }
.range b { color:var(--primary); }
.flash { padding:10px 14px; border-radius:10px; margin-bottom:12px; border:1px solid; }
.flash.ok { color:var(--primary); border-color:var(--primary); background:rgba(66,212,123,.08); }
.flash.bad { color:var(--red); border-color:var(--red); background:rgba(255,101,101,.08); }
.sechead h2 { margin:0 0 8px; font-size:13px; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); display:flex; gap:8px; align-items:center; }
h2 .tools { margin-left:auto; display:flex; gap:6px; align-items:center; text-transform:none; letter-spacing:0; }
details.clear { position:relative; }
details.clear summary { list-style:none; cursor:pointer; border:1px solid var(--outline); background:var(--variant); color:var(--red); border-radius:9px; padding:4px 9px; font:600 11px "Segoe UI",system-ui,sans-serif; }
header details.clear summary { padding:7px 12px; font-size:13px; }
details.clear summary::-webkit-details-marker { display:none; }
details.clear[open] summary { border-color:var(--red); }
details.clear .pop { position:absolute; right:0; top:calc(100% + 6px); z-index:5; width:280px; background:var(--surface); border:1px solid var(--red); border-radius:12px; padding:12px; box-shadow:0 8px 24px rgba(0,0,0,.5); font:13px/1.4 "Segoe UI",system-ui,sans-serif; color:var(--text); }
details.clear .pop p { margin:0 0 8px; color:var(--orange); }
details.clear .pop label { display:block; color:var(--muted); font-size:12px; margin-bottom:8px; }
details.clear .pop input { display:block; width:100%; margin-top:4px; padding:8px 10px; border-radius:8px; border:1px solid var(--outline); background:var(--bg); color:var(--text); }
button.danger { width:100%; background:var(--red); color:#2a0606; border-color:var(--red); }
button,.btn { border:1px solid var(--outline); background:var(--variant); color:var(--primary); border-radius:9px; padding:7px 12px; font:600 13px inherit; cursor:pointer; text-decoration:none; }
.tiles { display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:10px; margin-bottom:18px; }
.tile { background:var(--surface); border:1px solid var(--outline); border-radius:12px; padding:12px 14px; }
.tile small { display:block; color:var(--muted); font-size:12px; }
.tile b { display:block; font-size:24px; margin-top:4px; }
.tile.bad b { color:var(--red); }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr)); gap:14px; }
section.card { background:var(--surface); border:1px solid var(--outline); border-radius:12px; padding:12px 14px; margin-bottom:14px; overflow:visible; }
@media (max-width:760px) { section.card table { display:block; overflow-x:auto; } }
section.card h2 { margin:0 0 10px; font-size:13px; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); display:flex; gap:8px; align-items:center; }
section.card h2 .btn { margin-left:auto; font-size:11px; padding:4px 9px; text-transform:none; letter-spacing:0; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th { text-align:left; color:var(--muted); font-weight:500; font-size:12px; padding:5px 6px; border-bottom:1px solid var(--outline); }
td { padding:6px; border-bottom:1px solid #2a3034; vertical-align:top; }
td.num,th.num { text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }
td.key { font-family:"Roboto Mono",Consolas,monospace; font-size:12px; color:var(--primary); white-space:nowrap; }
td.msg { color:var(--orange); overflow-wrap:anywhere; min-width:200px; }
.bar { height:6px; background:var(--primary); border-radius:3px; opacity:.75; }
.empty { color:var(--muted); padding:8px 0; }
.chart svg { width:100%; height:96px; display:block; }
.tile.live b { color:var(--primary); }
.tile.live .live-dot { display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--primary); margin-left:5px; vertical-align:middle; box-shadow:0 0 0 0 rgba(66,212,123,.5); animation:livepulse 1.8s infinite; }
@keyframes livepulse { 0%{box-shadow:0 0 0 0 rgba(66,212,123,.5);} 70%{box-shadow:0 0 0 6px rgba(66,212,123,0);} 100%{box-shadow:0 0 0 0 rgba(66,212,123,0);} }
.legend { color:var(--muted); font-size:12px; margin-top:4px; }
.legend i { display:inline-block; width:10px; height:10px; border-radius:2px; margin:0 4px 0 12px; vertical-align:-1px; }
.login { max-width:360px; margin:12vh auto; background:var(--surface); border:1px solid var(--outline); border-radius:14px; padding:24px; }
.login h1 { margin:0 0 4px; font-size:20px; }
.login p { color:var(--muted); margin:0 0 18px; }
.login label { display:block; margin-bottom:12px; color:var(--muted); font-size:12px; }
.login input { display:block; width:100%; margin-top:4px; padding:10px 12px; border-radius:9px; border:1px solid var(--outline); background:var(--bg); color:var(--text); font-size:15px; }
.login button { width:100%; padding:11px; background:var(--primary); color:#06210f; border:0; font-size:15px; }
.error { color:var(--red); margin-bottom:12px; }
.filters { margin-bottom:8px; }
.filters a { display:inline-block; margin-right:6px; font-size:12px; padding:4px 10px; border:1px solid var(--outline); border-radius:999px; color:var(--muted); text-decoration:none; }
.filters a.on { color:#06210f; background:var(--primary); border-color:var(--primary); font-weight:700; }
footer { color:var(--muted); font-size:12px; text-align:center; padding:20px; }
</style>
</head>
<body>
<?php }

if (empty($_SESSION['admin'])) {
    page_start('M² · panel administratora'); ?>
<form class="login" method="post" autocomplete="on">
  <h1>M² · panel administratora</h1>
  <p>Statystyki strony</p>
  <?php if (!$configured): ?>
    <div class="error">Panel nie jest jeszcze skonfigurowany (brak konta administratora w stats/data/config.php).</div>
  <?php elseif (!$db): ?>
    <div class="error">Brak połączenia z bazą statystyk.</div>
  <?php endif; ?>
  <?php if ($loginError): ?><div class="error"><?= h($loginError) ?></div><?php endif; ?>
  <input type="hidden" name="action" value="login">
  <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
  <label>Login<input name="user" autocomplete="username" required <?= $configured ? '' : 'disabled' ?>></label>
  <label>Hasło<input name="password" type="password" autocomplete="current-password" required <?= $configured ? '' : 'disabled' ?>></label>
  <button type="submit" <?= $configured && $db ? '' : 'disabled' ?>>Zaloguj</button>
</form>
</body></html>
<?php exit; }

$_SESSION['seen'] = time();
if (!$db) { page_start('M² · statystyki'); echo '<main><div class="error">Brak połączenia z bazą statystyk.</div></main></body></html>'; exit; }

$periods = ['1' => 'Dziś', '7' => '7 dni', '30' => '30 dni', '0' => 'Wszystko'];
$period = array_key_exists((string) ($_GET['p'] ?? '7'), $periods) ? (string) ($_GET['p'] ?? '7') : '7';
$since = $period === '0' ? 0 : strtotime('today -' . ((int) $period - 1) . ' days');
$cuts = m2_admin_cuts();
$periodText = $period === '0' ? 'Wszystkie zapisane dane' : ($period === '1' ? 'Dziś · ' . date('d.m.Y') : $periods[$period] . ' · ' . date('d.m', $since) . '–' . date('d.m.Y'));
function since_for(string $section): int { global $since, $cuts; return max($since, (int) ($cuts[$section] ?? 0)); }
function sv(string $section): array { return [since_for($section)]; }
$errFilter = in_array($_GET['err'] ?? '', ['api', 'js'], true) ? $_GET['err'] : 'all';

function q(string $sql, array $params = []): array {
    global $db;
    $statement = $db->prepare($sql);
    $statement->execute($params);
    return $statement->fetchAll(PDO::FETCH_ASSOC);
}
function one(string $sql, array $params = []) { $rows = q($sql, $params); return $rows ? array_values($rows[0])[0] : 0; }

$s = [$since];
// Boty (rozpoznane po User-Agent) nie wchodzą do liczby wejść, odwiedzających, wykresu ani krajów/miast.
$human = "COALESCE(device,'') <> 'Bot'";
// vid jest dzienny, więc COUNT(DISTINCT vid) w okresie dłuższym niż dzień to „osobo-dni”, nie liczba osób.
$topKeys = q("SELECT e.pkey, COUNT(DISTINCT e.vid) AS users, COUNT(*) AS sessions, MAX(e.ts) AS last,
    (SELECT x.pname FROM m2_events x WHERE x.kind = 'key' AND x.pkey = e.pkey AND x.pname IS NOT NULL AND x.pname <> '' ORDER BY x.ts DESC LIMIT 1) AS name,
    (SELECT COALESCE(SUM(y.weight),0) FROM m2_events y WHERE y.kind = 'api' AND y.pkey = e.pkey AND y.ts >= ?) AS lookups
    FROM m2_events e WHERE e.kind = 'key' AND e.ts >= ? GROUP BY e.pkey ORDER BY users DESC, sessions DESC LIMIT 50", [since_for('keys'), since_for('keys')]);
$keyDb = q('SELECT pkey, name, hits, first_seen, last_seen FROM m2_keys ORDER BY hits DESC, last_seen DESC LIMIT ' . M2_KEYS_MAX);
$errorWhere = $errFilter === 'api' ? "kind = 'api' AND status >= 400" : ($errFilter === 'js' ? "kind = 'jserror'" : "((kind = 'api' AND status >= 400) OR kind = 'jserror')");
$errors = q("SELECT ts, kind, screen, resource, status, message, source, country, city, browser, device FROM m2_events WHERE $errorWhere AND ts >= ? ORDER BY ts DESC LIMIT 100", sv('errors'));

if (isset($_GET['export'])) {
    $type = (string) $_GET['export'];
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="m2-' . preg_replace('/[^a-z]/', '', $type) . '-' . date('Ymd-Hi') . '.csv"');
    $out = fopen('php://output', 'w');
    fwrite($out, "\xEF\xBB\xBF");
    if ($type === 'keys') {
        fputcsv($out, ['klucz', 'nazwa', 'osobo_dni', 'sesje', 'zapytania_api', 'ostatnio'], ';');
        foreach ($topKeys as $r) fputcsv($out, [$r['pkey'], $r['name'], $r['users'], $r['sessions'], $r['lookups'], date('Y-m-d H:i', (int) $r['last'])], ';');
    } elseif ($type === 'keydb') {
        fputcsv($out, ['klucz', 'nazwa', 'sesje_ze_sledzeniem', 'pierwszy_raz', 'ostatnio'], ';');
        foreach ($keyDb as $r) fputcsv($out, [$r['pkey'], $r['name'], $r['hits'], date('Y-m-d H:i', (int) $r['first_seen']), date('Y-m-d H:i', (int) $r['last_seen'])], ';');
    } elseif ($type === 'errors') {
        fputcsv($out, ['czas', 'rodzaj', 'zakladka', 'zasob', 'status', 'komunikat', 'zrodlo', 'kraj', 'miasto', 'przegladarka'], ';');
        foreach ($errors as $r) fputcsv($out, [date('Y-m-d H:i:s', (int) $r['ts']), $r['kind'] === 'api' ? 'API' : 'JS', $r['screen'], $r['resource'], $r['status'], $r['message'], $r['source'], $r['country'], $r['city'], $r['browser']], ';');
    } else {
        fputcsv($out, ['czas', 'rodzaj', 'waga', 'zakladka', 'klucz', 'nazwa', 'zasob', 'zrodlo', 'status', 'ms', 'komunikat', 'kraj', 'miasto', 'urzadzenie', 'przegladarka', 'skad'], ';');
        foreach (q('SELECT * FROM m2_events WHERE ts >= ? ORDER BY ts DESC LIMIT 50000', $s) as $r) {
            fputcsv($out, [date('Y-m-d H:i:s', (int) $r['ts']), $r['kind'], $r['weight'], $r['screen'], $r['pkey'], $r['pname'], $r['resource'], $r['source'], $r['status'], $r['ms'], $r['message'], $r['country'], $r['city'], $r['device'], $r['browser'], $r['referrer']], ';');
        }
    }
    exit;
}

$personDays = (int) one("SELECT COUNT(DISTINCT vid) FROM m2_events WHERE kind IN ('visit','screen') AND $human AND ts >= ?", sv('tiles'));
$firstTs = (int) one("SELECT MIN(ts) FROM m2_events WHERE kind IN ('visit','screen') AND $human AND ts >= ?", sv('tiles'));
$visitorDays = $firstTs ? max(1, (int) round((strtotime('today') - strtotime(date('Y-m-d', $firstTs))) / 86400) + 1) : 1;
$tiles = ['Wejścia (sesje)' => one("SELECT COUNT(*) FROM m2_events WHERE kind = 'visit' AND $human AND ts >= ?", sv('tiles'))];
if ($period === '1') {
    $tiles['Odwiedzający dziś'] = $personDays;
} else {
    $tiles['Odwiedzający dziennie (średnio)'] = number_format($personDays / $visitorDays, 1, ',', ' ');
    $tiles['Odwiedzający (suma dzienna)'] = $personDays;
}
$tiles += [
    'Otwarcia zakładek' => one("SELECT COUNT(*) FROM m2_events WHERE kind = 'screen' AND ts >= ?", sv('tiles')),
    'Śledzone klucze' => one("SELECT COUNT(DISTINCT pkey) FROM m2_events WHERE kind = 'key' AND ts >= ?", sv('tiles')),
    'Zapytania API' => one("SELECT COALESCE(SUM(weight),0) FROM m2_events WHERE kind = 'api' AND ts >= ?", sv('tiles')),
    'Średni czas API' => round((float) one("SELECT COALESCE(SUM(ms*weight)*1.0/NULLIF(SUM(weight),0),0) FROM m2_events WHERE kind = 'api' AND status < 400 AND ts >= ?", sv('tiles'))) . ' ms',
];
$apiErrors = (int) one("SELECT COUNT(*) FROM m2_events WHERE kind = 'api' AND status >= 400 AND ts >= ?", sv('tiles'));
$jsErrors = (int) one("SELECT COUNT(*) FROM m2_events WHERE kind = 'jserror' AND ts >= ?", sv('tiles'));
// „Aktywni teraz” — unikalni odwiedzający (bez botów) z ostatnich 10 minut; niezależne od wybranego zakresu, odświeża się przy przeładowaniu strony.
$activeNow = (int) one("SELECT COUNT(DISTINCT vid) FROM m2_events WHERE $human AND ts >= ?", [time() - 600]);

$chartDays = $period === '0' ? M2_STATS_RETENTION_DAYS : max(7, (int) $period);
$daily = [];
for ($i = $chartDays - 1; $i >= 0; $i--) $daily[date('Y-m-d', strtotime("today -$i days"))] = ['visits' => 0, 'unique' => 0, 'errors' => 0];
foreach (q("SELECT day, SUM(CASE WHEN kind = 'visit' AND $human THEN 1 ELSE 0 END) AS visits, COUNT(DISTINCT CASE WHEN kind IN ('visit','screen') AND $human THEN vid END) AS uniq,
    SUM(CASE WHEN kind = 'jserror' OR (kind = 'api' AND status >= 400) THEN 1 ELSE 0 END) AS errors
    FROM m2_events WHERE ts >= ? GROUP BY day", [max(strtotime('today -' . ($chartDays - 1) . ' days'), (int) ($cuts['chart'] ?? 0))]) as $r) {
    if (isset($daily[$r['day']])) $daily[$r['day']] = ['visits' => (int) $r['visits'], 'unique' => (int) $r['uniq'], 'errors' => (int) $r['errors']];
}

$countries = q("SELECT COALESCE(country,'?') AS label, COUNT(DISTINCT vid) AS c FROM m2_events WHERE kind = 'visit' AND $human AND ts >= ? GROUP BY country ORDER BY c DESC LIMIT 20", sv('countries'));
$cities = q("SELECT city AS label, MAX(country) AS country, COUNT(DISTINCT vid) AS c FROM m2_events WHERE kind = 'visit' AND $human AND city IS NOT NULL AND ts >= ? GROUP BY city ORDER BY c DESC LIMIT 25", sv('cities'));
$channels = q("SELECT pname AS label, COUNT(*) AS c FROM m2_events WHERE kind = 'channel' AND ts >= ? GROUP BY pname ORDER BY c DESC LIMIT 25", sv('channels'));
$sources = q("SELECT COALESCE(source,'?') AS source, SUM(weight) AS total, SUM(CASE WHEN status >= 400 THEN weight ELSE 0 END) AS bad,
    SUM(CASE WHEN status < 400 THEN ms*weight ELSE 0 END)*1.0/NULLIF(SUM(CASE WHEN status < 400 THEN weight ELSE 0 END),0) AS avgms,
    MAX(CASE WHEN status < 400 THEN ms END) AS maxms FROM m2_events WHERE kind = 'api' AND ts >= ? GROUP BY source ORDER BY total DESC", sv('sources'));

function ranking(array $rows, string $empty = 'Brak danych', ?callable $label = null): string {
    if (!$rows) return '<div class="empty">' . h($empty) . '</div>';
    $max = max(array_map(static fn($r) => (float) $r['c'], $rows)) ?: 1;
    $html = '<table>';
    foreach ($rows as $r) {
        $text = $label ? $label($r) : h($r['label'] ?? '—');
        $html .= '<tr><td>' . $text . '<div class="bar" style="width:' . round(100 * (float) $r['c'] / $max, 1) . '%"></div></td><td class="num">' . n($r['c']) . '</td></tr>';
    }
    return $html . '</table>';
}
function flag(string $country): string {
    if (!preg_match('/^[A-Z]{2}$/', $country)) return '';
    return '&#' . (0x1F1E6 + ord($country[0]) - 65) . ';&#' . (0x1F1E6 + ord($country[1]) - 65) . '; ';
}
function chart(array $daily): string {
    $w = 900; $hgt = 96; $pad = 22; $count = count($daily);
    $max = max(1, ...array_map(static fn($d) => max($d['visits'], $d['unique'], $d['errors']), array_values($daily)));
    $slot = ($w - $pad) / $count; $bar = max(2, $slot * .38);
    $svg = '<svg viewBox="0 0 ' . $w . ' ' . $hgt . '" preserveAspectRatio="none" role="img" aria-label="Wejścia dzień po dniu">';
    $svg .= '<text x="0" y="12" fill="#a3aba7" font-size="11">' . n($max) . '</text>';
    $i = 0;
    foreach ($daily as $day => $d) {
        $x = $pad + $i * $slot;
        foreach ([['visits', '#42d47b', 0], ['unique', '#2196f3', $bar], ['errors', '#ff6565', $bar * 2]] as [$k, $color, $offset]) {
            $height = ($hgt - 34) * $d[$k] / $max;
            if ($d[$k] > 0) $svg .= '<rect x="' . round($x + $offset * .7, 1) . '" y="' . round($hgt - 18 - $height, 1) . '" width="' . round($bar * .7, 1) . '" height="' . round($height, 1) . '" fill="' . $color . '"><title>' . h($day . ' · ' . $k . ': ' . $d[$k]) . '</title></rect>';
        }
        if ($count <= 31 || $i % 7 === 0) $svg .= '<text x="' . round($x, 1) . '" y="' . ($hgt - 4) . '" fill="#a3aba7" font-size="10">' . h(substr($day, 5)) . '</text>';
        $i++;
    }
    return $svg . '</svg>';
}

function clear_btn(string $section): string {
    global $period;
    $what = $section === 'all' ? 'WSZYSTKIE statystyki zostaną trwale usunięte.' : 'Sekcja „' . M2_ADMIN_SECTIONS[$section] . '” zostanie wyczyszczona (pokaże tylko nowe dane).';
    return '<details class="clear"><summary>' . ($section === 'all' ? 'Wyczyść wszystko' : 'Wyczyść') . '</summary><form method="post" class="pop">'
        . '<input type="hidden" name="action" value="clear"><input type="hidden" name="section" value="' . h($section) . '">'
        . '<input type="hidden" name="p" value="' . h($period) . '"><input type="hidden" name="csrf" value="' . h($_SESSION['csrf']) . '">'
        . '<p>' . h($what) . '</p><label>Potwierdź hasłem administratora<input type="password" name="password" autocomplete="current-password" required></label>'
        . '<button type="submit" class="danger">Wyczyść</button></form></details>';
}
function title(string $text, string $section, string $extra = ''): string {
    return '<h2>' . h($text) . '<span class="tools">' . $extra . clear_btn($section) . '</span></h2>';
}
$flash = $_SESSION['flash'] ?? null; unset($_SESSION['flash']);

page_start('M² · statystyki'); ?>
<header>
  <h1>M² · statystyki strony</h1>
  <nav class="periods"><?php foreach ($periods as $key => $label): $key = (string) $key; ?><a href="?p=<?= h($key) ?>" class="<?= $key === $period ? 'on' : '' ?>"<?= $key === $period ? ' aria-current="page"' : '' ?>><?= $key === $period ? '✓ ' : '' ?><?= h($label) ?></a><?php endforeach; ?></nav>
  <span class="spacer"></span>
  <a class="btn" href="?p=<?= h($period) ?>&amp;export=events">CSV: wszystkie zdarzenia</a>
  <?= clear_btn('all') ?>
  <form method="post"><input type="hidden" name="action" value="logout"><input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>"><button type="submit">Wyloguj</button></form>
</header>
<main>
  <div class="range">Zakres: <b><?= h($periodText) ?></b></div>
  <?php if ($flash): ?><div class="flash <?= h($flash[0]) ?>"><?= h($flash[1]) ?></div><?php endif; ?>
  <div class="sechead"><?= title('Podsumowanie', 'tiles') ?></div>
  <div class="tiles">
    <div class="tile live" title="Unikalni odwiedzający z ostatnich 10 minut (bez botów). Odświeża się przy przeładowaniu strony."><small>Aktywni teraz<span class="live-dot"></span></small><b><?= n($activeNow) ?></b></div>
    <?php foreach ($tiles as $label => $value): ?><div class="tile"><small><?= h($label) ?></small><b><?= is_numeric($value) ? n($value) : h($value) ?></b></div><?php endforeach; ?>
    <div class="tile <?= $apiErrors ? 'bad' : '' ?>"><small>Błędy API</small><b><?= n($apiErrors) ?></b></div>
    <div class="tile <?= $jsErrors ? 'bad' : '' ?>"><small>Błędy w przeglądarce</small><b><?= n($jsErrors) ?></b></div>
  </div>

  <section class="card chart"><?= title('Wejścia dzień po dniu', 'chart') ?><?= chart($daily) ?>
    <div class="legend"><i style="background:#42d47b"></i>wejścia<i style="background:#2196f3"></i>unikalni<i style="background:#ff6565"></i>błędy</div></section>

  <section class="card"><?= title('Najczęściej sprawdzane klucze', 'keys', '<a class="btn" href="?p=' . h($period) . '&amp;export=keys">CSV</a>') ?>
    <?php if (!$topKeys): ?><div class="empty">Brak danych</div><?php else: ?>
    <table><tr><th>#</th><th>Nazwa</th><th>Klucz</th><th class="num" title="Osoba liczona raz na każdy dzień, w którym śledziła klucz">Osobo-dni</th><th class="num" title="Sesje karty z tym kluczem; odświeżenie strony nie liczy się ponownie">Sesje</th><th class="num">Zapytania API</th><th class="num">Ostatnio</th></tr>
    <?php foreach ($topKeys as $i => $r): ?><tr><td><?= $i + 1 ?></td><td><?= h($r['name'] ?: '—') ?></td><td class="key" title="<?= h($r['pkey']) ?>"><?= h(strtoupper(substr($r['pkey'], 0, 4)) . ' · ' . substr($r['pkey'], 0, 12) . '…') ?></td><td class="num"><?= n($r['users']) ?></td><td class="num"><?= n($r['sessions']) ?></td><td class="num"><?= n($r['lookups']) ?></td><td class="num"><?= h(date('d.m H:i', (int) $r['last'])) ?></td></tr><?php endforeach; ?>
    </table><?php endif; ?></section>

  <section class="card"><?= title('Baza kluczy (' . count($keyDb) . ' / ' . M2_KEYS_MAX . ')', 'keydb', '<a class="btn" href="?p=' . h($period) . '&amp;export=keydb">CSV</a>') ?>
    <?php if (!$keyDb): ?><div class="empty">Brak danych</div><?php else: ?>
    <table><tr><th>#</th><th>Nazwa</th><th>Klucz</th><th class="num" title="Ile sesji kart śledziło ten klucz (nie liczba zapytań do API)">Sesje ze śledzeniem</th><th class="num">Pierwszy raz</th><th class="num">Ostatnio</th></tr>
    <?php foreach ($keyDb as $i => $r): ?><tr><td><?= $i + 1 ?></td><td><?= h($r['name'] ?: '—') ?></td><td class="key" title="<?= h($r['pkey']) ?>"><?= h(strtoupper(substr($r['pkey'], 0, 4)) . ' · ' . substr($r['pkey'], 0, 12) . '…') ?></td><td class="num"><?= n($r['hits']) ?></td><td class="num"><?= h(date('d.m.y H:i', (int) $r['first_seen'])) ?></td><td class="num"><?= h(date('d.m H:i', (int) $r['last_seen'])) ?></td></tr><?php endforeach; ?>
    </table><?php endif; ?></section>

  <div class="grid">
    <section class="card"><?= title('Kraje', 'countries') ?><?= ranking($countries, 'Brak danych', static fn($r) => flag((string) $r['label']) . h($r['label'])) ?></section>
    <section class="card"><?= title('Miasta', 'cities') ?><?= ranking($cities, 'Brak danych', static fn($r) => flag((string) $r['country']) . h($r['label'])) ?></section>
    <section class="card"><?= title('Dodawane kanały publiczne', 'channels') ?><?= ranking($channels) ?></section>
  </div>

  <section class="card"><?= title('Źródła danych API', 'sources') ?>
    <?php if (!$sources): ?><div class="empty">Brak danych</div><?php else: ?>
    <table><tr><th>Źródło</th><th class="num">Zapytania</th><th class="num">Błędy</th><th class="num">% błędów</th><th class="num">Średnio</th><th class="num">Najwolniej</th></tr>
    <?php foreach ($sources as $r): $pct = (float) $r['total'] ? 100 * (float) $r['bad'] / (float) $r['total'] : 0; ?>
      <tr><td><?= h($r['source']) ?></td><td class="num"><?= n($r['total']) ?></td><td class="num"><?= n($r['bad']) ?></td><td class="num" style="color:<?= $pct > 5 ? 'var(--red)' : 'inherit' ?>"><?= number_format($pct, 1, ',', ' ') ?>%</td><td class="num"><?= n($r['avgms']) ?> ms</td><td class="num"><?= n($r['maxms']) ?> ms</td></tr>
    <?php endforeach; ?></table><?php endif; ?></section>

  <section class="card"><?= title('Ostatnie błędy', 'errors', '<a class="btn" href="?p=' . h($period) . '&amp;err=' . h($errFilter) . '&amp;export=errors">CSV</a>') ?>
    <div class="filters"><?php foreach (['all' => 'Wszystkie', 'api' => 'API', 'js' => 'Przeglądarka'] as $key => $label): ?><a href="?p=<?= h($period) ?>&amp;err=<?= $key ?>" class="<?= $key === $errFilter ? 'on' : '' ?>"><?= $label ?></a><?php endforeach; ?></div>
    <?php if (!$errors): ?><div class="empty">Brak błędów</div><?php else: ?>
    <table><tr><th>Czas</th><th>Rodzaj</th><th>Gdzie</th><th>Komunikat</th><th>Skąd</th><th>Przeglądarka</th></tr>
    <?php foreach ($errors as $r): ?><tr><td class="num"><?= h(date('d.m H:i:s', (int) $r['ts'])) ?></td><td><?= $r['kind'] === 'api' ? 'API ' . h($r['status']) : 'JS' ?></td><td><?= h($r['kind'] === 'api' ? ($r['resource'] . ' · ' . $r['source']) : ($r['screen'] . ($r['source'] ? ' · ' . $r['source'] : ''))) ?></td><td class="msg"><?= h($r['message'] ?: '—') ?></td><td><?= flag((string) $r['country']) . h($r['city'] ?: $r['country']) ?></td><td><?= h($r['browser'] . ' · ' . $r['device']) ?></td></tr><?php endforeach; ?>
    </table><?php endif; ?></section>
</main>
<footer>Dane anonimowe: bez zapisu adresów IP, przechowywane <?= M2_STATS_RETENTION_DAYS ?> dni · <a href="https://db-ip.com" rel="noopener">IP Geolocation by DB-IP</a></footer>
</body>
</html>
