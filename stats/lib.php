<?php
declare(strict_types=1);

// M² Web — anonimowe statystyki: zapis zdarzeń do SQLite, lokalizacja IP z lokalnej bazy DB-IP Lite.
// Nic tu nie może przerwać działania strony: każdy błąd zapisu jest połykany.

const M2_STATS_RETENTION_DAYS = 90;
date_default_timezone_set('Europe/Warsaw');

function m2_stats_dir(): string {
    $dir = getenv('M2_STATS_DIR') ?: __DIR__ . '/data';
    if (!is_dir($dir)) @mkdir($dir, 0750, true);
    return $dir;
}

// Konfiguracja (poza repozytorium): data/config.php zwraca np.
// ['mysql' => ['dsn' => 'mysql:host=localhost;dbname=...;charset=utf8mb4', 'user' => '...', 'pass' => '...'],
//  'admin_user' => '...', 'admin_hash' => password_hash(...)]
function m2_stats_config(): array {
    static $config = null;
    if ($config === null) {
        $file = m2_stats_dir() . '/config.php';
        $config = is_file($file) ? (array) (include $file) : [];
        // Reset hasła przez FTP: plik data/nowe-haslo.txt (min. 10 znaków) zamieniamy na hash i usuwamy.
        $reset = m2_stats_dir() . '/nowe-haslo.txt';
        $hashFile = m2_stats_dir() . '/admin-hash.php';
        if (is_file($reset)) {
            $password = trim((string) file_get_contents($reset));
            if (strlen($password) >= 10 && file_put_contents($hashFile, "<?php\nreturn " . var_export(password_hash($password, PASSWORD_DEFAULT), true) . ";\n", LOCK_EX) !== false) @unlink($reset);
        }
        if (is_file($hashFile)) $config['admin_hash'] = (string) (include $hashFile);
    }
    return $config;
}

function m2_stats_db(): ?PDO {
    static $db = null, $failed = false;
    if ($db || $failed) return $db;
    try {
        $mysql = m2_stats_config()['mysql'] ?? null;
        if (is_array($mysql) && !empty($mysql['dsn'])) {
            $db = new PDO((string) $mysql['dsn'], (string) ($mysql['user'] ?? ''), (string) ($mysql['pass'] ?? ''), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 3]);
            $id = 'BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY'; $text = 'VARCHAR(500)'; $suffix = ' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4';
        } else {
            $db = new PDO('sqlite:' . m2_stats_dir() . '/stats.sqlite', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $db->exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=3000;');
            $id = 'INTEGER PRIMARY KEY'; $text = 'TEXT'; $suffix = '';
        }
        $marker = m2_stats_dir() . '/schema-v1-' . $db->getAttribute(PDO::ATTR_DRIVER_NAME) . '.ok';
        if (is_file($marker)) return $db;
        $db->exec("CREATE TABLE IF NOT EXISTS m2_events (
            id $id, ts INTEGER NOT NULL, day CHAR(10) NOT NULL, vid CHAR(16) NOT NULL, kind VARCHAR(16) NOT NULL,
            weight INTEGER NOT NULL DEFAULT 1, screen VARCHAR(32), pkey CHAR(64), pname VARCHAR(64), resource VARCHAR(24),
            source VARCHAR(128), status INTEGER, ms INTEGER, message $text, country CHAR(2), city VARCHAR(96),
            device VARCHAR(16), browser VARCHAR(16), referrer VARCHAR(128))$suffix");
        $db->exec("CREATE TABLE IF NOT EXISTS m2_logins (ts INTEGER NOT NULL, iphash CHAR(16) NOT NULL, ok INTEGER NOT NULL)$suffix");
        try { $db->exec('CREATE INDEX m2_events_kind_ts ON m2_events(kind, ts)'); } catch (Throwable $e) {}
        try { $db->exec('CREATE INDEX m2_events_vid_ts ON m2_events(vid, ts)'); } catch (Throwable $e) {}
        try { $db->exec('CREATE INDEX m2_logins_ip ON m2_logins(iphash, ts)'); } catch (Throwable $e) {}
        @file_put_contents($marker, gmdate('c'));
    } catch (Throwable $e) {
        $db = null; $failed = true;
    }
    return $db;
}

function m2_stats_salt(): string {
    static $salt = null;
    if ($salt !== null) return $salt;
    // Plik .php: nawet bez .htaccess przeglądarka nie zobaczy jego treści.
    $file = m2_stats_dir() . '/salt.php';
    $salt = is_file($file) ? (string) (include $file) : '';
    if (strlen($salt) < 32) {
        $salt = bin2hex(random_bytes(32));
        @file_put_contents($file, "<?php return '$salt';\n", LOCK_EX);
    }
    return $salt;
}

function m2_client_ip(): string {
    return (string) ($_SERVER['REMOTE_ADDR'] ?? '');
}

function m2_ip_hash(string $ip): string {
    return substr(hash('sha256', m2_stats_salt() . '|ip|' . $ip), 0, 16);
}

// Ten sam odwiedzający = to samo IP + przeglądarka w danym dniu. Surowe IP nie jest zapisywane.
function m2_visitor_id(): string {
    return substr(hash('sha256', m2_stats_salt() . '|' . m2_client_ip() . '|' . ($_SERVER['HTTP_USER_AGENT'] ?? '') . '|' . gmdate('Y-m-d')), 0, 16);
}

function m2_user_agent(): array {
    $ua = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');
    $device = preg_match('/iPad|Tablet/i', $ua) ? 'Tablet' : (preg_match('/Mobi|Android|iPhone/i', $ua) ? 'Telefon' : 'Komputer');
    if (preg_match('/bot|crawl|spider|slurp|curl|wget|python|httpclient/i', $ua)) $device = 'Bot';
    $browser = 'Inna';
    foreach (['Edg/' => 'Edge', 'OPR/' => 'Opera', 'SamsungBrowser' => 'Samsung', 'Firefox/' => 'Firefox', 'Chrome/' => 'Chrome', 'Safari/' => 'Safari'] as $needle => $name) {
        if (strpos($ua, $needle) !== false) { $browser = $name; break; }
    }
    return [$device, $browser];
}

function m2_geo(string $ip): array {
    static $cache = [];
    if (isset($cache[$ip])) return $cache[$ip];
    $country = strtoupper(substr((string) ($_SERVER['HTTP_CF_IPCOUNTRY'] ?? ''), 0, 2));
    $city = '';
    $dir = m2_stats_dir();
    foreach (['dbip-city-lite.mmdb', 'dbip-country-lite.mmdb'] as $file) {
        if (!is_file("$dir/$file")) continue;
        try {
            $record = (new M2MaxMindReader("$dir/$file"))->get($ip);
            if (is_array($record)) {
                $country = (string) ($record['country']['iso_code'] ?? $country);
                $city = (string) ($record['city']['names']['en'] ?? '');
                $region = (string) ($record['subdivisions'][0]['names']['en'] ?? '');
                if ($city !== '' && $region !== '') $city .= ', ' . $region;
            }
        } catch (Throwable $e) {}
        break;
    }
    return $cache[$ip] = [$country, $city];
}

function m2_cut($value, int $max): ?string {
    if ($value === null) return null;
    $text = trim(preg_replace('/[\x00-\x1f\x7f]+/u', ' ', (string) $value) ?? '');
    if ($text === '') return null;
    return function_exists('mb_substr') ? mb_substr($text, 0, $max) : substr($text, 0, $max);
}

function m2_stats_log(string $kind, array $fields = []): void {
    try {
        $db = m2_stats_db();
        if (!$db) return;
        [$device, $browser] = m2_user_agent();
        [$country, $city] = m2_geo(m2_client_ip());
        $now = time();
        $row = [
            'ts' => $now, 'day' => date('Y-m-d', $now), 'vid' => m2_visitor_id(), 'kind' => $kind,
            'weight' => max(1, (int) ($fields['weight'] ?? 1)),
            'screen' => m2_cut($fields['screen'] ?? null, 32),
            'pkey' => isset($fields['pkey']) && preg_match('/^[a-f0-9]{64}$/', strtolower((string) $fields['pkey'])) ? strtolower((string) $fields['pkey']) : null,
            'pname' => m2_cut($fields['pname'] ?? null, 64),
            'resource' => m2_cut($fields['resource'] ?? null, 24),
            'source' => m2_cut($fields['source'] ?? null, 128),
            'status' => isset($fields['status']) ? (int) $fields['status'] : null,
            'ms' => isset($fields['ms']) ? (int) $fields['ms'] : null,
            'message' => m2_cut($fields['message'] ?? null, 500),
            'country' => m2_cut($country, 2), 'city' => m2_cut($city, 96),
            'device' => $device, 'browser' => $browser,
            'referrer' => m2_cut($fields['referrer'] ?? null, 128),
        ];
        $statement = $db->prepare('INSERT INTO m2_events (' . implode(',', array_keys($row)) . ') VALUES (:' . implode(',:', array_keys($row)) . ')');
        $statement->execute($row);
        if (random_int(1, 300) === 1) {
            $db->prepare('DELETE FROM m2_events WHERE ts < ?')->execute([$now - M2_STATS_RETENTION_DAYS * 86400]);
            $db->prepare('DELETE FROM m2_logins WHERE ts < ?')->execute([$now - 86400]);
        }
    } catch (Throwable $e) {}
}

// Minimalny czytnik formatu MaxMind DB (używany przez darmowe bazy DB-IP Lite, licencja CC BY 4.0).
final class M2MaxMindReader {
    private $handle;
    private int $nodeCount;
    private int $recordSize;
    private int $ipVersion;
    private int $dataStart;

    public function __construct(string $file) {
        $this->handle = fopen($file, 'rb');
        if (!$this->handle) throw new RuntimeException('Cannot open GeoIP database');
        $size = fstat($this->handle)['size'];
        $tailSize = min($size, 128 * 1024);
        fseek($this->handle, $size - $tailSize);
        $tail = (string) fread($this->handle, $tailSize);
        $marker = strrpos($tail, "\xAB\xCD\xEFMaxMind.com");
        if ($marker === false) throw new RuntimeException('Invalid GeoIP database');
        $this->dataStart = 0;
        [$metadata] = $this->decodeBuffer($tail, $marker + 14);
        $this->nodeCount = (int) $metadata['node_count'];
        $this->recordSize = (int) $metadata['record_size'];
        $this->ipVersion = (int) $metadata['ip_version'];
        $this->dataStart = intdiv($this->recordSize * 2, 8) * $this->nodeCount + 16;
    }

    public function __destruct() { if ($this->handle) fclose($this->handle); }

    public function get(string $ip) {
        $packed = @inet_pton($ip);
        if ($packed === false) return null;
        $bits = strlen($packed) * 8;
        $node = 0;
        if ($bits === 32 && $this->ipVersion === 6) {
            for ($i = 0; $i < 96 && $node < $this->nodeCount; $i++) $node = $this->readNode($node, 0);
        }
        for ($i = 0; $i < $bits && $node < $this->nodeCount; $i++) {
            $bit = (ord($packed[$i >> 3]) >> (7 - ($i & 7))) & 1;
            $node = $this->readNode($node, $bit);
        }
        if ($node <= $this->nodeCount) return null;
        [$value] = $this->decodeAt($node - $this->nodeCount - 16);
        return $value;
    }

    private function readNode(int $node, int $index): int {
        $bytes = intdiv($this->recordSize * 2, 8);
        fseek($this->handle, $node * $bytes);
        $b = (string) fread($this->handle, $bytes);
        if ($this->recordSize === 24) return $this->uint(substr($b, $index * 3, 3));
        if ($this->recordSize === 28) {
            $middle = ord($b[3]);
            return $index === 0 ? ((($middle & 0xF0) << 20) | $this->uint(substr($b, 0, 3))) : ((($middle & 0x0F) << 24) | $this->uint(substr($b, 4, 3)));
        }
        return $this->uint(substr($b, $index * 4, 4));
    }

    private function uint(string $bytes): int {
        $value = 0;
        for ($i = 0, $n = strlen($bytes); $i < $n; $i++) $value = ($value << 8) | ord($bytes[$i]);
        return $value;
    }

    private function decodeAt(int $offset): array {
        fseek($this->handle, $this->dataStart + $offset);
        $buffer = (string) fread($this->handle, 16384);
        return $this->decodeBuffer($buffer, 0);
    }

    // Dekoduje wartość z bufora; wskaźniki są doczytywane z sekcji danych.
    private function decodeBuffer(string $buf, int $pos): array {
        $ctrl = ord($buf[$pos++]);
        $type = $ctrl >> 5;
        if ($type === 1) {
            $ss = ($ctrl >> 3) & 3; $vvv = $ctrl & 7;
            if ($ss === 0) { $ptr = ($vvv << 8) | ord($buf[$pos]); $pos += 1; }
            elseif ($ss === 1) { $ptr = (($vvv << 16) | $this->uint(substr($buf, $pos, 2))) + 2048; $pos += 2; }
            elseif ($ss === 2) { $ptr = (($vvv << 24) | $this->uint(substr($buf, $pos, 3))) + 526336; $pos += 3; }
            else { $ptr = $this->uint(substr($buf, $pos, 4)); $pos += 4; }
            [$value] = $this->decodeAt($ptr);
            return [$value, $pos];
        }
        if ($type === 0) $type = 7 + ord($buf[$pos++]);
        $size = $ctrl & 0x1f;
        if ($size === 29) $size = 29 + ord($buf[$pos++]);
        elseif ($size === 30) { $size = 285 + $this->uint(substr($buf, $pos, 2)); $pos += 2; }
        elseif ($size === 31) { $size = 65821 + $this->uint(substr($buf, $pos, 3)); $pos += 3; }
        switch ($type) {
            case 2: return [substr($buf, $pos, $size), $pos + $size];
            case 3: return [unpack('E', substr($buf, $pos, 8))[1], $pos + 8];
            case 4: return [substr($buf, $pos, $size), $pos + $size];
            case 5: case 6: case 9: case 10: return [$this->uint(substr($buf, $pos, $size)), $pos + $size];
            case 8: $v = $this->uint(substr($buf, $pos, $size)); if ($size === 4 && $v >= 0x80000000) $v -= 0x100000000; return [$v, $pos + $size];
            case 15: return [unpack('G', substr($buf, $pos, 4))[1], $pos + 4];
            case 14: return [$size !== 0, $pos];
            case 7:
                $map = [];
                for ($i = 0; $i < $size; $i++) {
                    [$key, $pos] = $this->decodeBuffer($buf, $pos);
                    [$value, $pos] = $this->decodeBuffer($buf, $pos);
                    $map[$key] = $value;
                }
                return [$map, $pos];
            case 11:
                $list = [];
                for ($i = 0; $i < $size; $i++) { [$value, $pos] = $this->decodeBuffer($buf, $pos); $list[] = $value; }
                return [$list, $pos];
        }
        return [null, $pos + $size];
    }
}
