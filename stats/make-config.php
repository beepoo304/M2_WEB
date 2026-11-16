<?php
declare(strict_types=1);

// Tworzy stats/data/config.php ze zmiennych środowiskowych (uruchamiane lokalnie przed publikacją, nie z przeglądarki).
// ADMIN_USER, ADMIN_PASSWORD, opcjonalnie MYSQL_DATABASE, MYSQL_USER, MYSQL_PASSWORD, MYSQL_HOST (domyślnie localhost).
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$user = getenv('ADMIN_USER') ?: '';
$password = getenv('ADMIN_PASSWORD') ?: '';
if ($user === '' || strlen($password) < 10) { fwrite(STDERR, "ADMIN_USER i ADMIN_PASSWORD (min. 10 znaków) są wymagane\n"); exit(1); }
$config = ['admin_user' => $user, 'admin_hash' => password_hash($password, PASSWORD_DEFAULT)];
if (getenv('MYSQL_DATABASE')) {
    $config['mysql'] = [
        'dsn' => 'mysql:host=' . (getenv('MYSQL_HOST') ?: 'localhost') . ';dbname=' . getenv('MYSQL_DATABASE') . ';charset=utf8mb4',
        'user' => getenv('MYSQL_USER') ?: '',
        'pass' => getenv('MYSQL_PASSWORD') ?: '',
    ];
}
$target = $argv[1] ?? __DIR__ . '/data/config.php';
file_put_contents($target, "<?php\n// Wygenerowane przez stats/make-config.php — nie commitować.\nreturn " . var_export($config, true) . ";\n", LOCK_EX);
chmod($target, 0640);
echo "Zapisano " . basename($target) . ($config['mysql'] ?? null ? " (MySQL)" : " (SQLite)") . "\n";
