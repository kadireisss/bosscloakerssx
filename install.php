<?php
/**
 * BOSS Cloaker - Installation Script
 * Run this once to set up the database and create the admin account
 * DELETE THIS FILE AFTER INSTALLATION!
 */

$step = $_GET['step'] ?? 'check';
$error = '';
$success = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $dbHost = $_POST['db_host'] ?? 'localhost';
    $dbPort = $_POST['db_port'] ?? '3306';
    $dbName = $_POST['db_name'] ?? 'boss_cloaker';
    $dbUser = $_POST['db_user'] ?? '';
    $dbPass = $_POST['db_pass'] ?? '';
    $adminPass = $_POST['admin_pass'] ?? '';
    
    try {
        // Test connection
        $dsn = "mysql:host=$dbHost;port=$dbPort;charset=utf8mb4";
        $pdo = new PDO($dsn, $dbUser, $dbPass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
        
        // Create database if not exists
        $pdo->exec("CREATE DATABASE IF NOT EXISTS `$dbName` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        $pdo->exec("USE `$dbName`");
        
        // Run schema
        $schemaFile = __DIR__ . '/schema.sql';
        if (file_exists($schemaFile)) {
            $schema = file_get_contents($schemaFile);
            // Remove CREATE DATABASE and USE statements (we already did that)
            $schema = preg_replace('/CREATE DATABASE.*?;/s', '', $schema);
            $schema = preg_replace('/USE.*?;/s', '', $schema);
            
            // Execute each statement
            $statements = array_filter(array_map('trim', explode(';', $schema)));
            foreach ($statements as $stmt) {
                if (!empty($stmt)) {
                    $pdo->exec($stmt);
                }
            }
        }
        
        // Create admin user
        $hashedPassword = password_hash($adminPass ?: 'admin123', PASSWORD_BCRYPT, ['cost' => 12]);
        
        // Check if admin exists
        $check = $pdo->prepare("SELECT id FROM users WHERE username = 'admin'");
        $check->execute();
        if ($check->fetch()) {
            $pdo->prepare("UPDATE users SET password = ? WHERE username = 'admin'")
                ->execute([$hashedPassword]);
        } else {
            $pdo->prepare("INSERT INTO users (username, password, email) VALUES ('admin', ?, 'admin@boss.local')")
                ->execute([$hashedPassword]);
        }
        
        // Write config with actual values
        $configContent = '<?php
/**
 * BOSS Cloaker - Configuration (Auto-generated)
 */

error_reporting(E_ALL);
ini_set(\'display_errors\', \'0\');
ini_set(\'log_errors\', \'1\');
ini_set(\'session.cookie_httponly\', \'1\');
ini_set(\'session.use_strict_mode\', \'1\');

date_default_timezone_set(\'Europe/Istanbul\');

define(\'DB_HOST\', ' . var_export($dbHost, true) . ');
define(\'DB_PORT\', ' . var_export($dbPort, true) . ');
define(\'DB_NAME\', ' . var_export($dbName, true) . ');
define(\'DB_USER\', ' . var_export($dbUser, true) . ');
define(\'DB_PASS\', ' . var_export($dbPass, true) . ');
define(\'DB_CHARSET\', \'utf8mb4\');

define(\'ADMIN_PASSWORD\', \'\');
define(\'SESSION_SECRET\', ' . var_export(bin2hex(random_bytes(32)), true) . ');
define(\'APP_VERSION\', \'2.0-php\');

function getDB(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = sprintf(\'mysql:host=%s;port=%s;dbname=%s;charset=%s\', DB_HOST, DB_PORT, DB_NAME, DB_CHARSET);
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
        ];
        $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    }
    return $pdo;
}

function jsonResponse($data, int $status = 200): void {
    http_response_code($status);
    header(\'Content-Type: application/json; charset=utf-8\');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function getJsonBody(): array {
    $body = file_get_contents(\'php://input\');
    if (empty($body)) return [];
    $data = json_decode($body, true);
    return is_array($data) ? $data : [];
}

function getClientIP(): string {
    if (!empty($_SERVER[\'HTTP_X_FORWARDED_FOR\'])) {
        $ips = explode(\',\', $_SERVER[\'HTTP_X_FORWARDED_FOR\']);
        return trim($ips[0]);
    }
    if (!empty($_SERVER[\'HTTP_X_REAL_IP\'])) return $_SERVER[\'HTTP_X_REAL_IP\'];
    return $_SERVER[\'REMOTE_ADDR\'] ?? \'0.0.0.0\';
}

function getUserAgent(): string {
    return $_SERVER[\'HTTP_USER_AGENT\'] ?? \'\';
}

function getRequestHeaders(): array {
    $headers = [];
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, \'HTTP_\') === 0) {
            $headerName = str_replace(\'_\', \'-\', strtolower(substr($key, 5)));
            $headers[$headerName] = $value;
        }
    }
    return $headers;
}

function generateSlug(int $length = 8): string {
    $chars = \'abcdefghijklmnopqrstuvwxyz0123456789\';
    $slug = \'\';
    for ($i = 0; $i < $length; $i++) {
        $slug .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $slug;
}

function setCorsHeaders(): void {
    $origin = $_SERVER[\'HTTP_ORIGIN\'] ?? \'\';
    if ($origin) header("Access-Control-Allow-Origin: $origin");
    header(\'Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\');
    header(\'Access-Control-Allow-Headers: Content-Type, Authorization\');
    header(\'Access-Control-Allow-Credentials: true\');
}
';
        
        file_put_contents(__DIR__ . '/api/config.php', $configContent);
        
        $success = 'Kurulum başarılı! Admin kullanıcı adı: admin, Şifre: ' . ($adminPass ?: 'admin123');
        $step = 'done';
        
    } catch (PDOException $e) {
        $error = 'Veritabanı hatası: ' . $e->getMessage();
    } catch (Exception $e) {
        $error = 'Hata: ' . $e->getMessage();
    }
}

// Check requirements
$checks = [
    'PHP 7.4+' => version_compare(PHP_VERSION, '7.4.0', '>='),
    'PDO MySQL' => extension_loaded('pdo_mysql'),
    'JSON' => extension_loaded('json'),
    'OpenSSL' => extension_loaded('openssl'),
    'Session' => extension_loaded('session'),
    'mod_rewrite' => function_exists('apache_get_modules') ? in_array('mod_rewrite', apache_get_modules()) : true,
    'config.php yazılabilir' => is_writable(__DIR__ . '/api/'),
];
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BOSS Cloaker - Kurulum</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: system-ui, -apple-system, sans-serif; background: #09090b; color: #fafafa; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 2rem; }
        .container { max-width: 600px; width: 100%; }
        .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 2rem; }
        h1 { font-size: 1.5rem; margin-bottom: 0.5rem; color: #10b981; }
        h2 { font-size: 1.2rem; margin-bottom: 1rem; }
        p { color: #a1a1aa; font-size: 0.875rem; margin-bottom: 1rem; }
        .check { display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .check .ok { color: #10b981; }
        .check .fail { color: #ef4444; }
        label { display: block; font-size: 0.875rem; color: #a1a1aa; margin-bottom: 0.25rem; margin-top: 0.75rem; }
        input { width: 100%; padding: 0.625rem; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); border-radius: 6px; color: #fafafa; font-family: monospace; font-size: 0.875rem; }
        input:focus { outline: none; border-color: #10b981; }
        button { width: 100%; padding: 0.75rem; background: #10b981; color: #000; border: none; border-radius: 6px; font-weight: 600; font-size: 1rem; cursor: pointer; margin-top: 1.5rem; }
        button:hover { background: #059669; }
        .error { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: #ef4444; padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.875rem; }
        .success { background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.3); color: #10b981; padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.875rem; }
        .warning { background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3); color: #f59e0b; padding: 0.75rem; border-radius: 6px; margin-top: 1rem; font-size: 0.875rem; }
        .logo { text-align: center; margin-bottom: 2rem; }
        .logo span { font-size: 2rem; font-weight: 800; letter-spacing: -1px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <span style="color:#10b981">BOSS</span> <span>CLOAKER</span>
            <p style="margin-top:0.5rem">PHP/Plesk Kurulum Sihirbazı</p>
        </div>
        
        <div class="card">
            <?php if ($error): ?>
                <div class="error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            
            <?php if ($step === 'done'): ?>
                <div class="success"><?= htmlspecialchars($success) ?></div>
                <h2>Kurulum Tamamlandı!</h2>
                <p>Artık admin paneline giriş yapabilirsiniz.</p>
                <a href="/login"><button type="button">Admin Paneline Git</button></a>
                <div class="warning">
                    <strong>⚠️ GÜVENLİK:</strong> Bu dosyayı (install.php) sunucudan SİLİN!
                </div>
            <?php elseif ($step === 'check'): ?>
                <h2>Sistem Gereksinimleri</h2>
                <?php foreach ($checks as $name => $ok): ?>
                    <div class="check">
                        <span><?= $name ?></span>
                        <span class="<?= $ok ? 'ok' : 'fail' ?>"><?= $ok ? '✓' : '✗' ?></span>
                    </div>
                <?php endforeach; ?>
                
                <?php if (array_product($checks)): ?>
                    <p style="color:#10b981; margin-top:1rem">Tüm gereksinimler karşılanıyor!</p>
                    <a href="?step=install"><button type="button">Kuruluma Başla →</button></a>
                <?php else: ?>
                    <p style="color:#ef4444; margin-top:1rem">Bazı gereksinimler karşılanmıyor. Lütfen düzeltin.</p>
                <?php endif; ?>
            <?php else: ?>
                <h2>Veritabanı ve Admin Ayarları</h2>
                <form method="POST">
                    <label>MySQL Host</label>
                    <input type="text" name="db_host" value="localhost" required>
                    
                    <label>MySQL Port</label>
                    <input type="text" name="db_port" value="3306" required>
                    
                    <label>Veritabanı Adı</label>
                    <input type="text" name="db_name" value="boss_cloaker" required>
                    
                    <label>MySQL Kullanıcı</label>
                    <input type="text" name="db_user" value="" required placeholder="root">
                    
                    <label>MySQL Şifre</label>
                    <input type="password" name="db_pass" value="" placeholder="Veritabanı şifresi">
                    
                    <label>Admin Şifre</label>
                    <input type="password" name="admin_pass" value="" required placeholder="Güçlü bir şifre girin">
                    
                    <button type="submit">Kurulumu Tamamla</button>
                </form>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
