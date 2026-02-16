<?php
/**
 * BOSS Cloaker - Configuration
 * Plesk/PHP compatible version
 */

// Error reporting (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

// ============================================
// HTTPS DETECTION (supports reverse proxy / CDN)
// ============================================
function isHttps(): bool {
    // Direct HTTPS
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }
    // Behind reverse proxy (nginx, Apache, HAProxy)
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') {
        return true;
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] === 'on') {
        return true;
    }
    // Cloudflare
    if (!empty($_SERVER['HTTP_CF_VISITOR'])) {
        $cfVisitor = json_decode($_SERVER['HTTP_CF_VISITOR'], true);
        if (isset($cfVisitor['scheme']) && $cfVisitor['scheme'] === 'https') {
            return true;
        }
    }
    // Standard port check
    if (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443) {
        return true;
    }
    return false;
}

// Session configuration (only set if headers not yet sent)
if (!headers_sent() && session_status() === PHP_SESSION_NONE) {
    $isSecure = isHttps();

    // Use session_set_cookie_params for reliable cookie configuration
    session_set_cookie_params([
        'lifetime' => 0,           // Session cookie (expires when browser closes)
        'path'     => '/',         // Available across entire domain
        'domain'   => '',          // Current domain only
        'secure'   => $isSecure,   // Secure flag matches actual protocol
        'httponly'  => true,       // Not accessible via JavaScript
        'samesite' => 'Lax',      // Protects against CSRF while allowing normal navigation
    ]);

    @ini_set('session.use_strict_mode', '1');
    @ini_set('session.use_only_cookies', '1');
    @ini_set('session.cookie_httponly', '1');
    if ($isSecure) {
        @ini_set('session.cookie_secure', '1');
    }
}

// Timezone
date_default_timezone_set('Europe/Istanbul');

// ============================================
// DATABASE CONFIGURATION
// ============================================
define('DB_HOST', getenv('DB_HOST') ?: 'localhost');
define('DB_PORT', getenv('DB_PORT') ?: '3306');
define('DB_NAME', getenv('DB_NAME') ?: 'boss_cloaker');
define('DB_USER', getenv('DB_USER') ?: 'root');
define('DB_PASS', getenv('DB_PASS') ?: '');
define('DB_CHARSET', 'utf8mb4');

// ============================================
// APPLICATION SETTINGS
// ============================================
define('ADMIN_PASSWORD', getenv('ADMIN_PASSWORD') ?: '');
define('SESSION_SECRET', getenv('SESSION_SECRET') ?: 'boss-cloaker-secret-change-me');
define('APP_VERSION', '2.0-php');

// ============================================
// DATABASE CONNECTION (PDO)
// ============================================
function getDB(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        // Use 127.0.0.1 instead of localhost to avoid socket issues
        $host = DB_HOST === 'localhost' ? '127.0.0.1' : DB_HOST;
        
        // If using localhost/127.0.0.1, add unix_socket if available
        if ($host === '127.0.0.1' || $host === 'localhost') {
            $socketPath = '/var/run/mysqld/mysqld.sock';
            if (file_exists($socketPath)) {
                $dsn = sprintf(
                    'mysql:unix_socket=%s;dbname=%s;charset=%s',
                    $socketPath, DB_NAME, DB_CHARSET
                );
            } else {
                $dsn = sprintf(
                    'mysql:host=%s;port=%s;dbname=%s;charset=%s',
                    $host, DB_PORT, DB_NAME, DB_CHARSET
                );
            }
        } else {
            $dsn = sprintf(
                'mysql:host=%s;port=%s;dbname=%s;charset=%s',
                $host, DB_PORT, DB_NAME, DB_CHARSET
            );
        }
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
        ];
        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            http_response_code(500);
            die(json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]));
        }
    }
    return $pdo;
}

// ============================================
// HELPER FUNCTIONS
// ============================================

/**
 * Send JSON response
 */
function jsonResponse($data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

/**
 * Get JSON body from request
 */
function getJsonBody(): array {
    $body = file_get_contents('php://input');
    if (empty($body)) return [];
    $data = json_decode($body, true);
    return is_array($data) ? $data : [];
}

/**
 * Get client IP address
 */
function getClientIP(): string {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($ips[0]);
    }
    if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        return $_SERVER['HTTP_X_REAL_IP'];
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * Get User Agent
 */
function getUserAgent(): string {
    return $_SERVER['HTTP_USER_AGENT'] ?? '';
}

/**
 * Get all request headers (lowercase keys)
 */
function getRequestHeaders(): array {
    $headers = [];
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, 'HTTP_') === 0) {
            $headerName = str_replace('_', '-', strtolower(substr($key, 5)));
            $headers[$headerName] = $value;
        }
    }
    return $headers;
}

/**
 * Generate random slug
 */
function generateSlug(int $length = 8): string {
    $chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    $slug = '';
    for ($i = 0; $i < $length; $i++) {
        $slug .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $slug;
}

/**
 * CORS headers for API
 * Handles both cross-origin (with Origin header) and same-origin requests.
 * Always allows credentials so session cookies are accepted.
 */
function setCorsHeaders(): void {
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin) {
        // Cross-origin request: echo back the requesting origin
        header("Access-Control-Allow-Origin: $origin");
        header('Vary: Origin');
    }
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Max-Age: 86400');
}
