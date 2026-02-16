<?php
/**
 * BOSS Cloaker - Configuration
 * Plesk/PHP compatible version
 */

// Error reporting (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

// Session configuration (only set if headers not yet sent)
if (!headers_sent()) {
    @ini_set('session.cookie_httponly', '1');
    // cookie_secure should only be enabled for HTTPS
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        @ini_set('session.cookie_secure', '1');
    }
    @ini_set('session.use_strict_mode', '1');
    @ini_set('session.cookie_samesite', 'Lax');
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
 * Simple CORS headers for API
 */
function setCorsHeaders(): void {
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin) {
        header("Access-Control-Allow-Origin: $origin");
    }
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    header('Access-Control-Allow-Credentials: true');
}
