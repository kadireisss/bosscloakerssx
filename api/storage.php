<?php
/**
 * BOSS Cloaker - Storage Layer (Database Operations)
 * PDO/MySQL implementation
 */

require_once __DIR__ . '/config.php';

class Storage {
    private PDO $db;
    
    public function __construct() {
        $this->db = getDB();
    }
    
    // ============================================
    // AUTH
    // ============================================
    public function getUser(int $id): ?array {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE id = ?');
        $stmt->execute([$id]);
        return $stmt->fetch() ?: null;
    }
    
    public function getUserByUsername(string $username): ?array {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE username = ?');
        $stmt->execute([$username]);
        return $stmt->fetch() ?: null;
    }
    
    // ============================================
    // DOMAINS
    // ============================================
    public function getDomains(): array {
        $stmt = $this->db->query('SELECT * FROM domains ORDER BY created_at DESC');
        return $stmt->fetchAll();
    }
    
    public function getDomain(int $id): ?array {
        $stmt = $this->db->prepare('SELECT * FROM domains WHERE id = ?');
        $stmt->execute([$id]);
        return $stmt->fetch() ?: null;
    }
    
    public function getDomainByName(string $name): ?array {
        $stmt = $this->db->prepare('SELECT * FROM domains WHERE domain = ?');
        $stmt->execute([$name]);
        return $stmt->fetch() ?: null;
    }
    
    public function getDomainBySlug(string $slug): ?array {
        $stmt = $this->db->prepare('SELECT * FROM domains WHERE slug = ?');
        $stmt->execute([$slug]);
        return $stmt->fetch() ?: null;
    }
    
    public function createDomain(array $data): array {
        $slug = generateSlug();
        $sql = 'INSERT INTO domains (domain, slug, target_url, landing_page_id, redirect_enabled, detection_level, status, 
                block_direct_access, blocked_platforms, js_challenge, redirect_mode, active_hours, active_days, timezone,
                max_clicks_per_ip, rate_limit_window, allow_mobile, allow_desktop)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
        $stmt = $this->db->prepare($sql);
        $stmt->execute([
            $data['domain'] ?? '',
            $slug,
            $data['targetUrl'] ?? $data['target_url'] ?? '',
            $data['landingPageId'] ?? $data['landing_page_id'] ?? null,
            (int)($data['redirectEnabled'] ?? $data['redirect_enabled'] ?? 1),
            $data['detectionLevel'] ?? $data['detection_level'] ?? 'high',
            $data['status'] ?? 'active',
            (int)($data['blockDirectAccess'] ?? $data['block_direct_access'] ?? 0),
            $data['blockedPlatforms'] ?? $data['blocked_platforms'] ?? 'google,facebook,bing,tiktok',
            (int)($data['jsChallenge'] ?? $data['js_challenge'] ?? 0),
            $data['redirectMode'] ?? $data['redirect_mode'] ?? '302',
            $data['activeHours'] ?? $data['active_hours'] ?? null,
            $data['activeDays'] ?? $data['active_days'] ?? null,
            $data['timezone'] ?? 'Europe/Istanbul',
            (int)($data['maxClicksPerIp'] ?? $data['max_clicks_per_ip'] ?? 0),
            (int)($data['rateLimitWindow'] ?? $data['rate_limit_window'] ?? 3600),
            (int)($data['allowMobile'] ?? $data['allow_mobile'] ?? 1),
            (int)($data['allowDesktop'] ?? $data['allow_desktop'] ?? 1),
        ]);
        return $this->getDomain((int)$this->db->lastInsertId());
    }
    
    public function updateDomain(int $id, array $data): array {
        $fields = [];
        $values = [];
        
        $fieldMap = [
            'domain' => 'domain',
            'targetUrl' => 'target_url', 'target_url' => 'target_url',
            'landingPageId' => 'landing_page_id', 'landing_page_id' => 'landing_page_id',
            'redirectEnabled' => 'redirect_enabled', 'redirect_enabled' => 'redirect_enabled',
            'detectionLevel' => 'detection_level', 'detection_level' => 'detection_level',
            'status' => 'status',
            'blockDirectAccess' => 'block_direct_access', 'block_direct_access' => 'block_direct_access',
            'blockedPlatforms' => 'blocked_platforms', 'blocked_platforms' => 'blocked_platforms',
            'jsChallenge' => 'js_challenge', 'js_challenge' => 'js_challenge',
            'redirectMode' => 'redirect_mode', 'redirect_mode' => 'redirect_mode',
            'activeHours' => 'active_hours', 'active_hours' => 'active_hours',
            'activeDays' => 'active_days', 'active_days' => 'active_days',
            'timezone' => 'timezone',
            'maxClicksPerIp' => 'max_clicks_per_ip', 'max_clicks_per_ip' => 'max_clicks_per_ip',
            'rateLimitWindow' => 'rate_limit_window', 'rate_limit_window' => 'rate_limit_window',
            'allowMobile' => 'allow_mobile', 'allow_mobile' => 'allow_mobile',
            'allowDesktop' => 'allow_desktop', 'allow_desktop' => 'allow_desktop',
            'allowedCountries' => 'allowed_countries', 'allowed_countries' => 'allowed_countries',
            'blockedCountries' => 'blocked_countries', 'blocked_countries' => 'blocked_countries',
        ];
        
        foreach ($data as $key => $value) {
            if (isset($fieldMap[$key])) {
                $dbField = $fieldMap[$key];
                if (!in_array("`$dbField` = ?", $fields)) {
                    $fields[] = "`$dbField` = ?";
                    $values[] = $value;
                }
            }
        }
        
        if (empty($fields)) return $this->getDomain($id);
        
        $values[] = $id;
        $sql = 'UPDATE domains SET ' . implode(', ', $fields) . ' WHERE id = ?';
        $stmt = $this->db->prepare($sql);
        $stmt->execute($values);
        return $this->getDomain($id);
    }
    
    public function deleteDomain(int $id): void {
        $this->db->prepare('DELETE FROM access_logs WHERE domain_id = ?')->execute([$id]);
        $this->db->prepare('DELETE FROM rate_limits WHERE domain_id = ?')->execute([$id]);
        $this->db->prepare('DELETE FROM challenge_tokens WHERE domain_id = ?')->execute([$id]);
        $this->db->prepare('DELETE FROM domains WHERE id = ?')->execute([$id]);
    }
    
    // ============================================
    // LANDING PAGES
    // ============================================
    public function getLandingPages(): array {
        $stmt = $this->db->query('SELECT * FROM landing_pages ORDER BY created_at DESC');
        return $stmt->fetchAll();
    }
    
    public function getLandingPage(int $id): ?array {
        $stmt = $this->db->prepare('SELECT * FROM landing_pages WHERE id = ?');
        $stmt->execute([$id]);
        return $stmt->fetch() ?: null;
    }
    
    public function createLandingPage(array $data): array {
        $sql = 'INSERT INTO landing_pages (name, html_content, css_content, js_content, thumbnail) VALUES (?, ?, ?, ?, ?)';
        $stmt = $this->db->prepare($sql);
        $stmt->execute([
            $data['name'] ?? '',
            $data['htmlContent'] ?? $data['html_content'] ?? '',
            $data['cssContent'] ?? $data['css_content'] ?? null,
            $data['jsContent'] ?? $data['js_content'] ?? null,
            $data['thumbnail'] ?? null,
        ]);
        return $this->getLandingPage((int)$this->db->lastInsertId());
    }
    
    public function updateLandingPage(int $id, array $data): array {
        $fields = [];
        $values = [];
        
        $fieldMap = [
            'name' => 'name',
            'htmlContent' => 'html_content', 'html_content' => 'html_content',
            'cssContent' => 'css_content', 'css_content' => 'css_content',
            'jsContent' => 'js_content', 'js_content' => 'js_content',
            'thumbnail' => 'thumbnail',
        ];
        
        foreach ($data as $key => $value) {
            if (isset($fieldMap[$key])) {
                $dbField = $fieldMap[$key];
                if (!in_array("`$dbField` = ?", $fields)) {
                    $fields[] = "`$dbField` = ?";
                    $values[] = $value;
                }
            }
        }
        
        if (empty($fields)) return $this->getLandingPage($id);
        
        $values[] = $id;
        $sql = 'UPDATE landing_pages SET ' . implode(', ', $fields) . ' WHERE id = ?';
        $stmt = $this->db->prepare($sql);
        $stmt->execute($values);
        return $this->getLandingPage($id);
    }
    
    public function deleteLandingPage(int $id): void {
        $this->db->prepare('DELETE FROM landing_pages WHERE id = ?')->execute([$id]);
    }
    
    // ============================================
    // ACCESS LOGS
    // ============================================
    public function createAccessLog(array $data): array {
        $sql = 'INSERT INTO access_logs (domain_id, ip_address, user_agent, is_bot, bot_score, bot_reasons, destination, headers)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
        $stmt = $this->db->prepare($sql);
        $stmt->execute([
            $data['domainId'] ?? $data['domain_id'] ?? null,
            $data['ipAddress'] ?? $data['ip_address'] ?? null,
            $data['userAgent'] ?? $data['user_agent'] ?? null,
            $data['isBot'] ?? $data['is_bot'] ?? null,
            $data['botScore'] ?? $data['bot_score'] ?? null,
            $data['botReasons'] ?? $data['bot_reasons'] ?? null,
            $data['destination'] ?? null,
            $data['headers'] ?? '{}',
        ]);
        $id = (int)$this->db->lastInsertId();
        $stmt2 = $this->db->prepare('SELECT * FROM access_logs WHERE id = ?');
        $stmt2->execute([$id]);
        return $stmt2->fetch() ?: [];
    }
    
    public function getAccessLogs(int $limit = 100): array {
        $stmt = $this->db->prepare('SELECT * FROM access_logs ORDER BY created_at DESC LIMIT ?');
        $stmt->execute([$limit]);
        return $stmt->fetchAll();
    }
    
    public function getStats(): array {
        $total = $this->db->query('SELECT COUNT(*) as cnt FROM access_logs')->fetch()['cnt'] ?? 0;
        $bots = $this->db->query('SELECT COUNT(*) as cnt FROM access_logs WHERE is_bot = 1')->fetch()['cnt'] ?? 0;
        $real = $total - $bots;
        return [
            'totalVisits' => (int)$total,
            'botVisits' => (int)$bots,
            'realVisits' => (int)$real,
            'botPercentage' => $total > 0 ? round(($bots / $total) * 100) : 0,
        ];
    }
    
    // ============================================
    // BLACKLISTS
    // ============================================
    public function isIpBlacklisted(string $ip): bool {
        $stmt = $this->db->prepare('SELECT id FROM ip_blacklist WHERE ip_address = ?');
        $stmt->execute([$ip]);
        return (bool)$stmt->fetch();
    }
    
    public function isUaBlacklisted(string $userAgent): bool {
        $patterns = $this->db->query('SELECT pattern FROM user_agent_blacklist')->fetchAll();
        foreach ($patterns as $entry) {
            $pattern = $entry['pattern'];
            // Check if pattern is a valid regex (starts with / or #)
            if (preg_match('/^[\/#]/', $pattern)) {
                // It's a regex pattern, use it directly
                $result = @preg_match($pattern . 'i', $userAgent);
                if ($result === 1) {
                    return true;
                }
                // If regex is invalid, fall through to string matching
            }
            // Fallback to simple substring matching
            if (stripos($userAgent, $pattern) !== false) {
                return true;
            }
        }
        return false;
    }
    
    public function getIpBlacklist(): array {
        return $this->db->query('SELECT * FROM ip_blacklist ORDER BY added_at DESC')->fetchAll();
    }
    
    public function addToIpBlacklist(string $ip, ?string $reason = null): array {
        $stmt = $this->db->prepare('INSERT INTO ip_blacklist (ip_address, reason) VALUES (?, ?)');
        $stmt->execute([$ip, $reason]);
        $id = (int)$this->db->lastInsertId();
        $stmt2 = $this->db->prepare('SELECT * FROM ip_blacklist WHERE id = ?');
        $stmt2->execute([$id]);
        return $stmt2->fetch();
    }
    
    public function removeFromIpBlacklist(int $id): void {
        $this->db->prepare('DELETE FROM ip_blacklist WHERE id = ?')->execute([$id]);
    }
    
    public function getUaBlacklist(): array {
        return $this->db->query('SELECT * FROM user_agent_blacklist ORDER BY added_at DESC')->fetchAll();
    }
    
    public function addToUaBlacklist(string $pattern, ?string $reason = null): array {
        $stmt = $this->db->prepare('INSERT INTO user_agent_blacklist (pattern, reason) VALUES (?, ?)');
        $stmt->execute([$pattern, $reason]);
        $id = (int)$this->db->lastInsertId();
        $stmt2 = $this->db->prepare('SELECT * FROM user_agent_blacklist WHERE id = ?');
        $stmt2->execute([$id]);
        return $stmt2->fetch();
    }
    
    public function removeFromUaBlacklist(int $id): void {
        $this->db->prepare('DELETE FROM user_agent_blacklist WHERE id = ?')->execute([$id]);
    }
    
    // ============================================
    // RATE LIMITING
    // ============================================
    public function checkRateLimit(int $domainId, string $ip, int $maxClicks, int $windowSeconds): bool {
        if ($maxClicks <= 0) return true;
        
        $windowStart = date('Y-m-d H:i:s', time() - $windowSeconds);
        $stmt = $this->db->prepare(
            'SELECT click_count FROM rate_limits WHERE domain_id = ? AND ip_address = ? AND first_click >= ?'
        );
        $stmt->execute([$domainId, $ip, $windowStart]);
        $entry = $stmt->fetch();
        
        if (!$entry) return true;
        return ($entry['click_count'] ?? 0) < $maxClicks;
    }
    
    public function incrementRateLimit(int $domainId, string $ip, int $windowSeconds): void {
        $windowStart = date('Y-m-d H:i:s', time() - $windowSeconds);
        $stmt = $this->db->prepare(
            'SELECT id, click_count FROM rate_limits WHERE domain_id = ? AND ip_address = ? AND first_click >= ?'
        );
        $stmt->execute([$domainId, $ip, $windowStart]);
        $existing = $stmt->fetch();
        
        if ($existing) {
            $this->db->prepare('UPDATE rate_limits SET click_count = ?, last_click = NOW() WHERE id = ?')
                ->execute([($existing['click_count'] ?? 0) + 1, $existing['id']]);
        } else {
            $this->db->prepare('INSERT INTO rate_limits (domain_id, ip_address, click_count) VALUES (?, ?, 1)')
                ->execute([$domainId, $ip]);
        }
    }
    
    // ============================================
    // CHALLENGE TOKENS
    // ============================================
    public function createChallengeToken(int $domainId, string $ip, string $ua): string {
        $token = bin2hex(random_bytes(32));
        $expiresAt = date('Y-m-d H:i:s', time() + 300); // 5 minutes
        
        $stmt = $this->db->prepare(
            'INSERT INTO challenge_tokens (token, domain_id, ip_address, user_agent, verified, expires_at) VALUES (?, ?, ?, ?, 0, ?)'
        );
        $stmt->execute([$token, $domainId, $ip, $ua, $expiresAt]);
        return $token;
    }
    
    public function verifyChallengeToken(string $token, string $ip, int $domainId, string $ua): bool {
        $stmt = $this->db->prepare(
            'SELECT * FROM challenge_tokens WHERE token = ? AND ip_address = ? AND domain_id = ? AND expires_at >= NOW()'
        );
        $stmt->execute([$token, $ip, $domainId]);
        $entry = $stmt->fetch();
        
        if (!$entry) return false;
        if ($entry['verified']) return false;
        if ($entry['user_agent'] !== $ua) return false;
        
        // Mark as verified and delete
        $this->db->prepare('UPDATE challenge_tokens SET verified = 1 WHERE id = ?')->execute([$entry['id']]);
        $this->db->prepare('DELETE FROM challenge_tokens WHERE id = ?')->execute([$entry['id']]);
        
        return true;
    }
    
    // ============================================
    // SETTINGS
    // ============================================
    public function getSettings(): array {
        return $this->db->query('SELECT * FROM settings ORDER BY setting_key ASC')->fetchAll();
    }
    
    public function getSetting(string $key): ?string {
        $stmt = $this->db->prepare('SELECT setting_value FROM settings WHERE setting_key = ?');
        $stmt->execute([$key]);
        $row = $stmt->fetch();
        return $row ? $row['setting_value'] : null;
    }
    
    public function setSetting(string $key, ?string $value): array {
        $stmt = $this->db->prepare('SELECT id FROM settings WHERE setting_key = ?');
        $stmt->execute([$key]);
        $existing = $stmt->fetch();
        
        if ($existing) {
            $this->db->prepare('UPDATE settings SET setting_value = ? WHERE setting_key = ?')
                ->execute([$value, $key]);
        } else {
            $this->db->prepare('INSERT INTO settings (setting_key, setting_value) VALUES (?, ?)')
                ->execute([$key, $value]);
        }
        
        $stmt2 = $this->db->prepare('SELECT * FROM settings WHERE setting_key = ?');
        $stmt2->execute([$key]);
        return $stmt2->fetch();
    }
    
    public function deleteSetting(string $key): void {
        $this->db->prepare('DELETE FROM settings WHERE setting_key = ?')->execute([$key]);
    }
    
    // ============================================
    // SEED DATA
    // ============================================
    public function seedData(): void {
        // Create admin if not exists
        $admin = $this->getUserByUsername('admin');
        if (!$admin) {
            $adminPassword = ADMIN_PASSWORD ?: 'boss_' . substr(bin2hex(random_bytes(4)), 0, 8);
            $hashedPassword = password_hash($adminPassword, PASSWORD_BCRYPT, ['cost' => 12]);
            $this->db->prepare('INSERT INTO users (username, password, email) VALUES (?, ?, ?)')
                ->execute(['admin', $hashedPassword, 'admin@boss.local']);
            error_log("==============================================");
            error_log("ADMIN ACCOUNT CREATED");
            error_log("Username: admin");
            if (!ADMIN_PASSWORD) {
                error_log("Password: " . $adminPassword);
            }
            error_log("==============================================");
        } elseif (ADMIN_PASSWORD) {
            $hashedPassword = password_hash(ADMIN_PASSWORD, PASSWORD_BCRYPT, ['cost' => 12]);
            $this->db->prepare('UPDATE users SET password = ? WHERE id = ?')
                ->execute([$hashedPassword, $admin['id']]);
        }
        
        // Create default landing page
        $pages = $this->getLandingPages();
        if (empty($pages)) {
            $this->createLandingPage([
                'name' => 'Telegram Crypto Group',
                'htmlContent' => '<!DOCTYPE html><html><body><h1>Safe Page</h1><p>Welcome to our community.</p></body></html>',
                'cssContent' => 'body { background: #f0f0f0; }',
                'jsContent' => "console.log('Safe page loaded');",
            ]);
        }
        
        // Create default domain
        $domains = $this->getDomains();
        if (empty($domains)) {
            $this->createDomain([
                'domain' => 'promo1',
                'targetUrl' => 'https://example.com/money-page',
                'landingPageId' => 1,
                'redirectEnabled' => 1,
                'status' => 'active',
            ]);
        }
    }
}

// Global storage instance
function getStorage(): Storage {
    static $storage = null;
    if ($storage === null) {
        $storage = new Storage();
    }
    return $storage;
}
