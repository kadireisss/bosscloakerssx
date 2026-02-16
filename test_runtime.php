<?php
/**
 * BOSS Cloaker - Runtime Test Script
 * Tests database connectivity, API functionality, and error checking
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('log_errors', '1');

echo "=== BOSS Cloaker Runtime Tests ===\n\n";

// Test 1: Database Configuration
echo "Test 1: Loading config.php...\n";
try {
    require_once __DIR__ . '/api/config.php';
    echo "✓ Config loaded successfully\n\n";
} catch (Exception $e) {
    echo "✗ Config load failed: " . $e->getMessage() . "\n\n";
    exit(1);
}

// Test 2: Database Connection
echo "Test 2: Testing database connection...\n";
try {
    $pdo = getDB();
    echo "✓ PDO connection established\n";
    
    $version = $pdo->query("SELECT VERSION()")->fetchColumn();
    echo "✓ Database version: $version\n\n";
} catch (Exception $e) {
    echo "✗ Database connection failed: " . $e->getMessage() . "\n\n";
    exit(1);
}

// Test 3: Storage Class
echo "Test 3: Loading storage class...\n";
try {
    require_once __DIR__ . '/api/storage.php';
    $storage = getStorage();
    echo "✓ Storage class loaded\n\n";
} catch (Exception $e) {
    echo "✗ Storage class failed: " . $e->getMessage() . "\n\n";
    exit(1);
}

// Test 4: Seed Data (Creates admin user)
echo "Test 4: Running seed data...\n";
try {
    $storage->seedData();
    echo "✓ Seed data executed\n\n";
} catch (Exception $e) {
    echo "✗ Seed data failed: " . $e->getMessage() . "\n\n";
    exit(1);
}

// Test 5: User Operations
echo "Test 5: Testing user operations...\n";
try {
    $admin = $storage->getUserByUsername('admin');
    if ($admin) {
        echo "✓ Admin user found (ID: {$admin['id']})\n";
        echo "✓ Username: {$admin['username']}\n";
    } else {
        echo "✗ Admin user not found\n";
    }
    echo "\n";
} catch (Exception $e) {
    echo "✗ User operations failed: " . $e->getMessage() . "\n\n";
}

// Test 6: Landing Page Operations
echo "Test 6: Testing landing page CRUD...\n";
try {
    // Create
    $page = $storage->createLandingPage([
        'name' => 'Test Page',
        'htmlContent' => '<html><body>Test</body></html>',
        'cssContent' => 'body { background: #fff; }',
        'jsContent' => 'console.log("test");'
    ]);
    echo "✓ Created landing page (ID: {$page['id']})\n";
    
    // Read
    $pages = $storage->getLandingPages();
    echo "✓ Retrieved " . count($pages) . " landing pages\n";
    
    // Update
    $updated = $storage->updateLandingPage($page['id'], [
        'name' => 'Updated Test Page'
    ]);
    echo "✓ Updated landing page\n";
    
    // Don't delete yet - we'll use it for domain test
    echo "\n";
} catch (Exception $e) {
    echo "✗ Landing page operations failed: " . $e->getMessage() . "\n\n";
}

// Test 7: Domain Operations
echo "Test 7: Testing domain CRUD...\n";
try {
    // Get the first landing page ID
    $pages = $storage->getLandingPages();
    $landingPageId = $pages[0]['id'] ?? 1;
    
    // Create
    $domain = $storage->createDomain([
        'domain' => 'test-domain-' . time(),
        'targetUrl' => 'https://example.com/target',
        'landingPageId' => $landingPageId,
        'redirectEnabled' => true,
        'detectionLevel' => 'high',
        'blockedPlatforms' => 'google,facebook',
        'jsChallenge' => false,
        'maxClicksPerIp' => 10,
        'allowMobile' => true,
        'allowDesktop' => true
    ]);
    echo "✓ Created domain (ID: {$domain['id']}, Slug: {$domain['slug']})\n";
    
    // Read
    $domains = $storage->getDomains();
    echo "✓ Retrieved " . count($domains) . " domains\n";
    
    // Read by slug
    $domainBySlug = $storage->getDomainBySlug($domain['slug']);
    echo "✓ Retrieved domain by slug: {$domainBySlug['domain']}\n";
    
    // Update
    $updated = $storage->updateDomain($domain['id'], [
        'detectionLevel' => 'medium'
    ]);
    echo "✓ Updated domain\n";
    
    echo "\n";
} catch (Exception $e) {
    echo "✗ Domain operations failed: " . $e->getMessage() . "\n\n";
}

// Test 8: Access Log
echo "Test 8: Testing access log...\n";
try {
    $log = $storage->createAccessLog([
        'domainId' => $domain['id'] ?? 1,
        'ipAddress' => '192.168.1.100',
        'userAgent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
        'isBot' => 0,
        'botScore' => 10,
        'botReasons' => json_encode(['NONE']),
        'destination' => 'target',
        'headers' => json_encode(['accept' => 'text/html'])
    ]);
    echo "✓ Created access log (ID: {$log['id']})\n";
    
    $logs = $storage->getAccessLogs(10);
    echo "✓ Retrieved " . count($logs) . " access logs\n";
    
    echo "\n";
} catch (Exception $e) {
    echo "✗ Access log failed: " . $e->getMessage() . "\n\n";
}

// Test 9: Blacklist Operations
echo "Test 9: Testing IP blacklist...\n";
try {
    $entry = $storage->addToIpBlacklist('10.0.0.1', 'Test block');
    echo "✓ Added IP to blacklist (ID: {$entry['id']})\n";
    
    $isBlacklisted = $storage->isIpBlacklisted('10.0.0.1');
    echo "✓ IP blacklist check: " . ($isBlacklisted ? 'BLOCKED' : 'ALLOWED') . "\n";
    
    $blacklist = $storage->getIpBlacklist();
    echo "✓ Retrieved " . count($blacklist) . " blacklist entries\n";
    
    echo "\n";
} catch (Exception $e) {
    echo "✗ Blacklist operations failed: " . $e->getMessage() . "\n\n";
}

// Test 10: UA Blacklist
echo "Test 10: Testing UA blacklist...\n";
try {
    $entry = $storage->addToUaBlacklist('testbot', 'Test pattern');
    echo "✓ Added UA pattern to blacklist (ID: {$entry['id']})\n";
    
    $isBlacklisted = $storage->isUaBlacklisted('Mozilla/5.0 testbot/1.0');
    echo "✓ UA blacklist check: " . ($isBlacklisted ? 'BLOCKED' : 'ALLOWED') . "\n";
    
    echo "\n";
} catch (Exception $e) {
    echo "✗ UA blacklist failed: " . $e->getMessage() . "\n\n";
}

// Test 11: Rate Limiting
echo "Test 11: Testing rate limiting...\n";
try {
    $allowed = $storage->checkRateLimit($domain['id'] ?? 1, '192.168.1.200', 5, 3600);
    echo "✓ Rate limit check (before): " . ($allowed ? 'ALLOWED' : 'BLOCKED') . "\n";
    
    $storage->incrementRateLimit($domain['id'] ?? 1, '192.168.1.200', 3600);
    echo "✓ Incremented rate limit counter\n";
    
    echo "\n";
} catch (Exception $e) {
    echo "✗ Rate limiting failed: " . $e->getMessage() . "\n\n";
}

// Test 12: Challenge Tokens
echo "Test 12: Testing JS challenge tokens...\n";
try {
    $token = $storage->createChallengeToken($domain['id'] ?? 1, '192.168.1.300', 'Mozilla/5.0');
    echo "✓ Created challenge token: " . substr($token, 0, 16) . "...\n";
    
    $verified = $storage->verifyChallengeToken($token, '192.168.1.300', $domain['id'] ?? 1, 'Mozilla/5.0');
    echo "✓ Token verification: " . ($verified ? 'VALID' : 'INVALID') . "\n";
    
    echo "\n";
} catch (Exception $e) {
    echo "✗ Challenge tokens failed: " . $e->getMessage() . "\n\n";
}

// Test 13: Settings
echo "Test 13: Testing settings...\n";
try {
    $setting = $storage->setSetting('test_key', 'test_value');
    echo "✓ Set setting: test_key = test_value\n";
    
    $value = $storage->getSetting('test_key');
    echo "✓ Retrieved setting: $value\n";
    
    echo "\n";
} catch (Exception $e) {
    echo "✗ Settings failed: " . $e->getMessage() . "\n\n";
}

// Test 14: Bot Detector
echo "Test 14: Testing bot detector...\n";
try {
    require_once __DIR__ . '/api/lib/detector.php';
    
    // Test normal user
    $result = detectBot(
        '192.168.1.100',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
        [
            'accept' => 'text/html',
            'accept-language' => 'en-US,en;q=0.9',
            'accept-encoding' => 'gzip, deflate'
        ],
        '',
        ['detectionLevel' => 'high']
    );
    echo "✓ Normal user detection - Score: {$result['score']}, Bot: " . ($result['isBot'] ? 'YES' : 'NO') . "\n";
    
    // Test bot (Google Ads IP)
    $result2 = detectBot(
        '66.249.64.1',
        'Mozilla/5.0 (compatible; Googlebot/2.1)',
        ['accept' => 'text/html'],
        '',
        ['detectionLevel' => 'high', 'blockedPlatforms' => 'google']
    );
    echo "✓ Bot detection - Score: {$result2['score']}, Bot: " . ($result2['isBot'] ? 'YES' : 'NO') . "\n";
    
    echo "\n";
} catch (Exception $e) {
    echo "✗ Bot detector failed: " . $e->getMessage() . "\n\n";
}

// Test 15: Stats
echo "Test 15: Testing statistics...\n";
try {
    $stats = $storage->getStats();
    echo "✓ Total visits: {$stats['totalVisits']}\n";
    echo "✓ Bot visits: {$stats['botVisits']}\n";
    echo "✓ Real visits: {$stats['realVisits']}\n";
    echo "✓ Bot percentage: {$stats['botPercentage']}%\n";
    
    echo "\n";
} catch (Exception $e) {
    echo "✗ Statistics failed: " . $e->getMessage() . "\n\n";
}

echo "=== All Tests Completed ===\n";
echo "Check for any warnings or notices above.\n";
