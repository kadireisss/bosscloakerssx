<?php
/**
 * Test Cloaker Engine Functionality
 * Simulates HTTP requests to test redirect logic
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');

echo "=== Cloaker Engine Test ===\n\n";

require_once __DIR__ . '/api/config.php';
require_once __DIR__ . '/api/storage.php';
require_once __DIR__ . '/api/lib/detector.php';

$storage = getStorage();

// Get a test domain
$domains = $storage->getDomains();
if (empty($domains)) {
    echo "No domains found. Creating test domain...\n";
    $pages = $storage->getLandingPages();
    $landingPageId = $pages[0]['id'] ?? 1;
    
    $domain = $storage->createDomain([
        'domain' => 'test-cloaker',
        'targetUrl' => 'https://example.com/money-page',
        'landingPageId' => $landingPageId,
        'redirectEnabled' => true,
        'detectionLevel' => 'high',
        'blockedPlatforms' => 'google,facebook',
        'jsChallenge' => false
    ]);
} else {
    $domain = $domains[0];
}

echo "Using domain: {$domain['domain']} (Slug: {$domain['slug']})\n\n";

// Test scenarios
$scenarios = [
    [
        'name' => 'Normal User (Chrome Desktop)',
        'ip' => '192.168.1.50',
        'ua' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'headers' => [
            'accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'accept-language' => 'en-US,en;q=0.9',
            'accept-encoding' => 'gzip, deflate, br',
            'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ],
        'expected' => 'target'
    ],
    [
        'name' => 'Google Ads Bot (IP Detection)',
        'ip' => '66.249.64.10',
        'ua' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'headers' => [
            'accept' => 'text/html',
            'user-agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
        ],
        'expected' => 'landing'
    ],
    [
        'name' => 'Facebook Bot (UA Detection)',
        'ip' => '192.168.1.60',
        'ua' => 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
        'headers' => [
            'accept' => '*/*',
            'user-agent' => 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)'
        ],
        'expected' => 'landing'
    ],
    [
        'name' => 'Suspicious Bot (Short UA)',
        'ip' => '192.168.1.70',
        'ua' => 'Bot',
        'headers' => [
            'accept' => 'text/html',
            'user-agent' => 'Bot'
        ],
        'expected' => 'landing'
    ],
    [
        'name' => 'Bot with Missing Headers',
        'ip' => '192.168.1.80',
        'ua' => 'Mozilla/5.0',
        'headers' => [
            'user-agent' => 'Mozilla/5.0'
        ],
        'expected' => 'landing'
    ],
    [
        'name' => 'Normal Mobile User',
        'ip' => '192.168.1.90',
        'ua' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
        'headers' => [
            'accept' => 'text/html',
            'accept-language' => 'en-US,en;q=0.9',
            'accept-encoding' => 'gzip, deflate',
            'user-agent' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
        ],
        'expected' => 'target'
    ]
];

echo "Testing " . count($scenarios) . " scenarios...\n\n";

$passed = 0;
$failed = 0;

foreach ($scenarios as $i => $scenario) {
    echo "Test " . ($i + 1) . ": {$scenario['name']}\n";
    echo "  IP: {$scenario['ip']}\n";
    echo "  UA: " . substr($scenario['ua'], 0, 60) . "...\n";
    
    $domainSettings = [
        'blockedPlatforms' => $domain['blocked_platforms'],
        'detectionLevel' => $domain['detection_level'],
        'blockDirectAccess' => (bool)$domain['block_direct_access']
    ];
    
    $result = detectBot(
        $scenario['ip'],
        $scenario['ua'],
        $scenario['headers'],
        '',
        $domainSettings
    );
    
    $destination = $result['isBot'] ? 'landing' : 'target';
    $status = ($destination === $scenario['expected']) ? '✓' : '✗';
    
    echo "  Score: {$result['score']}\n";
    echo "  Detected as: " . ($result['isBot'] ? 'BOT' : 'REAL USER') . "\n";
    echo "  Destination: $destination\n";
    echo "  Result: $status " . ($status === '✓' ? 'PASS' : 'FAIL (expected: ' . $scenario['expected'] . ')') . "\n";
    
    if (!empty($result['reasons'])) {
        echo "  Reasons: " . implode(', ', array_slice($result['reasons'], 0, 3)) . "\n";
    }
    
    if ($status === '✓') {
        $passed++;
    } else {
        $failed++;
    }
    
    echo "\n";
}

echo "=== Test Summary ===\n";
echo "Total: " . count($scenarios) . "\n";
echo "Passed: $passed ✓\n";
echo "Failed: $failed ✗\n";
echo "\n";

if ($failed === 0) {
    echo "All tests PASSED! ✓\n";
} else {
    echo "Some tests FAILED! ✗\n";
}
