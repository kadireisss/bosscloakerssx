<?php
/**
 * BOSS Cloaker - Bot Detector Engine
 * PHP port of the Node.js detector
 */

// ============================================
// GOOGLE ADS / ADSENSE / SAFE BROWSING IP RANGES
// ============================================
const GOOGLE_RANGES = [
    '66.249.64.0/19', '66.249.0.0/16',
    '64.233.160.0/19', '64.233.0.0/16',
    '72.14.192.0/18', '72.14.0.0/16',
    '209.85.128.0/17', '209.85.0.0/16',
    '216.239.32.0/19', '216.239.0.0/16',
    '66.102.0.0/20', '74.125.0.0/16',
    '173.194.0.0/16', '142.250.0.0/15',
    '172.217.0.0/16', '216.58.0.0/16',
    '108.177.0.0/17', '35.190.0.0/17',
    '35.191.0.0/16', '130.211.0.0/22',
    '34.64.0.0/10', '35.184.0.0/13',
    '35.192.0.0/14', '35.196.0.0/15',
    '35.198.0.0/16', '35.199.0.0/16',
    '35.200.0.0/13', '35.208.0.0/12',
    '35.224.0.0/12', '35.240.0.0/13',
    '2001:4860::/32',
    '2404:6800::/32',
    '2607:f8b0::/32',
    '2800:3f0::/32',
    '2a00:1450::/32',
    '2c0f:fb50::/32',
];

const FACEBOOK_RANGES = [
    '31.13.24.0/21', '31.13.64.0/18',
    '45.64.40.0/22', '66.220.144.0/20',
    '69.63.176.0/20', '69.171.224.0/19',
    '74.119.76.0/22', '102.132.96.0/20',
    '103.4.96.0/22', '129.134.0.0/16',
    '157.240.0.0/16', '173.252.64.0/18',
    '179.60.192.0/22', '185.60.216.0/22',
    '185.89.216.0/22', '199.201.64.0/22',
    '204.15.20.0/22',
    '2a03:2880::/32',
    '2620:0:1c00::/40',
    '2620:0:1cff::/48',
];

const MICROSOFT_RANGES = [
    '13.64.0.0/11', '13.96.0.0/13',
    '13.104.0.0/14', '20.0.0.0/8',
    '40.64.0.0/10', '40.74.0.0/15',
    '40.76.0.0/14', '40.80.0.0/12',
    '40.96.0.0/12', '40.112.0.0/13',
    '40.120.0.0/14', '40.124.0.0/16',
    '40.125.0.0/17', '40.126.0.0/18',
    '52.0.0.0/8', '65.52.0.0/14',
    '70.37.0.0/17', '70.37.128.0/18',
    '104.40.0.0/13', '104.208.0.0/13',
    '131.253.0.0/16', '134.170.0.0/16',
    '137.116.0.0/15', '137.135.0.0/16',
    '138.91.0.0/16', '157.55.0.0/16',
    '157.56.0.0/14', '168.61.0.0/16',
    '168.62.0.0/15', '191.232.0.0/13',
    '199.30.16.0/20', '207.46.0.0/16',
    '2603:1000::/25',
    '2603:1010::/25',
    '2603:1020::/25',
    '2603:1030::/25',
    '2603:1040::/25',
    '2603:1050::/25',
    '2a01:111::/32',
];

const CLOUDFLARE_RANGES = [
    '173.245.48.0/20', '103.21.244.0/22',
    '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18',
    '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17',
    '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13',
    '131.0.72.0/22',
];

const USOM_RANGES = [
    '193.140.0.0/16', '193.255.0.0/16',
    '212.174.0.0/16', '85.120.0.0/14',
];

const AWS_RANGES = [
    '3.0.0.0/8', '13.32.0.0/12',
    '18.0.0.0/8', '34.192.0.0/10',
    '35.0.0.0/8', '44.192.0.0/10',
    '52.0.0.0/8', '54.0.0.0/8',
    '99.77.0.0/16', '99.80.0.0/12',
    '176.32.0.0/12', '205.251.192.0/19',
];

const SECURITY_SCANNER_RANGES = [
    '74.125.0.0/16',
    '185.220.101.0/24',
    '192.88.134.0/23', '185.93.228.0/22',
    '199.83.128.0/21', '198.143.32.0/19',
    '23.0.0.0/12', '23.32.0.0/11',
    '23.64.0.0/14', '23.72.0.0/13',
    '96.16.0.0/15', '96.6.0.0/15',
    '104.64.0.0/10', '184.24.0.0/13',
    '184.50.0.0/15', '184.84.0.0/14',
];

const DATACENTER_RANGES = [
    // DigitalOcean
    '104.131.0.0/16', '104.236.0.0/16',
    '138.68.0.0/16', '138.197.0.0/16',
    '139.59.0.0/16', '142.93.0.0/16',
    '146.185.128.0/17', '159.65.0.0/16',
    '159.89.0.0/16', '161.35.0.0/16',
    '162.243.0.0/16', '165.22.0.0/16',
    '167.71.0.0/16', '167.172.0.0/16',
    '178.128.0.0/16', '188.166.0.0/16',
    '206.189.0.0/16', '207.154.192.0/18',
    // Linode
    '45.33.0.0/16', '45.56.0.0/16',
    '45.79.0.0/16', '50.116.0.0/16',
    '66.175.208.0/20', '69.164.192.0/18',
    '72.14.176.0/20', '74.207.224.0/19',
    '96.126.96.0/19', '97.107.128.0/17',
    '139.162.0.0/16', '172.104.0.0/15',
    '173.255.192.0/18', '178.79.128.0/17',
    '192.155.80.0/20', '198.58.96.0/19',
    // Vultr
    '45.32.0.0/16', '45.63.0.0/16',
    '45.76.0.0/15', '64.156.0.0/16',
    '66.42.0.0/16', '104.156.224.0/19',
    '104.207.128.0/17', '108.61.0.0/16',
    '136.244.0.0/16', '140.82.0.0/16',
    '144.202.0.0/16', '149.28.0.0/16',
    '155.138.0.0/16', '207.148.0.0/16',
    '208.167.224.0/19', '217.163.0.0/16',
    // Hetzner
    '5.9.0.0/16', '46.4.0.0/16',
    '78.46.0.0/15', '88.198.0.0/15',
    '94.130.0.0/16', '95.216.0.0/15',
    '116.202.0.0/15', '116.203.0.0/16',
    '135.181.0.0/16', '136.243.0.0/16',
    '138.201.0.0/16', '142.132.128.0/17',
    '144.76.0.0/16', '148.251.0.0/16',
    '157.90.0.0/16', '159.69.0.0/16',
    '162.55.0.0/16', '167.235.0.0/16',
    '168.119.0.0/16', '176.9.0.0/16',
    '178.63.0.0/16', '188.40.0.0/16',
    '195.201.0.0/16', '213.133.96.0/19',
    '213.239.192.0/18',
    // OVH
    '5.39.0.0/16', '5.135.0.0/16',
    '5.196.0.0/15', '37.59.0.0/16',
    '37.187.0.0/16', '46.105.0.0/16',
    '51.38.0.0/15', '51.68.0.0/15',
    '51.75.0.0/16', '51.77.0.0/16',
    '51.79.0.0/16', '51.83.0.0/16',
    '51.89.0.0/16', '51.91.0.0/16',
    '54.36.0.0/14', '54.37.0.0/16',
    '54.38.0.0/16', '57.128.0.0/14',
    '91.121.0.0/16', '92.222.0.0/16',
    '135.125.0.0/16', '137.74.0.0/16',
    '139.99.0.0/16', '141.94.0.0/16',
    '141.95.0.0/16', '144.217.0.0/16',
    '145.239.0.0/16', '147.135.0.0/16',
    '149.56.0.0/16', '151.80.0.0/16',
    '158.69.0.0/16', '162.19.0.0/16',
    '164.132.0.0/16', '167.114.0.0/16',
    '176.31.0.0/16', '178.32.0.0/15',
    '185.228.64.0/18', '188.165.0.0/16',
    '192.95.0.0/16', '193.70.0.0/16',
    '198.27.64.0/18', '198.50.128.0/17',
    '198.100.144.0/20', '213.186.32.0/19',
    '213.251.128.0/18',
];

// ============================================
// BOT USER-AGENT PATTERNS
// ============================================
const BOT_UA_PATTERNS = [
    'googleads', 'google-ads', 'adsbot', 'mediapartners',
    'facebookexternalhit', 'facebookcatalog', 'facebot',
    'bingpreview', 'adidxbot', 'bingbot',
    'twitterbot', 'linkedinbot', 'pinterestbot',
    'slackbot', 'telegrambot', 'whatsapp',
    'googlebot', 'google-inspectiontool',
    'slurp', 'duckduckbot',
    'yandexbot', 'baiduspider', 'sogou',
    'exabot', 'ia_archiver',
    'bot', 'crawler', 'spider', 'scraper',
    'robot', 'automated', 'monitor', 'checker',
    'curl', 'wget', 'python', 'java/', 'perl',
    'ruby', 'go-http-client', 'axios', 'node-fetch',
    'request', 'okhttp', 'apache-httpclient',
    'libwww', 'urllib', 'httplib', 'aiohttp',
    'headlesschrome', 'headless', 'phantomjs',
    'selenium', 'puppeteer', 'playwright',
    'chromium', 'chrome-lighthouse',
    'virustotal', 'urlscan', 'safeweb',
    'kaspersky', 'norton', 'mcafee', 'avast',
    'bitdefender', 'eset', 'avg', 'sophos',
    'trendmicro', 'symantec', 'malwarebytes',
    'nessus', 'nikto', 'nmap', 'masscan',
    'zap', 'burp', 'sqlmap', 'acunetix',
    'qualys', 'nexpose', 'openvas',
    'metasploit', 'shodan', 'censys',
    'cloudflare', 'akamai', 'fastly',
    'cloudfront', 'imperva', 'incapsula',
    'usom', 'tubitak', 'redpage', 'siber',
    'linkchecker', 'link-checker', 'deadlinkchecker',
    'w3c_validator', 'validator', 'gtmetrix',
    'pagespeed', 'lighthouse',
    'preview', 'thumbnail', 'snapshot',
    'screenshotbot', 'webshot',
];

// ============================================
// AD PLATFORM REFERER PATTERNS
// ============================================
const AD_PLATFORM_REFERERS = [
    'googleads.g.doubleclick.net',
    'googleadservices.com',
    'googlesyndication.com',
    'google.com/aclk',
    'google.com/pagead',
    'google.com/url?',
    'facebook.com/ads',
    'facebook.com/tr',
    'business.facebook.com',
    'bing.com/aclk',
    'bing.com/ads',
    'linkedin.com/ads',
    'pinterest.com/ads',
    'tiktok.com/ads',
    'twitter.com/ads',
    'outbrain.com',
    'taboola.com',
    'criteo.com',
    'adroll.com',
];

// ============================================
// PLATFORM MAPPINGS
// ============================================
const PLATFORM_IP_RANGES = [
    'google' => 'GOOGLE_RANGES',
    'facebook' => 'FACEBOOK_RANGES',
    'microsoft' => 'MICROSOFT_RANGES',
    'bing' => 'MICROSOFT_RANGES',
    'cloudflare' => 'CLOUDFLARE_RANGES',
    'aws' => 'AWS_RANGES',
];

const PLATFORM_UA_PATTERNS_MAP = [
    'google' => ['googleads', 'google-ads', 'adsbot', 'mediapartners', 'googlebot', 'google-inspectiontool'],
    'facebook' => ['facebookexternalhit', 'facebookcatalog', 'facebot'],
    'microsoft' => ['bingpreview', 'adidxbot', 'bingbot'],
    'bing' => ['bingpreview', 'adidxbot', 'bingbot'],
    'tiktok' => ['tiktok', 'bytespider', 'bytedance'],
    'twitter' => ['twitterbot'],
    'linkedin' => ['linkedinbot'],
    'pinterest' => ['pinterestbot'],
];

const PLATFORM_CLICK_IDS = [
    'google' => 'gclid',
    'facebook' => 'fbclid',
    'microsoft' => 'msclkid',
    'bing' => 'msclkid',
    'tiktok' => 'ttclid',
    'twitter' => 'twclid',
    'linkedin' => 'li_fat_id',
];

// ============================================
// HELPER FUNCTIONS
// ============================================

function ipToLong(string $ip): int {
    return ip2long($ip) ?: 0;
}

function isIPv4InCidr(string $ip, string $cidr): bool {
    if (strpos($cidr, ':') !== false) return false; // IPv6 CIDR
    $parts = explode('/', $cidr);
    if (count($parts) !== 2) return false;
    
    $subnet = ip2long($parts[0]);
    $ipLong = ip2long($ip);
    if ($subnet === false || $ipLong === false) return false;
    
    $mask = -1 << (32 - (int)$parts[1]);
    $subnet &= $mask;
    return ($ipLong & $mask) === $subnet;
}

function isIPv6InCidr(string $ip, string $cidr): bool {
    if (strpos($cidr, ':') === false) return false; // IPv4 CIDR
    $parts = explode('/', $cidr);
    if (count($parts) !== 2) return false;
    
    $subnet = inet_pton($parts[0]);
    $ipBin = inet_pton($ip);
    if ($subnet === false || $ipBin === false) return false;
    
    $prefix = (int)$parts[1];
    $mask = str_repeat('f', intdiv($prefix, 4));
    $remainder = $prefix % 4;
    if ($remainder > 0) {
        $mask .= dechex((0xf << (4 - $remainder)) & 0xf);
    }
    $mask = str_pad($mask, 32, '0');
    $maskBin = pack('H*', $mask);
    
    return ($ipBin & $maskBin) === ($subnet & $maskBin);
}

function isIpInCidr(string $ip, string $cidr): bool {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return isIPv4InCidr($ip, $cidr);
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return isIPv6InCidr($ip, $cidr);
    }
    return false;
}

function ipInRanges(string $ip, array $ranges): bool {
    foreach ($ranges as $range) {
        if (isIpInCidr($ip, $range)) return true;
    }
    return false;
}

function getPlatformRanges(string $platform): array {
    $map = [
        'google' => GOOGLE_RANGES,
        'facebook' => FACEBOOK_RANGES,
        'microsoft' => MICROSOFT_RANGES,
        'bing' => MICROSOFT_RANGES,
        'cloudflare' => CLOUDFLARE_RANGES,
        'aws' => AWS_RANGES,
    ];
    return $map[$platform] ?? [];
}

function checkUserAgent(string $ua): array {
    $uaLower = strtolower($ua);
    
    if (empty($ua) || strlen($ua) < 30) {
        return ['isBot' => true, 'pattern' => 'SHORT_OR_EMPTY_UA'];
    }
    
    foreach (BOT_UA_PATTERNS as $pattern) {
        if (strpos($uaLower, $pattern) !== false) {
            return ['isBot' => true, 'pattern' => $pattern];
        }
    }
    
    return ['isBot' => false, 'pattern' => null];
}

function checkHeaders(array $headers): array {
    $score = 0;
    $reasons = [];
    
    if (empty($headers['accept-language'])) {
        $score += 15;
        $reasons[] = 'MISSING_ACCEPT_LANGUAGE';
    }
    
    if (empty($headers['accept-encoding'])) {
        $score += 10;
        $reasons[] = 'MISSING_ACCEPT_ENCODING';
    }
    
    if (empty($headers['accept'])) {
        $score += 10;
        $reasons[] = 'MISSING_ACCEPT';
    }
    
    $hasSecFetch = !empty($headers['sec-fetch-mode']) || !empty($headers['sec-fetch-site']) || !empty($headers['sec-fetch-dest']);
    if (!$hasSecFetch && isset($headers['user-agent']) && strpos($headers['user-agent'], 'Chrome') !== false) {
        $score += 25;
        $reasons[] = 'CHROME_WITHOUT_SEC_FETCH';
    }
    
    if (!empty($headers['via']) || (isset($headers['x-forwarded-for']) && strpos($headers['x-forwarded-for'], ',') !== false)) {
        $score += 10;
        $reasons[] = 'PROXY_HEADERS_DETECTED';
    }
    
    return ['score' => $score, 'reasons' => $reasons];
}

// ============================================
// MAIN DETECTION FUNCTION
// ============================================
function detectBot(string $ip, string $userAgent, array $headers, string $fullUrl = '', array $domainSettings = []): array {
    $score = 0;
    $reasons = [];
    
    $blockedPlatformsStr = $domainSettings['blockedPlatforms'] ?? 'google,facebook,bing,tiktok,twitter,linkedin';
    $blockedPlatforms = array_map('trim', array_map('strtolower', explode(',', $blockedPlatformsStr)));
    $blockDirectAccess = (bool)($domainSettings['blockDirectAccess'] ?? false);
    $detectionLevel = $domainSettings['detectionLevel'] ?? 'high';
    
    $thresholds = [
        'low' => 80,
        'medium' => 60,
        'high' => 50,
        'paranoid' => 30,
    ];
    $threshold = $thresholds[$detectionLevel] ?? 50;
    
    $uaLower = strtolower($userAgent);
    
    // 1. PLATFORM-SPECIFIC IP DETECTION
    foreach ($blockedPlatforms as $platform) {
        $ipRanges = getPlatformRanges($platform);
        if (!empty($ipRanges) && ipInRanges($ip, $ipRanges)) {
            $score += 100;
            $reasons[] = strtoupper($platform) . '_IP_DETECTED';
        }
        
        $uaPatterns = PLATFORM_UA_PATTERNS_MAP[$platform] ?? [];
        foreach ($uaPatterns as $pattern) {
            if (strpos($uaLower, $pattern) !== false) {
                $score += 80;
                $reasons[] = strtoupper($platform) . '_UA: ' . $pattern;
                break;
            }
        }
        
        if (!empty($fullUrl)) {
            $parsedUrl = parse_url($fullUrl);
            if (isset($parsedUrl['query'])) {
                parse_str($parsedUrl['query'], $queryParams);
                $clickId = PLATFORM_CLICK_IDS[$platform] ?? null;
                if ($clickId && isset($queryParams[$clickId])) {
                    $score += 60;
                    $reasons[] = strtoupper($platform) . '_CLICK_ID: ' . $clickId;
                }
            }
        }
    }
    
    // 2. ALWAYS CHECK: USOM, Security Scanners, Datacenters
    if (ipInRanges($ip, USOM_RANGES)) {
        $score += 100;
        $reasons[] = 'USOM_IP_DETECTED';
    }
    
    if (ipInRanges($ip, SECURITY_SCANNER_RANGES)) {
        $score += 90;
        $reasons[] = 'SECURITY_SCANNER_IP';
    }
    
    if (ipInRanges($ip, DATACENTER_RANGES)) {
        $score += 60;
        $reasons[] = 'DATACENTER_IP';
    }
    
    // 3. GENERIC BOT USER-AGENT DETECTION
    $uaCheck = checkUserAgent($userAgent);
    if ($uaCheck['isBot']) {
        $score += 50;
        $reasons[] = 'BOT_UA: ' . $uaCheck['pattern'];
    }
    
    // 4. HEADER ANALYSIS
    $headerCheck = checkHeaders($headers);
    $score += $headerCheck['score'];
    $reasons = array_merge($reasons, $headerCheck['reasons']);
    
    // 5. DIRECT ACCESS DETECTION
    $referer = $headers['referer'] ?? ($headers['referrer'] ?? '');
    
    if ($blockDirectAccess && empty($referer)) {
        if (empty($headers['accept-language']) || empty($headers['accept-encoding'])) {
            $score += 50;
            $reasons[] = 'DIRECT_ACCESS_BLOCKED';
        } else {
            $score += 30;
            $reasons[] = 'DIRECT_ACCESS_WARNING';
        }
    }
    
    // 6. UTM/REFERER ANALYSIS
    if (!empty($referer)) {
        $refLower = strtolower($referer);
        foreach (AD_PLATFORM_REFERERS as $adRef) {
            if (strpos($refLower, $adRef) !== false) {
                $score += 30;
                $reasons[] = 'AD_REFERER: ' . $adRef;
                break;
            }
        }
    }
    
    // 7. BEHAVIORAL CHECKS
    if (empty($headers['cookie']) && !empty($referer)) {
        $score += 15;
        $reasons[] = 'NO_COOKIES_WITH_REFERER';
    }
    
    return [
        'isBot' => $score >= $threshold,
        'score' => $score,
        'reasons' => $reasons,
    ];
}
