<?php
/**
 * Beacon endpoint for free report behavioral events.
 *
 * Receives navigator.sendBeacon() payloads (Content-Type: text/plain).
 * $_POST is empty for beacon requests — body is read via php://input.
 */

require dirname(__DIR__) . '/config.php';

$raw  = file_get_contents('php://input');
$data = $raw !== false && $raw !== '' ? json_decode($raw, true) : null;

if (!is_array($data)) {
    http_response_code(400);
    exit;
}

// Validate token (UUID v4 format)
$token = trim($data['token'] ?? '');
if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $token)) {
    http_response_code(400);
    exit;
}

// Validate event_type
$allowed_types = ['page_viewed', 'cta_visible', 'cta_clicked', 'checkout_started'];
$event_type    = trim($data['event_type'] ?? '');
if (!in_array($event_type, $allowed_types, true)) {
    http_response_code(400);
    exit;
}

$session_id = isset($data['session_id']) ? substr(trim((string)$data['session_id']), 0, 64) : null;
if ($session_id === '') $session_id = null;

$con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if (mysqli_connect_errno()) {
    http_response_code(500);
    exit;
}

// Rate limit: max 20 events per token per minute
$window = date('Y-m-d H:i:00'); // fixed 1-minute bucket
$rl = $con->prepare(
    'INSERT INTO report_event_rl (token, window_start, count) VALUES (?, ?, 1)
     ON DUPLICATE KEY UPDATE count = count + 1'
);
$rl->bind_param('ss', $token, $window);
$rl->execute();
$rl->close();

$rl_check = $con->prepare('SELECT count FROM report_event_rl WHERE token = ? AND window_start = ?');
$rl_check->bind_param('ss', $token, $window);
$rl_check->execute();
$rl_check->bind_result($rl_count);
$rl_check->fetch();
$rl_check->close();

if ((int)$rl_count > 20) {
    mysqli_close($con);
    http_response_code(429);
    exit;
}

$ins = $con->prepare(
    'INSERT INTO report_events (token, event_type, session_id) VALUES (?, ?, ?)'
);
$ins->bind_param('sss', $token, $event_type, $session_id);
if (!$ins->execute()) {
    error_log('ip2geo report-event.php INSERT failed: ' . $ins->error);
    $ins->close();
    mysqli_close($con);
    http_response_code(500);
    exit;
}
$ins->close();
mysqli_close($con);

http_response_code(200);
