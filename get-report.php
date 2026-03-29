<?php
/**
 * Token creation + Stripe Checkout redirect.
 *
 * Called when the user clicks "Get Full Report + Block Script — $9".
 * Stores ip_list_json at this point so report.php can generate the report
 * after payment without relying on POST data or server sessions.
 *
 * Expected: POST with ip_classified_json (JSON array of classified IPs).
 * Falls back to a redirect back to the homepage on any error.
 */

require __DIR__ . '/config.php';
require __DIR__ . '/asn_classification.php';
require __DIR__ . '/vendor/autoload.php';

// ── Validate input ────────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /');
    exit;
}

$raw_json = $_POST['ip_classified_json'] ?? '';
if ($raw_json === '') {
    header('Location: /?error=no_data');
    exit;
}

$ip_data = json_decode($raw_json, true);
if (!is_array($ip_data) || count($ip_data) === 0) {
    header('Location: /?error=no_data');
    exit;
}

// Size guard: ip_list_json is MEDIUMTEXT (16MB max); enforce a practical ceiling
if (strlen($raw_json) > 10 * 1024 * 1024) {
    header('Location: /?error=too_large');
    exit;
}

// ── Generate token and submission hash ───────────────────────────────────────

$token           = sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
    mt_rand(0, 0xffff), mt_rand(0, 0xffff),
    mt_rand(0, 0xffff),
    mt_rand(0, 0x0fff) | 0x4000,
    mt_rand(0, 0x3fff) | 0x8000,
    mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
);
$submission_hash = hash('sha256', $raw_json);

// ── Persist to DB ─────────────────────────────────────────────────────────────

$con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if (mysqli_connect_errno()) {
    error_log('ip2geo get-report.php DB connect failed: ' . mysqli_connect_error());
    header('Location: /?error=db');
    exit;
}

// Check for a cached paid/redeemed report for the same IP list
$stmt = $con->prepare(
    'SELECT token, status FROM reports
     WHERE submission_hash = ? AND status IN ("paid","redeemed")
       AND (report_expires_at IS NULL OR report_expires_at > NOW())
     ORDER BY created_at DESC LIMIT 1'
);
$stmt->bind_param('s', $submission_hash);
$stmt->execute();
$cached = $stmt->get_result()->fetch_assoc();
$stmt->close();

if ($cached) {
    // Same IP list already paid — serve the cached report directly
    mysqli_close($con);
    header('Location: /report.php?token=' . urlencode($cached['token']));
    exit;
}

$stmt = $con->prepare(
    'INSERT INTO reports
       (token, submission_hash, ip_list_json, status, pending_expires_at, created_at)
     VALUES (?, ?, ?, "pending", DATE_ADD(NOW(), INTERVAL 1 HOUR), NOW())'
);
$stmt->bind_param('sss', $token, $submission_hash, $raw_json);
if (!$stmt->execute()) {
    error_log('ip2geo get-report.php INSERT failed: ' . $stmt->error);
    $stmt->close();
    mysqli_close($con);
    header('Location: /?error=db');
    exit;
}
$stmt->close();
mysqli_close($con);

// ── Create Stripe Checkout session ───────────────────────────────────────────

\Stripe\Stripe::setApiKey($stripe_secret_key);

$base_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
          . '://' . $_SERVER['HTTP_HOST'];

try {
    $session = \Stripe\Checkout\Session::create([
        'payment_method_types' => ['card'],
        'line_items'           => [[
            'price_data' => [
                'currency'     => 'usd',
                'unit_amount'  => 900,  // $9.00 in cents
                'product_data' => [
                    'name'        => 'ip2geo Threat Report + Block Script',
                    'description' => 'Rule-based threat summary, AbuseIPDB reputation data, and ready-to-run firewall block script for your IP list.',
                ],
            ],
            'quantity' => 1,
        ]],
        'mode'                 => 'payment',
        'client_reference_id'  => $token,
        'success_url'          => $base_url . '/report.php?token=' . urlencode($token) . '&session_id={CHECKOUT_SESSION_ID}',
        'cancel_url'           => $base_url . '/?cancelled=1',
    ]);
} catch (\Stripe\Exception\ApiErrorException $e) {
    error_log('ip2geo Stripe session create failed: ' . $e->getMessage());
    header('Location: /?error=payment');
    exit;
}

header('Location: ' . $session->url);
exit;
