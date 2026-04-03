<?php
/**
 * Stripe webhook handler.
 *
 * Handles checkout.session.completed events to mark tokens as paid.
 * This is the fallback path when the Stripe redirect is faster than
 * the user's browser (race condition). The report.php handler is the
 * primary path; this marks pending→paid so report.php can proceed.
 *
 * CRITICAL: raw body must be read BEFORE any json_decode or output buffering.
 * \Stripe\Webhook::constructEvent() verifies the Stripe-Signature HMAC
 * over the raw request body. Any modification invalidates the signature.
 */

require __DIR__ . '/config.php';
require __DIR__ . '/email_helper.php';
require __DIR__ . '/vendor/autoload.php';

$raw_body = file_get_contents('php://input');
$sig      = $_SERVER['HTTP_STRIPE_SIGNATURE'] ?? '';

try {
    $event = \Stripe\Webhook::constructEvent($raw_body, $sig, $stripe_webhook_secret);
} catch (\Stripe\Exception\SignatureVerificationException $e) {
    error_log('ip2geo webhook: invalid signature — ' . $e->getMessage());
    http_response_code(400);
    echo json_encode(['error' => 'Invalid signature']);
    exit;
} catch (\UnexpectedValueException $e) {
    error_log('ip2geo webhook: invalid payload — ' . $e->getMessage());
    http_response_code(400);
    echo json_encode(['error' => 'Invalid payload']);
    exit;
}

// Acknowledge all events immediately to prevent Stripe retries on slow processing
http_response_code(200);
echo json_encode(['received' => true]);

// Only act on checkout completion
if ($event->type !== 'checkout.session.completed') {
    exit;
}

$session            = $event->data->object;
$token              = $session->client_reference_id ?? '';
$intent             = $session->payment_intent      ?? '';
$notification_email = trim($session->customer_details->email ?? '');

if ($token === '') {
    error_log('ip2geo webhook: checkout.session.completed with no client_reference_id');
    send_alert_email(
        'Payment received with no token — untrackable purchase',
        build_payment_alert_html('checkout.session.completed arrived with no client_reference_id. Payment was received but cannot be matched to a report token.', [
            'payment_intent' => $intent,
            'session_id'     => $session->id ?? '',
            'email'          => $notification_email,
            'note'           => 'No token available. Find the payment in Stripe by payment intent or customer email above.',
        ]),
        $resend_api_key ?? '', $resend_from ?? ''
    );
    exit;
}

$con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if (mysqli_connect_errno()) {
    error_log('ip2geo webhook DB connect failed: ' . mysqli_connect_error());
    send_alert_email(
        'Webhook DB failure — payment confirmed but token not marked paid',
        build_payment_alert_html('DB connect failed in webhook.php. Stripe confirmed payment but the token cannot be marked paid. Report will likely fail when the customer lands on the success URL.', [
            'token'          => $token,
            'payment_intent' => $intent,
            'session_id'     => $session->id ?? '',
            'email'          => $notification_email,
            'error'          => mysqli_connect_error(),
            'note'           => 'Token is in pending state. If DB recovers, the customer may succeed via success_url. If not, manual refund may be needed.',
        ]),
        $resend_api_key ?? '', $resend_from ?? ''
    );
    exit;
}

// Idempotent: if already paid or redeemed, no-op
$stmt = $con->prepare(
    'UPDATE reports
     SET status = "paid", stripe_payment_intent = ?,
         notification_email = COALESCE(notification_email, NULLIF(?, ""))
     WHERE token = ? AND status = "pending" AND pending_expires_at > NOW()'
);
$stmt->bind_param('sss', $intent, $notification_email, $token);
$stmt->execute();
if ($stmt->affected_rows > 0) {
    error_log('ip2geo webhook: token ' . $token . ' marked paid via webhook');
}
$stmt->close();

// Fallback email: send if report.php hasn't already done so.
// report_expires_at is not set yet (report not generated); use 30 days from now as estimate.
if ($notification_email !== '' && !empty($resend_api_key) && !empty($resend_from)) {
    $approx_expires = date('Y-m-d H:i:s', strtotime('+30 days'));
    $ip_count = 0;
    $cnt_stmt = $con->prepare('SELECT JSON_LENGTH(ip_list_json) AS ip_count FROM reports WHERE token = ?');
    $cnt_stmt->bind_param('s', $token);
    $cnt_stmt->execute();
    $cnt_row = $cnt_stmt->get_result()->fetch_assoc();
    $cnt_stmt->close();
    $ip_count = (int)($cnt_row['ip_count'] ?? 0);
    send_report_email($con, $token, $notification_email, $approx_expires, $resend_api_key, $resend_from, $ip_count);
}

mysqli_close($con);
exit;
