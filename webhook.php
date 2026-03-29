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

$session = $event->data->object;
$token   = $session->client_reference_id ?? '';
$intent  = $session->payment_intent      ?? '';

if ($token === '') {
    error_log('ip2geo webhook: checkout.session.completed with no client_reference_id');
    exit;
}

$con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if (mysqli_connect_errno()) {
    error_log('ip2geo webhook DB connect failed: ' . mysqli_connect_error());
    exit;
}

// Idempotent: if already paid or redeemed, no-op
$stmt = $con->prepare(
    'UPDATE reports
     SET status = "paid", stripe_payment_intent = ?
     WHERE token = ? AND status = "pending" AND pending_expires_at > NOW()'
);
$stmt->bind_param('ss', $intent, $token);
$stmt->execute();
if ($stmt->affected_rows > 0) {
    error_log('ip2geo webhook: token ' . $token . ' marked paid via webhook');
}
$stmt->close();
mysqli_close($con);
exit;
