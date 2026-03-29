<?php
// Copy this file to config.php and fill in your credentials
$db_host = 'localhost';
$db_user = 'your_db_user';
$db_pass = 'your_db_password';
$db_name = 'your_db_name';

// Stripe — https://dashboard.stripe.com/apikeys
// Use a restricted key scoped to: Checkout Sessions → Write (nothing else needed).
// For QA/staging, use a Stripe Sandbox (Dashboard → account menu → Sandboxes) —
// each sandbox has isolated keys and can deliver webhooks directly to your URL
// without the Stripe CLI.
// Use test keys (sk_test_...) in sandbox/test; live keys (sk_live_...) in production only.
$stripe_secret_key    = 'sk_test_your_stripe_secret_key';
$stripe_webhook_secret = 'whsec_your_stripe_webhook_secret';
// Webhook secret: Dashboard → Developers → Webhooks → your endpoint → Signing secret
// Register endpoint: https://yourdomain.com/webhook.php
// Event to listen for: checkout.session.completed

// AbuseIPDB — get from https://www.abuseipdb.com/account/api
// Free tier: 1,000 checks/day. Leave empty to disable enrichment.
$abuseipdb_api_key = 'your_abuseipdb_api_key';
