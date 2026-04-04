<?php
/**
 * Email delivery helper for ip2geo.
 *
 * send_report_email() uses an atomic DB guard (email_sent_at IS NULL) to
 * ensure exactly one delivery attempt regardless of whether report.php or
 * webhook.php wins the race after payment.
 *
 * On Resend failure: email_sent_at is reset to NULL so the next request retries.
 * This means a transient send failure does not permanently block delivery.
 */

/**
 * Build the subject line for a report delivery email.
 * Exported as a pure function so it can be unit-tested.
 */
function report_email_subject(int $ip_count): string {
    return $ip_count > 0
        ? "Threat Intelligence Report ({$ip_count} IPs) - ip2geo"
        : 'Threat Intelligence Report - ip2geo';
}

/**
 * Attempt to send the report link email.
 *
 * @param mysqli  $con         Open DB connection (caller keeps ownership)
 * @param string  $token       Report token
 * @param string  $email       Recipient email address
 * @param string  $expires_at  Report expiry datetime string (Y-m-d H:i:s)
 * @param string  $api_key     Resend API key
 * @param string  $from        Resend from address e.g. "ip2geo <reports@ip2geo.org>"
 * @param int     $ip_count    Number of IPs analyzed (0 = unknown, omits count from subject)
 * @return bool   true if email was sent (or already sent by another path); false if skipped/failed
 */
function send_report_email(
    mysqli $con,
    string $token,
    string $email,
    string $expires_at,
    string $api_key,
    string $from,
    int $ip_count = 0
): bool {
    if ($email === '' || $api_key === '') return false;

    // Store email address; first writer wins — existing address is preserved
    $stmt = $con->prepare(
        'UPDATE reports SET notification_email = ? WHERE token = ? AND notification_email IS NULL'
    );
    $stmt->bind_param('ss', $email, $token);
    $stmt->execute();
    $stmt->close();

    // Atomic send-slot claim: only one caller (report.php vs webhook.php) proceeds
    $stmt = $con->prepare(
        'UPDATE reports SET email_sent_at = NOW() WHERE token = ? AND email_sent_at IS NULL'
    );
    $stmt->bind_param('s', $token);
    $stmt->execute();
    $claimed = $stmt->affected_rows > 0;
    $stmt->close();

    if (!$claimed) {
        // Already sent by the other path
        return true;
    }

    $report_url  = 'https://ip2geo.org/report.php?token=' . urlencode($token);
    $expires_fmt = date('F j, Y', strtotime($expires_at));

    $html = <<<HTML
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:sans-serif;color:#333;max-width:600px;margin:0 auto;padding:2em 1em">
  <h2 style="margin-top:0;color:#111">Your Threat Report is ready</h2>
  <p>Your ip2geo Threat Report has been generated. Click below to view your results, block scripts, and ASN ranges.</p>
  <p style="margin:1.5em 0">
    <a href="{$report_url}"
       style="background:#5e42a6;color:#fff;padding:0.65em 1.4em;border-radius:4px;text-decoration:none;font-weight:bold;display:inline-block">
      View your report &rarr;
    </a>
  </p>
  <p style="font-size:0.9em;color:#555">
    Or copy this link:<br>
    <a href="{$report_url}" style="color:#5e42a6;word-break:break-all">{$report_url}</a>
  </p>
  <hr style="border:none;border-top:1px solid #eee;margin:1.5em 0">
  <p style="font-size:0.85em;color:#777">
    This report expires on <strong>{$expires_fmt}</strong>. After that date your data is deleted and the link will stop working.<br>
Questions? <a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;&#115;&#117;&#112;&#112;&#111;&#114;&#116;&#64;&#105;&#112;&#50;&#103;&#101;&#111;&#46;&#111;&#114;&#103;" style="color:#5e42a6">&#115;&#117;&#112;&#112;&#111;&#114;&#116;&#64;&#105;&#112;&#50;&#103;&#101;&#111;&#46;&#111;&#114;&#103;</a>
  </p>
</body>
</html>
HTML;

    try {
        $resend = \Resend::client($api_key);
        $resend->emails->send([
            'from'    => $from,
            'to'      => [$email],
            'subject' => report_email_subject($ip_count),
            'html'    => $html,
        ]);
        return true;
    } catch (\Throwable $e) {
        error_log('ip2geo email: Resend send failed for token ' . $token . ': ' . $e->getMessage());
        // Reset guard so the next request (e.g. page reload) retries
        $stmt = $con->prepare('UPDATE reports SET email_sent_at = NULL WHERE token = ?');
        $stmt->bind_param('s', $token);
        $stmt->execute();
        $stmt->close();
        return false;
    }
}

/**
 * Build an HTML body for a purchase-related failure alert.
 *
 * @param string $description  One-line error description shown at the top
 * @param array  $ctx          Optional keyed context:
 *                             token, session_id, payment_intent, email, error, note
 * @return string HTML-safe email body
 */
function build_payment_alert_html(string $description, array $ctx = []): string
{
    $rows = '';
    $fields = [
        'token'          => 'Token',
        'session_id'     => 'Stripe Session ID',
        'payment_intent' => 'Payment Intent',
        'email'          => 'Customer Email',
        'error'          => 'PHP Error',
        'note'           => 'Note',
    ];
    foreach ($fields as $key => $label) {
        $val = $ctx[$key] ?? '';
        if ($val === '') continue;
        $le = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');
        $ve = htmlspecialchars($val, ENT_QUOTES, 'UTF-8');
        $rows .= "<tr><td style=\"padding:4px 8px;font-weight:bold;white-space:nowrap;vertical-align:top\">{$le}</td>"
               . "<td style=\"padding:4px 8px;word-break:break-all\">{$ve}</td></tr>";
    }
    $time_e = htmlspecialchars(gmdate('Y-m-d H:i:s') . ' UTC', ENT_QUOTES, 'UTF-8');
    $rows .= "<tr><td style=\"padding:4px 8px;font-weight:bold;white-space:nowrap\">Time</td>"
           . "<td style=\"padding:4px 8px\">{$time_e}</td></tr>";

    $stripe_links = '';
    if (!empty($ctx['payment_intent'])) {
        $pi = htmlspecialchars($ctx['payment_intent'], ENT_QUOTES, 'UTF-8');
        $stripe_links .= "<li><a href=\"https://dashboard.stripe.com/payments/{$pi}\">Open payment in Stripe Dashboard</a></li>";
    }
    if (!empty($ctx['session_id'])) {
        $sid = htmlspecialchars($ctx['session_id'], ENT_QUOTES, 'UTF-8');
        $stripe_links .= "<li><a href=\"https://dashboard.stripe.com/checkout/sessions/{$sid}\">Open checkout session in Stripe Dashboard</a></li>";
    }
    if (!empty($ctx['email'])) {
        $eq = htmlspecialchars(urlencode($ctx['email']), ENT_QUOTES, 'UTF-8');
        $stripe_links .= "<li><a href=\"https://dashboard.stripe.com/search?query={$eq}\">Search Stripe by customer email</a></li>";
    }
    if ($stripe_links === '') {
        $stripe_links = '<li>No Stripe identifiers available — check server error log for context</li>';
    }

    $db_section = '<p>No token available.</p>';
    if (!empty($ctx['token'])) {
        $t = htmlspecialchars($ctx['token'], ENT_QUOTES, 'UTF-8');
        $db_section = "<pre style=\"background:#f5f5f5;padding:0.8em;border-radius:4px;overflow-x:auto\">"
                    . "SELECT token, status, stripe_payment_intent, notification_email, created_at\n"
                    . "FROM reports WHERE token = '{$t}';</pre>";
    }

    $de = htmlspecialchars($description, ENT_QUOTES, 'UTF-8');

    return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head>"
         . "<body style=\"font-family:sans-serif;color:#222;max-width:700px;margin:0 auto;padding:2em 1em\">"
         . "<h2 style=\"margin-top:0;color:#c00\">ip2geo Payment Alert</h2>"
         . "<p style=\"background:#fff3cd;border:1px solid #ffc107;padding:0.8em 1em;border-radius:4px\">{$de}</p>"
         . "<table style=\"border-collapse:collapse;width:100%;border:1px solid #ddd\"><tbody>{$rows}</tbody></table>"
         . "<h3>Find in Stripe</h3><ul>{$stripe_links}</ul>"
         . "<h3>DB Lookup</h3>{$db_section}"
         . "</body></html>";
}

/**
 * Send an alert email to info@ip2geo.org via Resend.
 * Silently logs on failure — never throws.
 *
 * @param string $subject  Short subject (will be prefixed with "[ip2geo alert] ")
 * @param string $body_html Pre-built HTML body (use build_payment_alert_html())
 * @param string $api_key  Resend API key
 * @param string $from     Resend from address
 */
function send_alert_email(
    string $subject,
    string $body_html,
    string $api_key,
    string $from
): void {
    if ($api_key === '' || $from === '') {
        error_log('ip2geo alert: cannot send alert (no Resend config). Subject: ' . $subject);
        return;
    }
    try {
        $resend = \Resend::client($api_key);
        $resend->emails->send([
            'from'    => $from,
            'to'      => ['info@ip2geo.org'],
            'subject' => '[ip2geo alert] ' . $subject,
            'html'    => $body_html,
        ]);
    } catch (\Throwable $e) {
        error_log('ip2geo alert email failed: ' . $e->getMessage());
    }
}

/**
 * Return a privacy-masked version of an email address.
 * foo@example.com -> f**@example.com
 */
function mask_email(string $email): string {
    $parts = explode('@', $email, 2);
    if (count($parts) !== 2) return '***';
    $local = $parts[0];
    $masked_local = strlen($local) > 1
        ? substr($local, 0, 1) . str_repeat('*', min(strlen($local) - 1, 3))
        : '*';
    return $masked_local . '@' . $parts[1];
}
