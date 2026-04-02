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
 * Attempt to send the report link email.
 *
 * @param mysqli  $con         Open DB connection (caller keeps ownership)
 * @param string  $token       Report token
 * @param string  $email       Recipient email address
 * @param string  $expires_at  Report expiry datetime string (Y-m-d H:i:s)
 * @param string  $api_key     Resend API key
 * @param string  $from        Resend from address e.g. "ip2geo <reports@ip2geo.org>"
 * @return bool   true if email was sent (or already sent by another path); false if skipped/failed
 */
function send_report_email(
    mysqli $con,
    string $token,
    string $email,
    string $expires_at,
    string $api_key,
    string $from
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
    $resend_url  = 'https://ip2geo.org/send-report-link.php?token=' . urlencode($token);
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
    Need to resend this email? <a href="{$resend_url}" style="color:#5e42a6">Request it here</a>.<br>
    Questions? <a href="mailto:support@ip2geo.org" style="color:#5e42a6">support@ip2geo.org</a>
  </p>
</body>
</html>
HTML;

    try {
        $resend = \Resend::client($api_key);
        $resend->emails->send([
            'from'    => $from,
            'to'      => [$email],
            'subject' => 'Your ip2geo Threat Report',
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
