<?php
/**
 * Resend the report link email to the address stored at checkout.
 *
 * Restricted to the address already on file (stored from Stripe customer_details).
 * If no address is stored yet, accepts a new one and locks it in.
 * Prevents spam relay: only one address can ever be associated with a token.
 */

require __DIR__ . '/config.php';
require __DIR__ . '/email_helper.php';
require __DIR__ . '/includes/page-chrome.php';
require __DIR__ . '/vendor/autoload.php';

$token = isset($_GET['token']) ? trim($_GET['token']) : '';

// Demo report is publicly linked — no email delivery for it; redirect to the report directly.
if ($token === '00000000-0000-0000-0000-000000000000') {
    header('Location: /report.php?token=' . urlencode($token));
    exit;
}

$error   = '';
$success = false;

$con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if (mysqli_connect_errno()) {
    $error = 'Database unavailable. Please try again shortly.';
    $row   = null;
} else {
    $stmt = $con->prepare(
        'SELECT token, status, report_expires_at, notification_email, email_sent_at,
                JSON_LENGTH(ip_list_json) AS ip_count
         FROM reports WHERE token = ?'
    );
    $stmt->bind_param('s', $token);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
}

if (!$row && $error === '') {
    $error = 'This report link is invalid or has expired.';
}

if ($row && !in_array($row['status'], ['paid', 'redeemed'], true)) {
    $error = 'This report has not been paid for yet.';
}

if ($row && $row['report_expires_at'] && strtotime($row['report_expires_at']) < time()) {
    $error = 'This report has expired (30-day access window). Your data is no longer stored.';
}

$stored_email  = $row['notification_email'] ?? null;
$expires_at    = $row ? $row['report_expires_at'] : null;
$expires_fmt   = $expires_at !== null ? date('F j, Y', strtotime($expires_at)) : null;
$resend_enabled = !empty($resend_api_key) && !empty($resend_from);

// ── POST handler ──────────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $error === '' && $resend_enabled) {
    $submitted_email = strtolower(trim($_POST['email'] ?? ''));

    if ($submitted_email === '') {
        $error = 'Please enter an email address.';
    } elseif (!filter_var($submitted_email, FILTER_VALIDATE_EMAIL)) {
        $error = 'That does not look like a valid email address.';
    } elseif ($stored_email !== null && strtolower($stored_email) !== $submitted_email) {
        $error = 'That address does not match the one provided at checkout. Contact support@ip2geo.org if you need help.';
    } else {
        // Resend path: clear the atomic send-slot guard so send_report_email can
        // claim it again. The guard exists to prevent report.php/webhook.php from
        // double-sending on first delivery; here the user is explicitly requesting
        // a resend, so the guard must be cleared first.
        $reset = $con->prepare('UPDATE reports SET email_sent_at = NULL WHERE token = ?');
        $reset->bind_param('s', $token);
        $reset->execute();
        $reset->close();

        $sent = send_report_email($con, $token, $submitted_email, $expires_at, $resend_api_key, $resend_from, (int)($row['ip_count'] ?? 0));
        if ($sent) {
            $success = true;
            $stored_email = $submitted_email;
        } else {
            $error = 'Email delivery failed. Please try again in a moment or contact support@ip2geo.org.';
        }
    }
}

if ($con) mysqli_close($con);

$masked = $stored_email ? mask_email($stored_email) : null;

render_page_open('Resend Report Link — ip2geo.org', 'Resend a paid Threat Report link to the email on file.', [], [
    ['label' => 'New Lookup', 'href' => '/'],
]);
?>
<section class="report-section">
    <div class="report-inner">
        <div class="section-head">
            <h1>Resend Report Link</h1>
            <span class="section-tag">/ Email</span>
        </div>

        <?php if ($error !== ''): ?>
            <p class="form-error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
            <p><a href="/" class="button small">&larr; Back to ip2geo</a></p>

        <?php elseif ($success): ?>
            <p>Report link sent to <strong><?php echo htmlspecialchars(mask_email($stored_email), ENT_QUOTES, 'UTF-8'); ?></strong>. Check your inbox.</p>
            <p class="report-fine-print"><?php echo $expires_fmt !== null ? 'The link expires on ' . htmlspecialchars($expires_fmt, ENT_QUOTES, 'UTF-8') . '.' : 'This report does not expire.'; ?> If it doesn't arrive within a few minutes, check your spam folder or contact <a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;&#115;&#117;&#112;&#112;&#111;&#114;&#116;&#64;&#105;&#112;&#50;&#103;&#101;&#111;&#46;&#111;&#114;&#103;">&#115;&#117;&#112;&#112;&#111;&#114;&#116;&#64;&#105;&#112;&#50;&#103;&#101;&#111;&#46;&#111;&#114;&#103;</a>.</p>
            <p><a href="/report.php?token=<?php echo urlencode($token); ?>" class="button small">View your report</a></p>

        <?php elseif (!$resend_enabled): ?>
            <p>Email delivery is not configured. Contact <a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;&#115;&#117;&#112;&#112;&#111;&#114;&#116;&#64;&#105;&#112;&#50;&#103;&#101;&#111;&#46;&#111;&#114;&#103;">&#115;&#117;&#112;&#112;&#111;&#114;&#64;&#105;&#112;&#50;&#103;&#101;&#111;&#46;&#111;&#114;&#103;</a> with your report token and we will send you the link manually.</p>
            <p class="token-display"><?php echo htmlspecialchars($token, ENT_QUOTES, 'UTF-8'); ?></p>

        <?php else: ?>
            <?php if ($masked): ?>
                <p>We have an address on file for this report. Enter the same address to resend the link.</p>
                <p class="report-fine-print">On file: <strong><?php echo htmlspecialchars($masked, ENT_QUOTES, 'UTF-8'); ?></strong></p>
            <?php else: ?>
                <p>Enter your email address and we'll send you the link to your report<?php echo $expires_fmt !== null ? '. It expires on <strong>' . htmlspecialchars($expires_fmt, ENT_QUOTES, 'UTF-8') . '</strong>' : ''; ?>.</p>
            <?php endif; ?>

            <form class="resend-form" method="post" action="/send-report-link.php?token=<?php echo urlencode($token); ?>">
                <div class="field">
                    <label for="email">Email address</label>
                    <input type="email" name="email" id="email" placeholder="you@example.com" required
                           value="<?php echo htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                </div>
                <div class="form-actions">
                    <button type="submit" class="button">Send link</button>
                </div>
            </form>
        <?php endif; ?>
    </div>
</section>
<?php render_page_close(); ?>
