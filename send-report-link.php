<!DOCTYPE HTML>
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
require __DIR__ . '/vendor/autoload.php';

$token = isset($_GET['token']) ? trim($_GET['token']) : '';

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
$expires_at    = $row['report_expires_at'] ?? date('Y-m-d H:i:s', strtotime('+30 days'));
$expires_fmt   = date('F j, Y', strtotime($expires_at));
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
?>
<html>
    <head>
        <!-- Umami (production only) -->
        <?php if ($_SERVER['HTTP_HOST'] === 'ip2geo.org'): ?>
        <script defer src="https://cloud.umami.is/script.js" data-website-id="656d7a15-6282-4079-af1e-b8ed857fba2e"></script>
        <?php endif; ?>
        <title>Resend Report Link — ip2geo.org</title>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
        <link rel="stylesheet" href="assets/css/main.css" />
        <link rel="icon" href="/favicon.ico" />
        <noscript><link rel="stylesheet" href="assets/css/noscript.css" /></noscript>
    </head>
    <body class="is-preload">

        <!-- Header -->
        <header id="header">
            <a href="/" class="title">ip2geo.org</a>
            <nav>
                <ul>
                    <li><a href="/">Home</a></li>
                </ul>
            </nav>
        </header>

        <!-- Wrapper -->
        <div id="wrapper">
            <section id="main" class="wrapper">
                <div class="inner">
                    <h1 class="major">Resend Report Link</h1>

                    <?php if ($error !== ''): ?>
                    <p style="color:#e06c75"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
                    <p><a href="/" class="button small">← Back to ip2geo</a></p>

                    <?php elseif ($success): ?>
                    <p>Report link sent to <strong><?php echo htmlspecialchars(mask_email($stored_email), ENT_QUOTES, 'UTF-8'); ?></strong>. Check your inbox.</p>
                    <p style="font-size:0.9em;opacity:0.7">The link expires on <?php echo htmlspecialchars($expires_fmt, ENT_QUOTES, 'UTF-8'); ?>. If it doesn't arrive within a few minutes, check your spam folder or contact <a href="mailto:support@ip2geo.org">support@ip2geo.org</a>.</p>
                    <p><a href="/report.php?token=<?php echo urlencode($token); ?>" class="button small">View your report</a></p>

                    <?php elseif (!$resend_enabled): ?>
                    <p>Email delivery is not configured. Contact <a href="mailto:support@ip2geo.org">support@ip2geo.org</a> with your report token and we will send you the link manually.</p>
                    <p style="font-size:0.9em;opacity:0.7;font-family:monospace"><?php echo htmlspecialchars($token, ENT_QUOTES, 'UTF-8'); ?></p>

                    <?php else: ?>
                    <?php if ($masked): ?>
                    <p>We have an address on file for this report. Enter the same address to resend the link.</p>
                    <p style="font-size:0.9em;opacity:0.7">On file: <strong><?php echo htmlspecialchars($masked, ENT_QUOTES, 'UTF-8'); ?></strong></p>
                    <?php else: ?>
                    <p>Enter your email address and we'll send you the link to your report. It expires on <strong><?php echo htmlspecialchars($expires_fmt, ENT_QUOTES, 'UTF-8'); ?></strong>.</p>
                    <?php endif; ?>

                    <form method="post" action="/send-report-link.php?token=<?php echo urlencode($token); ?>" style="max-width:420px">
                        <div class="fields">
                            <div class="field">
                                <label for="email">Email address</label>
                                <input type="email" name="email" id="email" placeholder="you@example.com" required
                                       value="<?php echo htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                            </div>
                        </div>
                        <ul class="actions" style="margin-top:1em">
                            <li><input type="submit" value="Send link" class="primary"></li>
                        </ul>
                    </form>
                    <?php endif; ?>
                </div>
            </section>
        </div>

    <?php require __DIR__ . '/includes/footer.php'; ?>

        <!-- Scripts -->
        <script src="assets/js/jquery.min.js"></script>
        <script src="assets/js/jquery.scrollex.min.js"></script>
        <script src="assets/js/jquery.scrolly.min.js"></script>
        <script src="assets/js/browser.min.js"></script>
        <script src="assets/js/breakpoints.min.js"></script>
        <script src="assets/js/util.js"></script>
        <script src="assets/js/main.js"></script>

    </body>
</html>
