#!/usr/bin/env php
<?php
/**
 * Clean up expired report rows.
 *
 * Run via cron on the server — reads DB credentials from config.php.
 *
 * Two passes:
 *   1. Pending rows whose payment window expired (never converted).
 *   2. Redeemed rows whose 30-day access window has elapsed.
 *
 * Usage: php /path/to/ip2geo/scripts/cleanup-reports.php
 */

$config_path = __DIR__ . '/../config.php';
if (!file_exists($config_path)) {
    fwrite(STDERR, "cleanup-reports: config.php not found at $config_path\n");
    exit(1);
}
require $config_path;

$dsn = "mysql:host={$db_host};dbname={$db_name};charset=utf8mb4";
try {
    $pdo = new PDO($dsn, $db_user, $db_pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
} catch (PDOException $e) {
    fwrite(STDERR, "cleanup-reports: DB connect failed: " . $e->getMessage() . "\n");
    exit(1);
}

$now = date('Y-m-d H:i:s');

// 1. Expired pending rows (payment window elapsed, will never convert)
$stmt = $pdo->prepare(
    "DELETE FROM reports WHERE status = 'pending' AND pending_expires_at < NOW() - INTERVAL 2 HOUR"
);
$stmt->execute();
$pending_deleted = $stmt->rowCount();

// 2. Expired paid reports (30-day access window elapsed)
$stmt = $pdo->prepare(
    "DELETE FROM reports WHERE status = 'redeemed'
     AND report_expires_at IS NOT NULL AND report_expires_at < NOW()"
);
$stmt->execute();
$redeemed_deleted = $stmt->rowCount();

if ($pending_deleted > 0 || $redeemed_deleted > 0) {
    echo "[$now] cleanup-reports: deleted $pending_deleted pending, $redeemed_deleted redeemed\n";
} else {
    echo "[$now] cleanup-reports: nothing to delete\n";
}
