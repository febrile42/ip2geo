#!/usr/bin/env php
<?php
/**
 * Clean up expired report rows.
 *
 * Run via cron on the server — reads DB credentials from config.php.
 *
 * Three passes:
 *   1. Pending rows whose payment window expired (never converted).
 *   2. Redeemed rows whose report_expires_at has elapsed.
 *      (Vestigial: paid reports are permalinked since v3.2.0, so this never
 *       matches in practice — kept for any pre-3.2.0 row that escaped the
 *       nullify_legacy_paid_expiry migration.)
 *   3. Free rows 7 days after their report_expires_at (14 days total TTL).
 *
 * Before deleting free rows, materializes their analytics fields into
 * {$admin_db_name}.report_meta when configured, so admin dashboards survive
 * deletion. Skipped silently when $admin_db_name is empty (staging / dev).
 *
 * Usage: php /path/to/ip2geo/scripts/cleanup-reports.php
 */

$config_path = __DIR__ . '/../config.php';
if (!file_exists($config_path)) {
    fwrite(STDERR, "cleanup-reports: config.php not found at $config_path\n");
    exit(1);
}
require $config_path;

$admin_db_name = $admin_db_name ?? '';

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

// 2. Expired paid reports (legacy 30-day window; no-op since v3.2.0)
$stmt = $pdo->prepare(
    "DELETE FROM reports WHERE status = 'redeemed'
     AND report_expires_at IS NOT NULL AND report_expires_at < NOW()"
);
$stmt->execute();
$redeemed_deleted = $stmt->rowCount();

// 3. Free rows past their 7-day grace window. Before deletion, materialize
//    analytics into the admin cache (when configured) so dashboards survive.
$free_materialized = 0;
$free_deletable_filter = "status = 'free' AND report_expires_at < NOW() - INTERVAL 7 DAY";

if ($admin_db_name !== '') {
    $rows = $pdo->query(
        "SELECT token, status, submission_hash, created_at, ip_list_json,
                report_json, acquisition_source, notification_email
         FROM reports WHERE $free_deletable_filter"
    )->fetchAll(PDO::FETCH_ASSOC);

    if ($rows) {
        // Look up free→paid conversion at materialization time so we can record
        // the timestamp without persisting submission_hash.
        $conversion_lookup = $pdo->prepare(
            "SELECT MIN(created_at) AS converted_at FROM reports
             WHERE submission_hash = :submission_hash
               AND status IN ('paid','redeemed')"
        );

        $upsert = $pdo->prepare(
            "INSERT INTO `{$admin_db_name}`.`report_meta`
                (token, top_country, unique_countries, computed_at,
                 status, created_at, ip_count, verdict,
                 acquisition_domain, has_email, converted_to_paid_at)
             VALUES (:token, NULL, 0, NOW(),
                 :status, :created_at, :ip_count, :verdict,
                 :acquisition_domain, :has_email, :converted_to_paid_at)
             ON DUPLICATE KEY UPDATE
                 status = VALUES(status),
                 created_at = VALUES(created_at),
                 ip_count = VALUES(ip_count),
                 verdict = VALUES(verdict),
                 acquisition_domain = VALUES(acquisition_domain),
                 has_email = VALUES(has_email),
                 converted_to_paid_at = VALUES(converted_to_paid_at),
                 computed_at = NOW()"
        );

        foreach ($rows as $r) {
            $ip_list   = json_decode($r['ip_list_json'] ?? '[]', true) ?? [];
            $report    = json_decode($r['report_json']  ?? '{}', true) ?? [];
            $verdict   = isset($report['verdict']) ? (string)$report['verdict'] : null;

            $domain = null;
            if (!empty($r['acquisition_source'])) {
                $parsed = parse_url(trim($r['acquisition_source']));
                if (!empty($parsed['host'])) {
                    $domain = preg_replace('/^www\./', '', $parsed['host']);
                }
            }

            $conversion_lookup->execute([':submission_hash' => $r['submission_hash']]);
            $converted_at = $conversion_lookup->fetchColumn() ?: null;

            $upsert->execute([
                ':token'                => $r['token'],
                ':status'               => $r['status'],
                ':created_at'           => $r['created_at'],
                ':ip_count'             => count($ip_list),
                ':verdict'              => $verdict,
                ':acquisition_domain'   => $domain,
                ':has_email'            => !empty($r['notification_email']) ? 1 : 0,
                ':converted_to_paid_at' => $converted_at,
            ]);
            $free_materialized++;
        }
    }
}

$stmt = $pdo->prepare("DELETE FROM reports WHERE $free_deletable_filter");
$stmt->execute();
$free_deleted = $stmt->rowCount();

if ($pending_deleted > 0 || $redeemed_deleted > 0 || $free_deleted > 0 || $free_materialized > 0) {
    echo "[$now] cleanup-reports: deleted $pending_deleted pending, "
       . "$redeemed_deleted redeemed, $free_deleted free "
       . "(materialized $free_materialized to admin)\n";
} else {
    echo "[$now] cleanup-reports: nothing to delete\n";
}
