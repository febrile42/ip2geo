<?php
/**
 * Cron: clean up stale report_events and report_event_rl rows.
 * Run weekly (or more frequently) via the existing cron infrastructure.
 */

require dirname(__DIR__) . '/config.php';

$con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if (mysqli_connect_errno()) {
    error_log('cleanup_report_events: DB connect failed: ' . mysqli_connect_error());
    exit(1);
}

// Behavioral events: keep 90 days (covers 7-day report window + late conversions)
$con->query('DELETE FROM report_events WHERE event_at < NOW() - INTERVAL 90 DAY');

// Rate limit windows: discard anything older than 2 minutes (windows are 1 minute)
$con->query('DELETE FROM report_event_rl WHERE window_start < NOW() - INTERVAL 2 MINUTE');

mysqli_close($con);
