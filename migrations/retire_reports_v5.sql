-- Threat Reports retirement (R17, v5.0.0).
--
-- ⚠️  DO NOT RUN THIS DURING THE v5-retire build. Run it manually, by hand,
--     after 5.0.0 is live on production — and take a backup first:
--       mysqldump -u youruser -p yourdb reports report_events report_event_rl \
--         abuseipdb_cache abuseipdb_daily_usage > pre-retire-reports-backup.sql
--
-- report.php now returns a static 410 for every token and never reads any of
-- these tables, so nothing in the running app depends on this migration.
-- Nothing here touches community_cidr_stats, community_ip_stats,
-- community_ip_first_seen, or community_weekly_stats (Open Question 4 —
-- the Community Block List is a separate, still-open decision).

-- ── Step 1: retire the demo token row (R17) ────────────────────────────────
-- Safe to run any time; the demo report UI (/?view_token=...) has no caller
-- left once report.php stops generating/serving reports.
DELETE FROM reports WHERE token = '00000000-0000-0000-0000-000000000000';

-- ── Step 2 (optional): drop the report + AbuseIPDB tables entirely ─────────
-- Only the demo row was left in `reports` as of the 2026-09-23 PR-2 dive (the
-- one real paid report was already deleted by scripts/cleanup-reports.php on
-- 2026-05-04). If step 1 above has been run and a fresh backup exists, these
-- drops remove the now-dead schema. Leave commented out until the owner
-- decides there's no reason to keep the historical rows around.
--
-- DROP TABLE IF EXISTS reports;
-- DROP TABLE IF EXISTS report_events;
-- DROP TABLE IF EXISTS report_event_rl;
-- DROP TABLE IF EXISTS abuseipdb_cache;
-- DROP TABLE IF EXISTS abuseipdb_daily_usage;
