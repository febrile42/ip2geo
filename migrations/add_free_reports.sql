-- Migration: Free Temporary Reports
-- Run on server BEFORE deploying PHP files.
-- All statements use IF NOT EXISTS / safe MODIFY so re-running is harmless.

-- geo_results_json was missing from the original migrate.sql.
-- It exists in production already; the IF NOT EXISTS guard makes this idempotent.
ALTER TABLE reports
  ADD COLUMN IF NOT EXISTS geo_results_json MEDIUMTEXT NULL
  COMMENT 'Geo lookup results JSON; written by get-report.php at token creation';

-- Extend status ENUM to include free tier.
-- On MariaDB 10.4+: adding a value at the end is metadata-only (no table rebuild).
-- On older versions: acquires a metadata lock — run during low-traffic window.
ALTER TABLE reports
  MODIFY COLUMN status ENUM('pending','paid','redeemed','free') NOT NULL DEFAULT 'pending';

-- Anonymous view counter: total page views per report URL.
-- Incremented in report.php on every free or paid page view.
-- No PII, no session tracking — just a hit counter to measure sharing.
ALTER TABLE reports
  ADD COLUMN IF NOT EXISTS view_count INT UNSIGNED NOT NULL DEFAULT 0
  COMMENT 'Total page views for this report URL (anonymous, no PII)';
