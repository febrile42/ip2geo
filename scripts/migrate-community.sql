-- ip2geo Phase C DB migration — Community Threat Intelligence
-- Run once on the server before deploying Phase C PHP files.
-- Safe to re-run: all statements use IF NOT EXISTS / IF EXISTS guards.
-- Zero downtime: only creates new tables and adds a nullable column.
-- Rollback: DROP TABLE community_cidr_stats, community_ip_stats,
--           community_ip_first_seen;
--           ALTER TABLE reports DROP COLUMN data_consent;

-- ── Weekly CIDR aggregate (public feed) ──────────────────────────────────────
-- One row per CIDR range per ISO week. Powers /intel.php block list.
-- Sources: report_json['asn_ranges'][].cidrs[] for all opted-in reports.
-- Retention: 52 weeks. Monthly cron DELETEs rows older than 52 weeks.
CREATE TABLE IF NOT EXISTS community_cidr_stats (
    cidr          VARCHAR(50)       NOT NULL,   -- e.g. '185.220.101.0/24'
    asn           VARCHAR(12)       NOT NULL,   -- e.g. 'AS16276'
    org           VARCHAR(255)      NOT NULL,   -- e.g. 'OVH SAS'
    week_start    DATE              NOT NULL,   -- Monday of ISO 8601 week, UTC
    report_count  SMALLINT UNSIGNED NOT NULL DEFAULT 0,  -- opted-in reports containing this CIDR
    total_hits    INT UNSIGNED      NOT NULL DEFAULT 0,  -- sum of hit counts across reports
    PRIMARY KEY (cidr, week_start),
    KEY idx_week_hits (week_start, total_hits)  -- for top-N queries on /intel.php
) ENGINE=InnoDB;

-- ── Weekly IP aggregate (paid report community column) ───────────────────────
-- One row per scanning/VPN/cloud IP per ISO week. Powers the Community column
-- in the top-25 table on paid reports (visible only to opted-in report owners).
-- Sources: ip_list_json where classification IN ('scanning','vpn_proxy','cloud_exit').
-- Residential IPs: NEVER stored here. No exceptions.
-- Retention: 52 weeks. Monthly cron DELETEs rows older than 52 weeks.
CREATE TABLE IF NOT EXISTS community_ip_stats (
    ip            VARCHAR(45)       NOT NULL,
    week_start    DATE              NOT NULL,   -- Monday of ISO 8601 week, UTC
    report_count  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    total_hits    INT UNSIGNED      NOT NULL DEFAULT 0,
    PRIMARY KEY (ip, week_start),
    KEY idx_ip (ip),                            -- for cross-week first_seen join
    KEY idx_week_hits (week_start, total_hits)
) ENGINE=InnoDB;

-- ── Global IP first-seen index ───────────────────────────────────────────────
-- One row per IP, ever. Tracks when an IP first appeared in community data
-- across all weeks. Never pruned — permanent index.
-- Separate from community_ip_stats because first_seen is cross-week;
-- storing it on the weekly row would make it redundant with week_start.
CREATE TABLE IF NOT EXISTS community_ip_first_seen (
    ip          VARCHAR(45)  NOT NULL,
    first_seen  DATE         NOT NULL,
    PRIMARY KEY (ip)
) ENGINE=InnoDB;

-- ── Consent flag on reports ──────────────────────────────────────────────────
-- NULL  = not yet asked (banner will be shown on report page)
-- 1     = opted in (data ingested into aggregate tables)
-- 0     = declined (banner dismissed, never shown again for this token)
-- IMPORTANT: do not log token-to-IP associations anywhere, including
-- application logs. Doing so breaks the anonymization guarantee.
ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS data_consent TINYINT(1) NULL DEFAULT NULL
    COMMENT '1=opted in, 0=declined, NULL=not yet asked';
