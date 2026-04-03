-- ip2geo Phase A DB migration
-- Run once on the server before deploying Phase A PHP files.
-- Safe to re-run: all statements use IF NOT EXISTS / IF EXISTS guards.
-- Zero downtime: only creates new tables, no ALTER on existing tables.
-- Rollback: DROP TABLE reports, abuseipdb_cache, abuseipdb_daily_usage; revert PHP files.

-- ── ASN table (created by update-geoip.sh on first run, but ensure it exists) ──
CREATE TABLE IF NOT EXISTS geoip2_asn_current_int (
    network_start_integer BIGINT UNSIGNED NOT NULL,
    network_end_integer   BIGINT UNSIGNED NOT NULL,
    autonomous_system_number INT UNSIGNED,
    autonomous_system_org    VARCHAR(255),
    KEY idx_start (network_start_integer)
) ENGINE=InnoDB;

-- ── Paid reports ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reports (
    token                 VARCHAR(36)    NOT NULL,
    submission_hash       VARCHAR(64)    NOT NULL,
    ip_list_json          MEDIUMTEXT     NOT NULL,   -- classified IPs stored at token creation
                                                     -- [{ip,asn,classification,country,freq},...]
                                                     -- enables report generation after payment
                                                     -- without relying on POST data or sessions
    status                ENUM('pending','paid','redeemed') NOT NULL DEFAULT 'pending',
    pending_expires_at    DATETIME       NOT NULL,   -- 1 hour from token creation
    report_expires_at     DATETIME       NULL,       -- 30 days from redemption; NULL until redeemed
    report_json           MEDIUMTEXT     NULL,       -- final report, built at report.php time
    notification_email    VARCHAR(255)   NULL,       -- Phase B: notify when AI reports launch
    stripe_payment_intent VARCHAR(64)    NULL,
    created_at            DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (token),
    KEY idx_hash   (submission_hash),
    KEY idx_status (status),
    KEY idx_intent (stripe_payment_intent)
) ENGINE=InnoDB;

-- ── AbuseIPDB cache ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS abuseipdb_cache (
    ip               VARCHAR(45)  NOT NULL,
    confidence_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
    total_reports    INT UNSIGNED     NOT NULL DEFAULT 0,
    queried_at       DATETIME         NOT NULL,
    PRIMARY KEY (ip)
) ENGINE=InnoDB;

-- ── AbuseIPDB daily quota tracker ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS abuseipdb_daily_usage (
    usage_date   DATE             NOT NULL,
    calls_made   SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (usage_date)
) ENGINE=InnoDB;
