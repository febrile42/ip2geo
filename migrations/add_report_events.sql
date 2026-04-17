-- Phase 3: behavioral event log for free report funnel analysis
CREATE TABLE IF NOT EXISTS report_events (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    token       CHAR(36)        NOT NULL,
    event_type  ENUM('page_viewed','cta_visible','cta_clicked','checkout_started') NOT NULL,
    event_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    session_id  VARCHAR(64)     DEFAULT NULL,
    INDEX idx_token         (token),
    INDEX idx_event_at      (event_at),
    INDEX idx_token_type_at (token, event_type, event_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Phase 3: rate limit buckets for /api/report-event.php (1-minute windows per token)
CREATE TABLE IF NOT EXISTS report_event_rl (
    token        CHAR(36)  NOT NULL,
    window_start DATETIME  NOT NULL,
    count        SMALLINT  NOT NULL DEFAULT 1,
    PRIMARY KEY (token, window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Phase 4: acquisition attribution per submission
ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS acquisition_source VARCHAR(2000) DEFAULT NULL;
