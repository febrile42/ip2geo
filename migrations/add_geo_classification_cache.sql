-- Short-lived server-side cache of MaxMind classification results.
-- Written by index.php after each geo lookup; consumed by get-report.php to
-- avoid re-running all GeoIP queries on the same IP list within the same session.
-- 30-minute TTL — entries older than that are stale and will not be returned.
CREATE TABLE IF NOT EXISTS geo_classification_cache (
    cache_key    CHAR(64)     NOT NULL,
    ip_list_json MEDIUMTEXT   NOT NULL,
    geo_json     MEDIUMTEXT   NOT NULL,
    expires_at   DATETIME     NOT NULL,
    PRIMARY KEY  (cache_key),
    INDEX        idx_expires  (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
