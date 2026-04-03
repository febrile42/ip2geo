-- Add geo_results_json column to cache view_token page results
-- Run once on staging, then production before deploying the code change.
ALTER TABLE reports
    ADD COLUMN geo_results_json MEDIUMTEXT DEFAULT NULL
    AFTER ip_list_json;
