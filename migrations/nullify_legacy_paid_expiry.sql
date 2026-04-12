-- Migration: Nullify legacy paid report expiry dates
-- Run on server BEFORE or alongside deploying the v3.2.0 PHP files.
--
-- Context: prior to v3.2.0, paid reports expired 30 days after redemption.
-- The updated privacy policy states paid reports are permalinked (no automatic expiry).
-- This migration makes all existing paid/redeemed rows consistent with that policy.
--
-- Safe to re-run: the WHERE clause excludes rows already NULL and free/pending rows.

UPDATE reports
SET report_expires_at = NULL
WHERE status IN ('paid', 'redeemed')
  AND report_expires_at IS NOT NULL;
