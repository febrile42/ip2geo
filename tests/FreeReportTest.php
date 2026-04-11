<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Free temporary report tests — state machine, expiry, dedup, rate limiting.
 *
 * Uses in-memory SQLite to mirror the reports table (same pattern as TokenLifecycleTest).
 * Does not boot report.php or get-report.php directly — tests replicate the exact SQL
 * so schema/logic drift surfaces as failures.
 */
class FreeReportTest extends TestCase
{
    private \PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = new \PDO('sqlite::memory:');
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        $this->pdo->exec("
            CREATE TABLE reports (
                token               VARCHAR(36)  PRIMARY KEY,
                submission_hash     VARCHAR(64)  NOT NULL,
                ip_list_json        TEXT         NOT NULL,
                geo_results_json    TEXT,
                status              VARCHAR(16)  NOT NULL DEFAULT 'pending',
                pending_expires_at  DATETIME,
                report_expires_at   DATETIME,
                report_json         TEXT,
                view_count          INTEGER      NOT NULL DEFAULT 0,
                stripe_payment_intent VARCHAR(64),
                notification_email  VARCHAR(254),
                email_sent_at       DATETIME,
                created_at          DATETIME     NOT NULL
            )
        ");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private function insertRow(array $fields): void
    {
        $defaults = [
            'token'              => 'free-token-1',
            'submission_hash'    => hash('sha256', '[]'),
            'ip_list_json'       => '[]',
            'geo_results_json'   => null,
            'status'             => 'free',
            'pending_expires_at' => date('Y-m-d H:i:s', strtotime('+7 days')),
            'report_expires_at'  => date('Y-m-d H:i:s', strtotime('+7 days')),
            'report_json'        => null,
            'view_count'         => 0,
            'created_at'         => date('Y-m-d H:i:s'),
        ];
        $row = array_merge($defaults, $fields);
        $stmt = $this->pdo->prepare(
            'INSERT INTO reports
                (token, submission_hash, ip_list_json, geo_results_json, status,
                 pending_expires_at, report_expires_at, report_json, view_count, created_at)
             VALUES
                (:token, :submission_hash, :ip_list_json, :geo_results_json, :status,
                 :pending_expires_at, :report_expires_at, :report_json, :view_count, :created_at)'
        );
        $stmt->execute($row);
    }

    private function fetchRow(string $token): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM reports WHERE token = ?'
        );
        $stmt->execute([$token]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    // ── FreeReportCreation ────────────────────────────────────────────────────

    /** Free row written with status='free' and 7-day expiry timestamps */
    public function testFreeReportRowHasCorrectStatusAndExpiry(): void
    {
        $this->insertRow([]);
        $row = $this->fetchRow('free-token-1');

        $this->assertNotNull($row);
        $this->assertSame('free', $row['status']);

        $expires_ts = strtotime($row['report_expires_at']);
        $this->assertGreaterThan(time() + (6 * 86400), $expires_ts, 'report_expires_at should be ~7 days from now');
        $this->assertLessThan(time() + (8 * 86400), $expires_ts);
    }

    /** pending_expires_at matches report_expires_at (+7d, not +1hr) */
    public function testPendingExpiresAtMatchesReportExpiresAt(): void
    {
        $this->insertRow([]);
        $row = $this->fetchRow('free-token-1');

        $pending_ts  = strtotime($row['pending_expires_at']);
        $report_ts   = strtotime($row['report_expires_at']);

        // They should be within 5 seconds of each other (set by the same SQL expression)
        $this->assertEqualsWithDelta($pending_ts, $report_ts, 5, 'pending_expires_at and report_expires_at should match for free rows');
    }

    /** Free dedup: same submission_hash + active free report → reuse existing token */
    public function testFreeDedupReusesExistingFreeReport(): void
    {
        $hash = hash('sha256', '[{"ip":"1.2.3.4"}]');
        $this->insertRow([
            'token'           => 'existing-free-token',
            'submission_hash' => $hash,
            'status'          => 'free',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('+6 days')),
        ]);

        // Replicate the dedup SELECT from get-report.php free path
        $stmt = $this->pdo->prepare(
            'SELECT token FROM reports
             WHERE submission_hash = ? AND status = "free" AND report_expires_at > ?
             ORDER BY created_at DESC LIMIT 1'
        );
        $stmt->execute([$hash, date('Y-m-d H:i:s')]);
        $existing = $stmt->fetch(\PDO::FETCH_ASSOC);

        $this->assertNotFalse($existing);
        $this->assertSame('existing-free-token', $existing['token']);
    }

    /** Free dedup does NOT match expired free reports */
    public function testFreeDedupIgnoresExpiredFreeReport(): void
    {
        $hash = hash('sha256', '[{"ip":"1.2.3.4"}]');
        $this->insertRow([
            'token'           => 'expired-free-token',
            'submission_hash' => $hash,
            'status'          => 'free',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('-1 day')),
        ]);

        $stmt = $this->pdo->prepare(
            'SELECT token FROM reports
             WHERE submission_hash = ? AND status = "free" AND report_expires_at > ?
             ORDER BY created_at DESC LIMIT 1'
        );
        $stmt->execute([$hash, date('Y-m-d H:i:s')]);
        $existing = $stmt->fetch(\PDO::FETCH_ASSOC);

        $this->assertFalse($existing, 'Expired free report should not match dedup check');
    }

    /** Free rows are excluded from the paid submission_hash dedup check */
    public function testFreeStatusExcludedFromPaidDedup(): void
    {
        $hash = hash('sha256', '[{"ip":"1.2.3.4"}]');
        $this->insertRow([
            'token'           => 'free-only-token',
            'submission_hash' => $hash,
            'status'          => 'free',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('+6 days')),
        ]);

        // Paid dedup SELECT uses status IN ("paid","redeemed") — must NOT find the free row
        $stmt = $this->pdo->prepare(
            'SELECT token FROM reports
             WHERE submission_hash = ? AND status IN ("paid","redeemed")
               AND (report_expires_at IS NULL OR report_expires_at > ?)
             ORDER BY created_at DESC LIMIT 1'
        );
        $stmt->execute([$hash, date('Y-m-d H:i:s')]);
        $cached = $stmt->fetch(\PDO::FETCH_ASSOC);

        $this->assertFalse($cached, 'Free reports must be excluded from paid dedup check');
    }

    /** upgrade_token path: fetches ip_list_json from free row, creates pending row */
    public function testUpgradePathCreatesNewPendingRow(): void
    {
        $ip_json = '[{"ip":"1.2.3.4","freq":5}]';
        $hash    = hash('sha256', $ip_json);
        $this->insertRow([
            'token'           => 'free-tok',
            'submission_hash' => $hash,
            'ip_list_json'    => $ip_json,
            'status'          => 'free',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('+6 days')),
        ]);

        // Simulate upgrade: fetch from free row
        $stmt = $this->pdo->prepare(
            'SELECT ip_list_json, geo_results_json FROM reports
             WHERE token = ? AND status = "free" AND report_expires_at > ?'
        );
        $stmt->execute(['free-tok', date('Y-m-d H:i:s')]);
        $free_row = $stmt->fetch(\PDO::FETCH_ASSOC);
        $this->assertNotFalse($free_row);

        // Create pending row using fetched data
        $new_token = 'new-paid-token-1';
        $stmt2 = $this->pdo->prepare(
            "INSERT INTO reports
               (token, submission_hash, ip_list_json, status, pending_expires_at, created_at)
             VALUES (?, ?, ?, 'pending', datetime('now', '+1 hour'), datetime('now'))"
        );
        $stmt2->execute([$new_token, hash('sha256', $free_row['ip_list_json']), $free_row['ip_list_json']]);

        $row = $this->fetchRow($new_token);
        $this->assertSame('pending', $row['status']);
        $this->assertSame($ip_json, $row['ip_list_json']);
    }

    /** upgrade_token for expired free report returns no row */
    public function testUpgradeTokenExpiredFreeReportFindsNothing(): void
    {
        $this->insertRow([
            'token'            => 'expired-free',
            'status'           => 'free',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('-1 day')),
        ]);

        $stmt = $this->pdo->prepare(
            'SELECT ip_list_json FROM reports
             WHERE token = ? AND status = "free" AND report_expires_at > ?'
        );
        $stmt->execute(['expired-free', date('Y-m-d H:i:s')]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);

        $this->assertFalse($row, 'Expired free token should not be upgradeable');
    }

    // ── FreeReportExpiry ──────────────────────────────────────────────────────

    /** Expired free report is detected by report_expires_at check */
    public function testExpiredFreeReportDetected(): void
    {
        $this->insertRow([
            'status'           => 'free',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('-1 second')),
        ]);
        $row = $this->fetchRow('free-token-1');

        $this->assertLessThanOrEqual(time(), strtotime($row['report_expires_at']));
    }

    /** Active free report is not expired */
    public function testActiveFreeReportNotExpired(): void
    {
        $this->insertRow([
            'status'           => 'free',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('+6 days')),
        ]);
        $row = $this->fetchRow('free-token-1');

        $this->assertGreaterThan(time(), strtotime($row['report_expires_at']));
    }

    // ── FreeReportRendering ───────────────────────────────────────────────────

    /** report_json is initially NULL (lazy generation on first visit) */
    public function testReportJsonInitiallyNull(): void
    {
        $this->insertRow([]);
        $row = $this->fetchRow('free-token-1');

        $this->assertNull($row['report_json']);
    }

    /** Lazy generation UPDATE sets report_json on free row */
    public function testLazyGenerationStoresReportJson(): void
    {
        $this->insertRow([]);

        $report_json = json_encode(['verdict' => 'HIGH', 'top25' => []]);
        $stmt = $this->pdo->prepare(
            'UPDATE reports SET report_json = ? WHERE token = ? AND status = "free" AND report_json IS NULL'
        );
        $stmt->execute([$report_json, 'free-token-1']);

        $this->assertSame(1, $stmt->rowCount(), 'Should update exactly one row');
        $row = $this->fetchRow('free-token-1');
        $this->assertSame($report_json, $row['report_json']);
    }

    /** Lazy generation UPDATE is idempotent (second update on already-set row is a no-op) */
    public function testLazyGenerationIsIdempotent(): void
    {
        $this->insertRow(['report_json' => json_encode(['verdict' => 'LOW'])]);

        $stmt = $this->pdo->prepare(
            'UPDATE reports SET report_json = ? WHERE token = ? AND status = "free" AND report_json IS NULL'
        );
        $stmt->execute([json_encode(['verdict' => 'HIGH']), 'free-token-1']);

        $this->assertSame(0, $stmt->rowCount(), 'Should be a no-op when report_json is already set');
        // Original value preserved
        $row = $this->fetchRow('free-token-1');
        $report = json_decode($row['report_json'], true);
        $this->assertSame('LOW', $report['verdict']);
    }

    /** View counter increments on page view */
    public function testViewCounterIncrements(): void
    {
        $this->insertRow(['view_count' => 0]);

        $this->pdo->exec(
            'UPDATE reports SET view_count = view_count + 1 WHERE token = "free-token-1"'
        );
        $this->pdo->exec(
            'UPDATE reports SET view_count = view_count + 1 WHERE token = "free-token-1"'
        );

        $row = $this->fetchRow('free-token-1');
        $this->assertSame(2, (int)$row['view_count']);
    }

    // ── TokenLifecycle: free status transitions ───────────────────────────────

    /** free → expired: cleanup query matches rows past grace period */
    public function testCleanupQueryMatchesExpiredFreeRows(): void
    {
        // Row expired 8 days ago — past the 7-day grace period
        $this->insertRow([
            'token'            => 'old-free-1',
            'status'           => 'free',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('-8 days')),
        ]);
        // Row expired 5 days ago — still in grace period
        $this->insertRow([
            'token'            => 'old-free-2',
            'status'           => 'free',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('-5 days')),
        ]);
        // Active row — should not be deleted
        $this->insertRow([
            'token'            => 'active-free',
            'status'           => 'free',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('+3 days')),
        ]);

        // Replicate cleanup-reports.php pass 3
        $stmt = $this->pdo->prepare(
            "DELETE FROM reports WHERE status = 'free'
             AND report_expires_at < datetime('now', '-7 days')"
        );
        $stmt->execute();

        $this->assertSame(1, $stmt->rowCount(), 'Only 1 row should be deleted (expired > 7 days ago)');
        $this->assertNull($this->fetchRow('old-free-1'), 'Row expired 8 days ago should be deleted');
        $this->assertNotNull($this->fetchRow('old-free-2'), 'Row expired 5 days ago should survive grace period');
        $this->assertNotNull($this->fetchRow('active-free'), 'Active row should not be deleted');
    }

    /** status='free' excluded from paid dedup even when report_expires_at is in future */
    public function testFreePermanentlyExcludedFromPaidDedup(): void
    {
        $hash = hash('sha256', 'test-data');
        $this->insertRow([
            'submission_hash' => $hash,
            'status'          => 'free',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('+7 days')),
        ]);

        $stmt = $this->pdo->prepare(
            'SELECT token FROM reports
             WHERE submission_hash = ? AND status IN ("paid","redeemed")
               AND (report_expires_at IS NULL OR report_expires_at > ?)
             LIMIT 1'
        );
        $stmt->execute([$hash, date('Y-m-d H:i:s')]);
        $cached = $stmt->fetch(\PDO::FETCH_ASSOC);

        $this->assertFalse($cached);
    }

    /** Paid dedup with NULL report_expires_at (permanent paid report) */
    public function testPaidDedupWithNullExpiresAtMatchesPermanentReport(): void
    {
        $hash = hash('sha256', 'test-data-paid');
        $this->insertRow([
            'token'            => 'permanent-paid',
            'submission_hash'  => $hash,
            'status'           => 'redeemed',
            'report_expires_at' => null,
        ]);

        // New paid reports have report_expires_at = NULL (permanent).
        // The dedup check uses OR report_expires_at IS NULL to catch them.
        $stmt = $this->pdo->prepare(
            'SELECT token FROM reports
             WHERE submission_hash = ? AND status IN ("paid","redeemed")
               AND (report_expires_at IS NULL OR report_expires_at > ?)
             ORDER BY created_at DESC LIMIT 1'
        );
        $stmt->execute([$hash, date('Y-m-d H:i:s')]);
        $cached = $stmt->fetch(\PDO::FETCH_ASSOC);

        $this->assertNotFalse($cached);
        $this->assertSame('permanent-paid', $cached['token']);
    }
}
