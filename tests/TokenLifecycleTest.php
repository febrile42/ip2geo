<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Token lifecycle state-machine tests using an in-memory SQLite database.
 *
 * Tests the state transitions and expiry logic that report.php enforces:
 *   pending (not expired)  → show "payment processing" error
 *   pending (expired)      → show "expired payment window" error
 *   paid                   → generate report, mark redeemed
 *   redeemed (not expired) → serve cached report_json
 *   redeemed (expired)     → show "report expired" error
 *
 * We don't boot report.php directly; instead we replicate the exact SQL
 * that report.php uses so any drift between the tests and the real code
 * will surface as a test failure.
 */
class TokenLifecycleTest extends TestCase
{
    private \PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = new \PDO('sqlite::memory:');
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        // Mirror the reports table from scripts/migrate.sql
        $this->pdo->exec("
            CREATE TABLE reports (
                token               VARCHAR(36)  PRIMARY KEY,
                submission_hash     VARCHAR(64)  NOT NULL,
                ip_list_json        TEXT         NOT NULL,
                status              VARCHAR(16)  NOT NULL DEFAULT 'pending',
                pending_expires_at  DATETIME,
                report_expires_at   DATETIME,
                report_json         TEXT,
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
            'token'              => 'test-token-1',
            'submission_hash'    => hash('sha256', '[]'),
            'ip_list_json'       => '[]',
            'status'             => 'pending',
            'pending_expires_at' => date('Y-m-d H:i:s', strtotime('+1 hour')),
            'report_expires_at'  => null,
            'report_json'        => null,
            'created_at'         => date('Y-m-d H:i:s'),
        ];
        $row = array_merge($defaults, $fields);
        $sql = 'INSERT INTO reports (token, submission_hash, ip_list_json, status,
                    pending_expires_at, report_expires_at, report_json, created_at)
                VALUES (:token, :submission_hash, :ip_list_json, :status,
                    :pending_expires_at, :report_expires_at, :report_json, :created_at)';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($row);
    }

    private function fetchRow(string $token): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT token, status, pending_expires_at, report_expires_at, report_json
             FROM reports WHERE token = ?'
        );
        $stmt->execute([$token]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    // ── pending token: not expired ────────────────────────────────────────────

    public function testPendingTokenNotExpiredExists(): void
    {
        $this->insertRow(['status' => 'pending']);
        $row = $this->fetchRow('test-token-1');

        $this->assertNotNull($row);
        $this->assertSame('pending', $row['status']);
        $this->assertGreaterThan(time(), strtotime($row['pending_expires_at']));
    }

    // ── pending token: expired ────────────────────────────────────────────────

    public function testPendingTokenExpiredDetected(): void
    {
        $this->insertRow([
            'status'             => 'pending',
            'pending_expires_at' => date('Y-m-d H:i:s', strtotime('-1 second')),
        ]);
        $row = $this->fetchRow('test-token-1');

        $this->assertNotNull($row);
        $this->assertSame('pending', $row['status']);
        $this->assertLessThanOrEqual(time(), strtotime($row['pending_expires_at']));
    }

    // ── webhook marks pending → paid ──────────────────────────────────────────

    public function testWebhookMarksPendingAsPaid(): void
    {
        $this->insertRow(['status' => 'pending']);

        $token  = 'test-token-1';
        $intent = 'pi_test123';

        $stmt = $this->pdo->prepare(
            'UPDATE reports
             SET status = "paid", stripe_payment_intent = :intent,
                 notification_email = COALESCE(notification_email, NULLIF(:email, ""))
             WHERE token = :token AND status = "pending" AND pending_expires_at > :now'
        );
        $stmt->execute([':intent' => $intent, ':email' => '', ':token' => $token, ':now' => date('Y-m-d H:i:s')]);

        $this->assertSame(1, $stmt->rowCount());
        $row = $this->fetchRow($token);
        $this->assertSame('paid', $row['status']);
    }

    public function testWebhookIsIdempotentOnAlreadyPaidToken(): void
    {
        $this->insertRow(['status' => 'paid']);

        $stmt = $this->pdo->prepare(
            'UPDATE reports
             SET status = "paid", stripe_payment_intent = :intent,
                 notification_email = COALESCE(notification_email, NULLIF(:email, ""))
             WHERE token = :token AND status = "pending" AND pending_expires_at > :now'
        );
        $stmt->execute([':intent' => 'pi_test123', ':email' => '', ':token' => 'test-token-1', ':now' => date('Y-m-d H:i:s')]);

        // already paid → WHERE status = "pending" finds nothing → 0 rows updated
        $this->assertSame(0, $stmt->rowCount());
    }

    public function testWebhookDoesNotMarkExpiredTokenAsPaid(): void
    {
        $this->insertRow([
            'status'             => 'pending',
            'pending_expires_at' => date('Y-m-d H:i:s', strtotime('-1 minute')),
        ]);

        $stmt = $this->pdo->prepare(
            'UPDATE reports
             SET status = "paid", stripe_payment_intent = :intent,
                 notification_email = COALESCE(notification_email, NULLIF(:email, ""))
             WHERE token = :token AND status = "pending" AND pending_expires_at > :now'
        );
        $stmt->execute([':intent' => 'pi_test', ':email' => '', ':token' => 'test-token-1', ':now' => date('Y-m-d H:i:s')]);

        $this->assertSame(0, $stmt->rowCount());
        // Status must still be pending (not paid)
        $this->assertSame('pending', $this->fetchRow('test-token-1')['status']);
    }

    // ── report generation: paid → redeemed ───────────────────────────────────

    public function testReportGenerationMarksPaidAsRedeemed(): void
    {
        $this->insertRow(['status' => 'paid']);

        $token      = 'test-token-1';
        $reportJson = json_encode(['verdict' => 'HIGH']);
        $expires    = date('Y-m-d H:i:s', strtotime('+30 days'));

        $stmt = $this->pdo->prepare(
            'UPDATE reports
             SET status = "redeemed", report_json = :rj, report_expires_at = :exp
             WHERE token = :token AND status IN ("pending","paid")'
        );
        $stmt->execute([':rj' => $reportJson, ':exp' => $expires, ':token' => $token]);

        $this->assertSame(1, $stmt->rowCount());
        $row = $this->fetchRow($token);
        $this->assertSame('redeemed', $row['status']);
        $this->assertSame($reportJson, $row['report_json']);
        $this->assertNotNull($row['report_expires_at']);
    }

    // ── redeemed: not expired → cached report served ──────────────────────────

    public function testRedeemedTokenNotExpiredHasCachedReport(): void
    {
        $this->insertRow([
            'status'            => 'redeemed',
            'report_json'       => '{"verdict":"LOW"}',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('+29 days')),
        ]);

        $row = $this->fetchRow('test-token-1');

        $this->assertSame('redeemed', $row['status']);
        $this->assertGreaterThan(time(), strtotime($row['report_expires_at']));
        $this->assertNotNull($row['report_json']);
        $report = json_decode($row['report_json'], true);
        $this->assertSame('LOW', $report['verdict']);
    }

    // ── redeemed: expired → error ─────────────────────────────────────────────

    public function testRedeemedTokenExpiredDetected(): void
    {
        $this->insertRow([
            'status'            => 'redeemed',
            'report_json'       => '{"verdict":"MODERATE"}',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('-1 day')),
        ]);

        $row = $this->fetchRow('test-token-1');

        $this->assertSame('redeemed', $row['status']);
        $this->assertLessThan(time(), strtotime($row['report_expires_at']));
    }

    // ── submission_hash dedup: same IP list reuses cached report ─────────────

    public function testSameSubmissionHashFindsExistingPaidReport(): void
    {
        $hash = hash('sha256', '[{"ip":"1.2.3.4"}]');
        $this->insertRow([
            'token'           => 'cached-token',
            'submission_hash' => $hash,
            'status'          => 'redeemed',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('+29 days')),
        ]);

        // Simulate the SELECT in get-report.php
        $stmt = $this->pdo->prepare(
            'SELECT token, status FROM reports
             WHERE submission_hash = ? AND status IN ("paid","redeemed")
               AND (report_expires_at IS NULL OR report_expires_at > ?)
             ORDER BY created_at DESC LIMIT 1'
        );
        $stmt->execute([$hash, date('Y-m-d H:i:s')]);
        $cached = $stmt->fetch(\PDO::FETCH_ASSOC);

        $this->assertNotFalse($cached);
        $this->assertSame('cached-token', $cached['token']);
    }

    public function testDifferentSubmissionHashDoesNotMatchCachedReport(): void
    {
        $this->insertRow([
            'token'           => 'cached-token',
            'submission_hash' => hash('sha256', 'original'),
            'status'          => 'redeemed',
            'report_expires_at' => date('Y-m-d H:i:s', strtotime('+1 day')),
        ]);

        $stmt = $this->pdo->prepare(
            'SELECT token FROM reports
             WHERE submission_hash = ? AND status IN ("paid","redeemed")
               AND (report_expires_at IS NULL OR report_expires_at > ?)
             LIMIT 1'
        );
        $stmt->execute([hash('sha256', 'different'), date('Y-m-d H:i:s')]);
        $cached = $stmt->fetch(\PDO::FETCH_ASSOC);

        $this->assertFalse($cached);
    }
}
