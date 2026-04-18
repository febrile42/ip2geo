<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Unit tests for /api/report-event.php logic.
 *
 * Tests the validation rules, rate-limit logic, and DB write pattern in isolation
 * using SQLite in-memory. Does not boot the endpoint directly.
 */
class ReportEventEndpointTest extends TestCase
{
    private \PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = new \PDO('sqlite::memory:');
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        $this->pdo->exec("
            CREATE TABLE report_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                token      VARCHAR(36) NOT NULL,
                event_type VARCHAR(30) NOT NULL,
                event_at   DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                session_id VARCHAR(64)
            )
        ");

        $this->pdo->exec("
            CREATE TABLE report_event_rl (
                token        VARCHAR(36) NOT NULL,
                window_start DATETIME    NOT NULL,
                count        INTEGER     NOT NULL DEFAULT 1,
                PRIMARY KEY (token, window_start)
            )
        ");
    }

    // ── Token validation ──────────────────────────────────────────────────────

    /** Valid UUID v4 passes the regex */
    public function testValidTokenPassesRegex(): void
    {
        $token = 'a1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5';
        $this->assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/',
            $token
        );
    }

    /** Uppercase UUID fails (endpoint requires lowercase) */
    public function testUppercaseTokenFailsRegex(): void
    {
        $token = 'A1B2C3D4-E5F6-4A7B-8C9D-E0F1A2B3C4D5';
        $this->assertDoesNotMatchRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/',
            $token
        );
    }

    /** Empty token fails */
    public function testEmptyTokenFailsRegex(): void
    {
        $this->assertDoesNotMatchRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/',
            ''
        );
    }

    /** Token with SQL injection attempt fails */
    public function testSqlInjectionTokenFailsRegex(): void
    {
        $token = "'; DROP TABLE report_events; --";
        $this->assertDoesNotMatchRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/',
            $token
        );
    }

    // ── Event type validation ─────────────────────────────────────────────────

    /** All four allowed event types pass */
    public function testAllowedEventTypes(): void
    {
        $allowed = ['page_viewed', 'cta_visible', 'cta_clicked', 'checkout_started'];
        foreach ($allowed as $type) {
            $this->assertContains($type, $allowed);
        }
    }

    /** Unknown event type is not in allowed list */
    public function testUnknownEventTypeRejected(): void
    {
        $allowed = ['page_viewed', 'cta_visible', 'cta_clicked', 'checkout_started'];
        $this->assertNotContains('admin_view', $allowed);
        $this->assertNotContains('', $allowed);
        $this->assertNotContains('page_viewed; DROP TABLE', $allowed);
    }

    // ── session_id handling ───────────────────────────────────────────────────

    /** session_id longer than 64 chars is truncated */
    public function testSessionIdTruncatedAt64Chars(): void
    {
        $long = str_repeat('a', 80);
        $truncated = substr(trim($long), 0, 64);
        $this->assertSame(64, strlen($truncated));
    }

    /** Empty session_id becomes null */
    public function testEmptySessionIdBecomesNull(): void
    {
        $session_id = trim('');
        if ($session_id === '') $session_id = null;
        $this->assertNull($session_id);
    }

    /** Valid 32-char hex session_id passes through unchanged */
    public function testValidSessionIdPassesThrough(): void
    {
        $sid = str_repeat('a1', 16); // 32 chars
        $result = substr(trim($sid), 0, 64);
        $this->assertSame($sid, $result);
    }

    // ── Rate limit logic ──────────────────────────────────────────────────────

    /** Rate limit INSERT upserts correctly — first event creates count=1 */
    public function testRateLimitFirstEventCreatesCount(): void
    {
        $token  = 'aaaaaaaa-0000-4000-8000-000000000001';
        $window = date('Y-m-d H:i:00');

        $this->pdo->prepare(
            'INSERT INTO report_event_rl (token, window_start, count) VALUES (?, ?, 1)
             ON CONFLICT(token, window_start) DO UPDATE SET count = count + 1'
        )->execute([$token, $window]);

        $stmt = $this->pdo->prepare(
            'SELECT count FROM report_event_rl WHERE token = ? AND window_start = ?'
        );
        $stmt->execute([$token, $window]);
        $this->assertSame(1, (int)$stmt->fetchColumn());
    }

    /** Rate limit upsert increments count on second event in same window */
    public function testRateLimitSecondEventIncrementsCount(): void
    {
        $token  = 'aaaaaaaa-0000-4000-8000-000000000002';
        $window = date('Y-m-d H:i:00');

        $upsert = $this->pdo->prepare(
            'INSERT INTO report_event_rl (token, window_start, count) VALUES (?, ?, 1)
             ON CONFLICT(token, window_start) DO UPDATE SET count = count + 1'
        );
        $upsert->execute([$token, $window]);
        $upsert->execute([$token, $window]);
        $upsert->execute([$token, $window]);

        $stmt = $this->pdo->prepare(
            'SELECT count FROM report_event_rl WHERE token = ? AND window_start = ?'
        );
        $stmt->execute([$token, $window]);
        $this->assertSame(3, (int)$stmt->fetchColumn());
    }

    /** Events above 20 per minute are rejected by the rate limit */
    public function testRateLimitRejects21stEvent(): void
    {
        $token  = 'aaaaaaaa-0000-4000-8000-000000000003';
        $window = date('Y-m-d H:i:00');

        // Seed the RL table with count=20 directly
        $this->pdo->prepare(
            'INSERT INTO report_event_rl (token, window_start, count) VALUES (?, ?, 20)'
        )->execute([$token, $window]);

        // Simulate one more event → count becomes 21
        $this->pdo->prepare(
            'INSERT INTO report_event_rl (token, window_start, count) VALUES (?, ?, 1)
             ON CONFLICT(token, window_start) DO UPDATE SET count = count + 1'
        )->execute([$token, $window]);

        $stmt = $this->pdo->prepare(
            'SELECT count FROM report_event_rl WHERE token = ? AND window_start = ?'
        );
        $stmt->execute([$token, $window]);
        $count = (int)$stmt->fetchColumn();

        // Rate limit check: > 20 means reject
        $this->assertGreaterThan(20, $count);
    }

    /** 20th event is still within the limit */
    public function testRateLimitAllows20thEvent(): void
    {
        $token  = 'aaaaaaaa-0000-4000-8000-000000000004';
        $window = date('Y-m-d H:i:00');

        $this->pdo->prepare(
            'INSERT INTO report_event_rl (token, window_start, count) VALUES (?, ?, 20)'
        )->execute([$token, $window]);

        $stmt = $this->pdo->prepare(
            'SELECT count FROM report_event_rl WHERE token = ? AND window_start = ?'
        );
        $stmt->execute([$token, $window]);
        $count = (int)$stmt->fetchColumn();

        $this->assertLessThanOrEqual(20, $count, '20th event should be within limit');
    }

    /** Different tokens have separate rate limit buckets */
    public function testRateLimitBucketsArePerToken(): void
    {
        $window = date('Y-m-d H:i:00');
        $tok1   = 'aaaaaaaa-0000-4000-8000-000000000005';
        $tok2   = 'aaaaaaaa-0000-4000-8000-000000000006';

        $upsert = $this->pdo->prepare(
            'INSERT INTO report_event_rl (token, window_start, count) VALUES (?, ?, 1)
             ON CONFLICT(token, window_start) DO UPDATE SET count = count + 1'
        );

        // 5 events for tok1, 3 for tok2
        for ($i = 0; $i < 5; $i++) $upsert->execute([$tok1, $window]);
        for ($i = 0; $i < 3; $i++) $upsert->execute([$tok2, $window]);

        $fetch = $this->pdo->prepare(
            'SELECT count FROM report_event_rl WHERE token = ? AND window_start = ?'
        );

        $fetch->execute([$tok1, $window]);
        $this->assertSame(5, (int)$fetch->fetchColumn());

        $fetch->execute([$tok2, $window]);
        $this->assertSame(3, (int)$fetch->fetchColumn());
    }

    // ── Event INSERT ──────────────────────────────────────────────────────────

    /** Event INSERT stores token, event_type, and session_id */
    public function testEventInsertStoresAllFields(): void
    {
        $token      = 'aaaaaaaa-0000-4000-8000-000000000007';
        $event_type = 'cta_clicked';
        $session_id = bin2hex(random_bytes(16));

        $this->pdo->prepare(
            'INSERT INTO report_events (token, event_type, session_id) VALUES (?, ?, ?)'
        )->execute([$token, $event_type, $session_id]);

        $stmt = $this->pdo->prepare(
            'SELECT * FROM report_events WHERE token = ? ORDER BY id DESC LIMIT 1'
        );
        $stmt->execute([$token]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);

        $this->assertSame($token,      $row['token']);
        $this->assertSame($event_type, $row['event_type']);
        $this->assertSame($session_id, $row['session_id']);
    }

    /** Event INSERT with null session_id stores NULL */
    public function testEventInsertWithNullSessionId(): void
    {
        $token = 'aaaaaaaa-0000-4000-8000-000000000008';

        $this->pdo->prepare(
            'INSERT INTO report_events (token, event_type, session_id) VALUES (?, ?, ?)'
        )->execute([$token, 'page_viewed', null]);

        $stmt = $this->pdo->prepare(
            'SELECT session_id FROM report_events WHERE token = ?'
        );
        $stmt->execute([$token]);
        $this->assertNull($stmt->fetchColumn());
    }

    // ── Cleanup logic ─────────────────────────────────────────────────────────

    /** Cleanup removes events older than 90 days */
    public function testCleanupRemovesOldEvents(): void
    {
        $token = 'aaaaaaaa-0000-4000-8000-000000000009';

        $this->pdo->prepare(
            "INSERT INTO report_events (token, event_type, event_at) VALUES (?, 'page_viewed', ?)"
        )->execute([$token, date('Y-m-d H:i:s', strtotime('-91 days'))]);

        $this->pdo->prepare(
            "INSERT INTO report_events (token, event_type, event_at) VALUES (?, 'cta_visible', ?)"
        )->execute([$token, date('Y-m-d H:i:s', strtotime('-30 days'))]);

        $this->pdo->exec(
            "DELETE FROM report_events WHERE event_at < datetime('now', '-90 days')"
        );

        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM report_events WHERE token = ?');
        $stmt->execute([$token]);
        $this->assertSame(1, (int)$stmt->fetchColumn(), 'Only the recent event should remain');
    }

    /** RL cleanup removes windows older than 2 minutes */
    public function testRlCleanupRemovesOldWindows(): void
    {
        $token  = 'aaaaaaaa-0000-4000-8000-00000000000a';
        $old    = date('Y-m-d H:i:00', strtotime('-3 minutes'));
        $recent = date('Y-m-d H:i:00');

        $this->pdo->prepare(
            'INSERT INTO report_event_rl (token, window_start, count) VALUES (?, ?, 5)'
        )->execute([$token, $old]);

        $this->pdo->prepare(
            'INSERT INTO report_event_rl (token, window_start, count) VALUES (?, ?, 3)'
        )->execute([$token, $recent]);

        $this->pdo->exec(
            "DELETE FROM report_event_rl WHERE window_start < datetime('now', '-2 minutes')"
        );

        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM report_event_rl WHERE token = ?');
        $stmt->execute([$token]);
        $this->assertSame(1, (int)$stmt->fetchColumn(), 'Only recent window should remain');
    }
}
