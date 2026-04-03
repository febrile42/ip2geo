<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../email_helper.php';

/**
 * Tests for email_helper.php.
 *
 * Pure function tests (mask_email, build_payment_alert_html) run without any
 * DB or network. Atomic DB logic in send_report_email() is tested by replaying
 * the exact SQL statements against a SQLite mirror — same pattern as
 * TokenLifecycleTest — since the function accepts a mysqli connection.
 */
class EmailHelperTest extends TestCase
{
    // ── mask_email ─────────────────────────────────────────────────────────────

    public function testMaskEmailNormal(): void
    {
        // local='foo' → len=3, stars=min(2,3)=2 → 'f**'
        $this->assertSame('f**@example.com', mask_email('foo@example.com'));
    }

    public function testMaskEmailLongLocalCappedAtThreeStars(): void
    {
        // local='foobar' → len=6, stars=min(5,3)=3 → 'f***'
        $this->assertSame('f***@example.com', mask_email('foobar@example.com'));
    }

    public function testMaskEmailTwoCharLocal(): void
    {
        // local='ab' → len=2, stars=min(1,3)=1 → 'a*'
        $this->assertSame('a*@domain.com', mask_email('ab@domain.com'));
    }

    public function testMaskEmailOneCharLocal(): void
    {
        // local='a' → len=1, not > 1 → '*'
        $this->assertSame('*@x.io', mask_email('a@x.io'));
    }

    public function testMaskEmailEmptyLocal(): void
    {
        // '@domain.com' → local='', len=0, not > 1 → '*'
        $this->assertSame('*@domain.com', mask_email('@domain.com'));
    }

    public function testMaskEmailNoAtSign(): void
    {
        $this->assertSame('***', mask_email('invalidemail'));
    }

    // ── report_email_subject ───────────────────────────────────────────────────

    public function testSubjectIncludesIpCountWhenPositive(): void
    {
        // Regression: webhook.php was not passing ip_count, so subject always
        // dropped the count. Verify the subject includes the count when > 0.
        $this->assertSame(
            'Threat Intelligence Report (500 IPs) - ip2geo',
            report_email_subject(500)
        );
    }

    public function testSubjectOmitsCountWhenZero(): void
    {
        $this->assertSame(
            'Threat Intelligence Report - ip2geo',
            report_email_subject(0)
        );
    }

    // ── build_payment_alert_html ───────────────────────────────────────────────

    public function testAlertHtmlContainsDescription(): void
    {
        $html = build_payment_alert_html('Something went wrong');
        $this->assertStringContainsString('Something went wrong', $html);
    }

    public function testAlertHtmlEscapesDescriptionXss(): void
    {
        $html = build_payment_alert_html('<script>alert(1)</script>');
        $this->assertStringNotContainsString('<script>', $html);
        $this->assertStringContainsString('&lt;script&gt;', $html);
    }

    public function testAlertHtmlRendersAllContextFields(): void
    {
        $html = build_payment_alert_html('test', [
            'token'          => 'tok_abc',
            'session_id'     => 'cs_123',
            'payment_intent' => 'pi_456',
            'email'          => 'user@example.com',
            'error'          => 'DB timeout',
            'note'           => 'Check logs',
        ]);
        $this->assertStringContainsString('tok_abc', $html);
        $this->assertStringContainsString('cs_123', $html);
        $this->assertStringContainsString('pi_456', $html);
        $this->assertStringContainsString('user@example.com', $html);
        $this->assertStringContainsString('DB timeout', $html);
        $this->assertStringContainsString('Check logs', $html);
    }

    public function testAlertHtmlSkipsEmptyContextFields(): void
    {
        $html = build_payment_alert_html('test', ['token' => '', 'session_id' => '']);
        // Empty fields produce no table rows; labels must be absent
        $this->assertStringNotContainsString('>Token<', $html);
        $this->assertStringNotContainsString('>Stripe Session ID<', $html);
    }

    public function testAlertHtmlEscapesContextFieldXss(): void
    {
        $html = build_payment_alert_html('test', ['error' => '<b>injected</b>']);
        $this->assertStringNotContainsString('<b>', $html);
        $this->assertStringContainsString('&lt;b&gt;', $html);
    }

    public function testAlertHtmlStripePaymentIntentLink(): void
    {
        $html = build_payment_alert_html('test', ['payment_intent' => 'pi_99']);
        $this->assertStringContainsString('dashboard.stripe.com/payments/pi_99', $html);
    }

    public function testAlertHtmlStripeSessionLink(): void
    {
        $html = build_payment_alert_html('test', ['session_id' => 'cs_99']);
        $this->assertStringContainsString('dashboard.stripe.com/checkout/sessions/cs_99', $html);
    }

    public function testAlertHtmlStripeSearchLinkForEmail(): void
    {
        // urlencode('foo@bar.com') = 'foo%40bar.com'
        $html = build_payment_alert_html('test', ['email' => 'foo@bar.com']);
        $this->assertStringContainsString('dashboard.stripe.com/search', $html);
        $this->assertStringContainsString('foo%40bar.com', $html);
    }

    public function testAlertHtmlFallbackWhenNoStripeIdentifiers(): void
    {
        $html = build_payment_alert_html('test', []);
        $this->assertStringContainsString('No Stripe identifiers available', $html);
    }

    public function testAlertHtmlDbSectionWithToken(): void
    {
        $html = build_payment_alert_html('test', ['token' => 'tok_xyz']);
        $this->assertStringContainsString("WHERE token = 'tok_xyz'", $html);
    }

    public function testAlertHtmlDbSectionWithoutToken(): void
    {
        $html = build_payment_alert_html('test', []);
        $this->assertStringContainsString('No token available', $html);
    }

    public function testAlertHtmlAlwaysContainsTimeRow(): void
    {
        $html = build_payment_alert_html('test', []);
        $this->assertStringContainsString('UTC', $html);
    }

    // ── send_report_email: atomic DB logic (SQLite mirror) ─────────────────────
    //
    // send_report_email() accepts a mysqli connection, so we can't pass it a
    // PDO/SQLite handle. Instead we replay the exact SQL it executes and verify
    // the claim semantics — same approach as TokenLifecycleTest.

    private \PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = new \PDO('sqlite::memory:');
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $this->pdo->exec('
            CREATE TABLE reports (
                token              VARCHAR(36)  PRIMARY KEY,
                status             VARCHAR(16)  NOT NULL DEFAULT "paid",
                notification_email VARCHAR(254),
                email_sent_at      DATETIME,
                created_at         DATETIME     NOT NULL
            )
        ');
    }

    private function insertPaid(string $token, ?string $notification_email = null): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO reports (token, status, notification_email, created_at)
             VALUES (?, "paid", ?, ?)'
        );
        $stmt->execute([$token, $notification_email, date('Y-m-d H:i:s')]);
    }

    private function getEmailFields(string $token): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT notification_email, email_sent_at FROM reports WHERE token = ?'
        );
        $stmt->execute([$token]);
        return $stmt->fetch(\PDO::FETCH_ASSOC) ?: [];
    }

    // notification_email: first writer wins (IS NULL guard)

    public function testNotificationEmailFirstWriterWins(): void
    {
        $this->insertPaid('tok_email_1', null);

        $stmt = $this->pdo->prepare(
            'UPDATE reports SET notification_email = ? WHERE token = ? AND notification_email IS NULL'
        );
        $stmt->execute(['first@example.com', 'tok_email_1']);
        $this->assertSame(1, $stmt->rowCount(), 'First write should store the address');

        $stmt->execute(['second@example.com', 'tok_email_1']);
        $this->assertSame(0, $stmt->rowCount(), 'Second write must be a no-op (address already set)');

        $this->assertSame('first@example.com', $this->getEmailFields('tok_email_1')['notification_email']);
    }

    public function testNotificationEmailNotOverwrittenWhenAlreadySet(): void
    {
        $this->insertPaid('tok_email_2', 'original@example.com');

        $stmt = $this->pdo->prepare(
            'UPDATE reports SET notification_email = ? WHERE token = ? AND notification_email IS NULL'
        );
        $stmt->execute(['new@example.com', 'tok_email_2']);
        $this->assertSame(0, $stmt->rowCount(), 'Existing address must not be overwritten');

        $this->assertSame('original@example.com', $this->getEmailFields('tok_email_2')['notification_email']);
    }

    // email_sent_at atomic claim: first caller claims the send slot

    public function testEmailSentAtFirstCallerClaims(): void
    {
        $this->insertPaid('tok_claim_1');

        $stmt = $this->pdo->prepare(
            "UPDATE reports SET email_sent_at = datetime('now') WHERE token = ? AND email_sent_at IS NULL"
        );
        $stmt->execute(['tok_claim_1']);
        $this->assertSame(1, $stmt->rowCount(), 'First caller should claim the send slot');
        $this->assertNotNull($this->getEmailFields('tok_claim_1')['email_sent_at']);
    }

    public function testEmailSentAtSecondCallerIsBlocked(): void
    {
        $this->insertPaid('tok_claim_2');

        $stmt = $this->pdo->prepare(
            "UPDATE reports SET email_sent_at = datetime('now') WHERE token = ? AND email_sent_at IS NULL"
        );
        $stmt->execute(['tok_claim_2']); // first caller claims
        $stmt->execute(['tok_claim_2']); // second caller
        $this->assertSame(0, $stmt->rowCount(), 'Second caller must find the slot already taken');
    }

    // On Resend failure: email_sent_at is reset to NULL so the next request retries

    public function testEmailSentAtResetToNullOnFailure(): void
    {
        $this->insertPaid('tok_reset');
        $this->pdo->exec("UPDATE reports SET email_sent_at = datetime('now') WHERE token = 'tok_reset'");

        // Simulate: Resend API threw → reset guard
        $stmt = $this->pdo->prepare('UPDATE reports SET email_sent_at = NULL WHERE token = ?');
        $stmt->execute(['tok_reset']);

        $this->assertNull(
            $this->getEmailFields('tok_reset')['email_sent_at'],
            'email_sent_at must be NULL after failure so the next request can retry'
        );
    }

    public function testEmailSentAtCanBeReclaimedAfterReset(): void
    {
        $this->insertPaid('tok_reclaim');
        // Claim → fail → reset
        $this->pdo->exec("UPDATE reports SET email_sent_at = datetime('now') WHERE token = 'tok_reclaim'");
        $this->pdo->exec("UPDATE reports SET email_sent_at = NULL WHERE token = 'tok_reclaim'");

        // Next request should be able to claim
        $stmt = $this->pdo->prepare(
            "UPDATE reports SET email_sent_at = datetime('now') WHERE token = ? AND email_sent_at IS NULL"
        );
        $stmt->execute(['tok_reclaim']);
        $this->assertSame(1, $stmt->rowCount(), 'After reset, next caller must be able to claim');
    }
}
