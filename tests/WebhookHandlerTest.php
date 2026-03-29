<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Webhook handler logic tests.
 *
 * We don't boot webhook.php directly (it reads php://input and exits).
 * Instead we test the three independent concerns:
 *
 *  1. HMAC signature verification — via the Stripe SDK's own constructEvent()
 *     with a known secret and correctly-computed test signature.
 *
 *  2. Event type filtering — only checkout.session.completed triggers DB writes.
 *
 *  3. Idempotent DB update — the UPDATE WHERE status="pending" guard.
 *     (Covered more thoroughly in TokenLifecycleTest; spot-checked here
 *      against the exact SQL string webhook.php uses.)
 *
 * Requires stripe/stripe-php in vendor/.
 * Run: vendor/bin/phpunit tests/WebhookHandlerTest.php
 */
class WebhookHandlerTest extends TestCase
{
    // ── Stripe signature verification ─────────────────────────────────────────

    /**
     * Build a test Stripe-Signature header the same way Stripe does.
     */
    private function buildStripeSignature(string $payload, string $secret, int $timestamp): string
    {
        $signed  = $timestamp . '.' . $payload;
        $sig     = hash_hmac('sha256', $signed, $secret);
        return 't=' . $timestamp . ',v1=' . $sig;
    }

    public function testValidSignatureConstructsEvent(): void
    {
        if (!class_exists('\Stripe\Webhook')) {
            $this->markTestSkipped('stripe/stripe-php not installed');
        }

        $secret    = 'whsec_test_secret_for_unit_test';
        $timestamp = time();
        $payload   = json_encode([
            'id'   => 'evt_test',
            'type' => 'checkout.session.completed',
            'data' => ['object' => ['client_reference_id' => 'tok_abc', 'payment_intent' => 'pi_123']],
        ]);

        $sig = $this->buildStripeSignature($payload, $secret, $timestamp);

        $event = \Stripe\Webhook::constructEvent($payload, $sig, $secret);
        $this->assertSame('checkout.session.completed', $event->type);
    }

    public function testInvalidSignatureThrows(): void
    {
        if (!class_exists('\Stripe\Webhook')) {
            $this->markTestSkipped('stripe/stripe-php not installed');
        }

        $this->expectException(\Stripe\Exception\SignatureVerificationException::class);

        $payload = json_encode(['id' => 'evt_test', 'type' => 'charge.succeeded', 'data' => ['object' => []]]);
        $badSig  = 't=' . time() . ',v1=deadbeef';

        \Stripe\Webhook::constructEvent($payload, $badSig, 'whsec_real_secret');
    }

    public function testTamperedPayloadThrows(): void
    {
        if (!class_exists('\Stripe\Webhook')) {
            $this->markTestSkipped('stripe/stripe-php not installed');
        }

        $this->expectException(\Stripe\Exception\SignatureVerificationException::class);

        $secret    = 'whsec_test_tamper';
        $timestamp = time();
        $original  = json_encode(['id' => 'evt_test', 'type' => 'charge.succeeded', 'data' => ['object' => []]]);
        $sig       = $this->buildStripeSignature($original, $secret, $timestamp);

        // Tamper with the payload after signing
        $tampered = str_replace('charge.succeeded', 'checkout.session.completed', $original);

        \Stripe\Webhook::constructEvent($tampered, $sig, $secret);
    }

    public function testExpiredTimestampThrows(): void
    {
        if (!class_exists('\Stripe\Webhook')) {
            $this->markTestSkipped('stripe/stripe-php not installed');
        }

        $this->expectException(\Stripe\Exception\SignatureVerificationException::class);

        $secret    = 'whsec_test_tolerance';
        $oldTs     = time() - 400; // 400s ago, beyond Stripe's 300s tolerance
        $payload   = json_encode(['id' => 'evt_test', 'type' => 'charge.succeeded', 'data' => ['object' => []]]);
        $sig       = $this->buildStripeSignature($payload, $secret, $oldTs);

        \Stripe\Webhook::constructEvent($payload, $sig, $secret);
    }

    // ── Event type filtering ──────────────────────────────────────────────────

    /**
     * Simulates the webhook.php guard: only act on checkout.session.completed.
     */
    private function shouldProcessEvent(string $eventType): bool
    {
        return $eventType === 'checkout.session.completed';
    }

    public function testCheckoutSessionCompletedIsProcessed(): void
    {
        $this->assertTrue($this->shouldProcessEvent('checkout.session.completed'));
    }

    public function testOtherEventTypesAreIgnored(): void
    {
        $ignored = [
            'charge.succeeded',
            'payment_intent.created',
            'customer.created',
            'checkout.session.async_payment_succeeded',
            '',
        ];

        foreach ($ignored as $type) {
            $this->assertFalse(
                $this->shouldProcessEvent($type),
                "Expected event type '{$type}' to be ignored"
            );
        }
    }

    // ── Idempotent DB update (SQLite mirror) ──────────────────────────────────

    private \PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = new \PDO('sqlite::memory:');
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $this->pdo->exec("
            CREATE TABLE reports (
                token                 VARCHAR(36) PRIMARY KEY,
                submission_hash       VARCHAR(64) NOT NULL,
                ip_list_json          TEXT        NOT NULL,
                status                VARCHAR(16) NOT NULL DEFAULT 'pending',
                pending_expires_at    DATETIME,
                report_expires_at     DATETIME,
                report_json           TEXT,
                stripe_payment_intent VARCHAR(64),
                created_at            DATETIME    NOT NULL
            )
        ");
    }

    private function insertPending(string $token, bool $expired = false): void
    {
        $exp = $expired
            ? date('Y-m-d H:i:s', strtotime('-1 minute'))
            : date('Y-m-d H:i:s', strtotime('+1 hour'));

        $stmt = $this->pdo->prepare(
            'INSERT INTO reports (token, submission_hash, ip_list_json, status, pending_expires_at, created_at)
             VALUES (?, ?, ?, "pending", ?, ?)'
        );
        $stmt->execute([$token, hash('sha256', ''), '[]', $exp, date('Y-m-d H:i:s')]);
    }

    private function getStatus(string $token): ?string
    {
        $stmt = $this->pdo->prepare('SELECT status FROM reports WHERE token = ?');
        $stmt->execute([$token]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);
        return $row ? $row['status'] : null;
    }

    public function testWebhookMarksPendingTokenAsPaid(): void
    {
        $this->insertPending('tok_valid');
        $intent = 'pi_test';

        $stmt = $this->pdo->prepare(
            'UPDATE reports
             SET status = "paid", stripe_payment_intent = ?
             WHERE token = ? AND status = "pending" AND pending_expires_at > ?'
        );
        $stmt->execute([$intent, 'tok_valid', date('Y-m-d H:i:s')]);

        $this->assertSame(1, $stmt->rowCount());
        $this->assertSame('paid', $this->getStatus('tok_valid'));
    }

    public function testWebhookIgnoresAlreadyPaidToken(): void
    {
        $this->insertPending('tok_paid');
        // Pre-mark as paid
        $this->pdo->exec("UPDATE reports SET status = 'paid' WHERE token = 'tok_paid'");

        $stmt = $this->pdo->prepare(
            'UPDATE reports
             SET status = "paid", stripe_payment_intent = ?
             WHERE token = ? AND status = "pending" AND pending_expires_at > ?'
        );
        $stmt->execute(['pi_dup', 'tok_paid', date('Y-m-d H:i:s')]);

        $this->assertSame(0, $stmt->rowCount(), 'Already-paid token should not be updated again');
    }

    public function testWebhookIgnoresRedeemedToken(): void
    {
        $this->insertPending('tok_redeemed');
        $this->pdo->exec("UPDATE reports SET status = 'redeemed' WHERE token = 'tok_redeemed'");

        $stmt = $this->pdo->prepare(
            'UPDATE reports
             SET status = "paid", stripe_payment_intent = ?
             WHERE token = ? AND status = "pending" AND pending_expires_at > ?'
        );
        $stmt->execute(['pi_dup', 'tok_redeemed', date('Y-m-d H:i:s')]);

        $this->assertSame(0, $stmt->rowCount());
    }

    public function testWebhookIgnoresExpiredPendingToken(): void
    {
        $this->insertPending('tok_expired', expired: true);

        $stmt = $this->pdo->prepare(
            'UPDATE reports
             SET status = "paid", stripe_payment_intent = ?
             WHERE token = ? AND status = "pending" AND pending_expires_at > ?'
        );
        $stmt->execute(['pi_late', 'tok_expired', date('Y-m-d H:i:s')]);

        $this->assertSame(0, $stmt->rowCount(), 'Expired pending token should not be paid');
        $this->assertSame('pending', $this->getStatus('tok_expired'));
    }

    public function testWebhookIgnoresNonexistentToken(): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE reports
             SET status = "paid", stripe_payment_intent = ?
             WHERE token = ? AND status = "pending" AND pending_expires_at > ?'
        );
        $stmt->execute(['pi_ghost', 'tok_ghost', date('Y-m-d H:i:s')]);

        $this->assertSame(0, $stmt->rowCount());
    }
}
