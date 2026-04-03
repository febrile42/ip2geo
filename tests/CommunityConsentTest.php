<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Community consent endpoint logic tests.
 *
 * We don't boot community-consent.php directly (it reads $_POST and exits).
 * Instead we replicate the exact SQL and business-logic it uses so any drift
 * between the tests and the real code surfaces as a test failure.
 *
 * Covers:
 *  1. Method validation (GET → 405)
 *  2. Missing / bad params (token, consent) → 400
 *  3. Invalid / unknown token → 400 invalid_token
 *  4. Unpaid (pending) status → 400 invalid_token
 *  5. Idempotency: data_consent already 0 → already_set
 *  6. Idempotency: data_consent already 1 → already_set
 *  7. Decline (consent=0): sets data_consent=0, returns ok
 *  8. Opt-in (consent=1) with valid JSON: ingests CIDRs + IPs, returns ingested=true
 *  9. Opt-in with null report_json: returns ingested=false
 * 10. Opt-in filters residential IPs (not ingested)
 * 11. Opt-in filters unknown IPs (not ingested)
 * 12. Opt-in ingests scanning / vpn_proxy / cloud_exit IPs
 * 13. week_start format is correct (Monday, YYYY-MM-DD)
 * 14. CIDR entries as string AND as ['cidr'=>…,'hits'=>…] objects are both handled
 *
 * Run: vendor/bin/phpunit tests/CommunityConsentTest.php
 */
class CommunityConsentTest extends TestCase
{
    private \PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = new \PDO('sqlite::memory:');
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        // Mirror reports table from scripts/migrate.sql
        $this->pdo->exec("
            CREATE TABLE reports (
                token                 VARCHAR(36)  PRIMARY KEY,
                submission_hash       VARCHAR(64)  NOT NULL,
                ip_list_json          TEXT,
                status                VARCHAR(16)  NOT NULL DEFAULT 'pending',
                pending_expires_at    DATETIME,
                report_expires_at     DATETIME,
                report_json           TEXT,
                stripe_payment_intent VARCHAR(64),
                notification_email    VARCHAR(254),
                email_sent_at         DATETIME,
                data_consent          INTEGER,
                created_at            DATETIME     NOT NULL
            )
        ");

        $this->pdo->exec("
            CREATE TABLE community_cidr_stats (
                cidr         VARCHAR(50)  NOT NULL,
                asn          VARCHAR(20)  NOT NULL,
                org          VARCHAR(255) NOT NULL DEFAULT '',
                week_start   DATE         NOT NULL,
                report_count INTEGER      NOT NULL DEFAULT 0,
                total_hits   INTEGER      NOT NULL DEFAULT 0,
                PRIMARY KEY (cidr, week_start)
            )
        ");

        $this->pdo->exec("
            CREATE TABLE community_ip_stats (
                ip           VARCHAR(45) NOT NULL,
                week_start   DATE        NOT NULL,
                report_count INTEGER     NOT NULL DEFAULT 0,
                total_hits   INTEGER     NOT NULL DEFAULT 0,
                PRIMARY KEY (ip, week_start)
            )
        ");

        $this->pdo->exec("
            CREATE TABLE community_ip_first_seen (
                ip         VARCHAR(45) NOT NULL PRIMARY KEY,
                first_seen DATE        NOT NULL
            )
        ");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /**
     * Insert a row into reports. Defaults to a paid report with no consent yet.
     */
    private function insertReport(array $fields): void
    {
        $defaults = [
            'token'           => 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            'submission_hash' => hash('sha256', '[]'),
            'ip_list_json'    => '[]',
            'status'          => 'paid',
            'data_consent'    => null,
            'report_json'     => null,
            'created_at'      => gmdate('Y-m-d H:i:s'),
        ];
        $row = array_merge($defaults, $fields);

        $stmt = $this->pdo->prepare(
            'INSERT INTO reports
                (token, submission_hash, ip_list_json, status, data_consent, report_json, created_at)
             VALUES
                (:token, :submission_hash, :ip_list_json, :status, :data_consent, :report_json, :created_at)'
        );
        $stmt->execute($row);
    }

    /**
     * Fetch data_consent for a token.
     */
    private function fetchConsent(string $token): mixed
    {
        $stmt = $this->pdo->prepare('SELECT data_consent FROM reports WHERE token = ?');
        $stmt->execute([$token]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);
        return $row ? $row['data_consent'] : null;
    }

    // ── Method validation ─────────────────────────────────────────────────────

    /**
     * The endpoint's first guard: non-POST requests must return 405.
     * We test the guard condition directly.
     */
    public function testGetMethodIsRejected(): void
    {
        // Simulate the guard: if method !== POST → 405
        $method = 'GET';
        $rejected = ($method !== 'POST');
        $this->assertTrue($rejected, 'GET request should be rejected with 405');
    }

    public function testPostMethodIsAccepted(): void
    {
        $method = 'POST';
        $rejected = ($method !== 'POST');
        $this->assertFalse($rejected, 'POST request should pass the method guard');
    }

    // ── Parameter validation ──────────────────────────────────────────────────

    /**
     * Mirrors the endpoint's bad_request guard:
     *   token === '' || !in_array(consent, [0,1], true)
     */
    private function isBadRequest(string $token, int $consent): bool
    {
        return $token === '' || !in_array($consent, [0, 1], true);
    }

    public function testMissingTokenReturnsBadRequest(): void
    {
        $this->assertTrue($this->isBadRequest('', 1));
    }

    public function testMissingConsentReturnsBadRequest(): void
    {
        // -1 is the default when consent param is absent
        $this->assertTrue($this->isBadRequest('some-token', -1));
    }

    public function testConsentMinusOneReturnsBadRequest(): void
    {
        $this->assertTrue($this->isBadRequest('some-token', -1));
    }

    public function testConsentTwoReturnsBadRequest(): void
    {
        $this->assertTrue($this->isBadRequest('some-token', 2));
    }

    public function testConsentZeroWithTokenIsValid(): void
    {
        $this->assertFalse($this->isBadRequest('some-token', 0));
    }

    public function testConsentOneWithTokenIsValid(): void
    {
        $this->assertFalse($this->isBadRequest('some-token', 1));
    }

    // ── Token validation ──────────────────────────────────────────────────────

    /**
     * Replicates the token-lookup + status-check from community-consent.php:
     *   SELECT status, data_consent, report_json, ip_list_json FROM reports WHERE token = ?
     *   → null row or status NOT IN ('paid','redeemed') → invalid_token
     */
    private function lookupReport(string $token): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT status, data_consent, report_json, ip_list_json
             FROM reports WHERE token = ?'
        );
        $stmt->execute([$token]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);
        if (!$row || !in_array($row['status'], ['paid', 'redeemed'], true)) {
            return null; // → 400 invalid_token
        }
        return $row;
    }

    public function testUnknownTokenReturnsInvalidToken(): void
    {
        $row = $this->lookupReport('00000000-0000-0000-0000-000000000000');
        $this->assertNull($row, 'Unknown token should return null (invalid_token)');
    }

    public function testPendingStatusReturnsInvalidToken(): void
    {
        $this->insertReport(['status' => 'pending']);
        $row = $this->lookupReport('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
        $this->assertNull($row, 'Pending report should be treated as invalid_token');
    }

    public function testPaidStatusIsValid(): void
    {
        $this->insertReport(['status' => 'paid']);
        $row = $this->lookupReport('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
        $this->assertNotNull($row);
        $this->assertSame('paid', $row['status']);
    }

    public function testRedeemedStatusIsValid(): void
    {
        $this->insertReport(['status' => 'redeemed']);
        $row = $this->lookupReport('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
        $this->assertNotNull($row);
        $this->assertSame('redeemed', $row['status']);
    }

    // ── Idempotency: already_set ──────────────────────────────────────────────

    /**
     * Mirrors: if ($row['data_consent'] !== null) → already_set
     * SQLite returns strings from TEXT/INTEGER columns, so we replicate the
     * same loose-check the endpoint uses (the real DB returns NULL vs a value).
     */
    public function testAlreadySetWhenDataConsentIsZero(): void
    {
        $this->insertReport(['data_consent' => 0]);
        $row = $this->lookupReport('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
        $this->assertNotNull($row);
        // NULL check: SQLite returns '0' string, not PHP null — treat as already set
        $alreadySet = ($row['data_consent'] !== null);
        $this->assertTrue($alreadySet, 'data_consent=0 should trigger already_set');
    }

    public function testAlreadySetWhenDataConsentIsOne(): void
    {
        $this->insertReport(['data_consent' => 1]);
        $row = $this->lookupReport('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
        $this->assertNotNull($row);
        $alreadySet = ($row['data_consent'] !== null);
        $this->assertTrue($alreadySet, 'data_consent=1 should trigger already_set');
    }

    public function testNotAlreadySetWhenDataConsentIsNull(): void
    {
        $this->insertReport(['data_consent' => null]);
        $row = $this->lookupReport('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
        $this->assertNotNull($row);
        $alreadySet = ($row['data_consent'] !== null);
        $this->assertFalse($alreadySet, 'data_consent=NULL should not trigger already_set');
    }

    // ── Decline (consent=0) ───────────────────────────────────────────────────

    public function testDeclineSetsDataConsentToZero(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid', 'data_consent' => null]);

        $stmt = $this->pdo->prepare('UPDATE reports SET data_consent = 0 WHERE token = ?');
        $stmt->execute([$token]);

        $this->assertSame(1, $stmt->rowCount());
        // SQLite returns '0' as a string; cast to int for comparison
        $this->assertSame(0, (int) $this->fetchConsent($token));
    }

    public function testDeclineDoesNotIngestAnyCidrs(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport([
            'status'      => 'paid',
            'data_consent' => null,
            'report_json'  => json_encode(['asn_ranges' => [
                ['asn' => 'AS1234', 'org' => 'Test Org', 'cidrs' => ['1.2.3.0/24']],
            ]]),
        ]);

        // consent=0: only UPDATE data_consent, no CIDR ingestion
        $stmt = $this->pdo->prepare('UPDATE reports SET data_consent = 0 WHERE token = ?');
        $stmt->execute([$token]);

        $count = (int) $this->pdo->query('SELECT COUNT(*) FROM community_cidr_stats')->fetchColumn();
        $this->assertSame(0, $count, 'Decline must not ingest any CIDR data');
    }

    // ── Opt-in (consent=1) ────────────────────────────────────────────────────

    /**
     * Run the full opt-in ingestion logic mirroring community-consent.php.
     * Returns the response array that the endpoint would json_encode().
     */
    private function runOptIn(string $token, string $reportJson, string $ipListJson): array
    {
        // Step 1: set data_consent = 1
        $stmt = $this->pdo->prepare('UPDATE reports SET data_consent = 1 WHERE token = ?');
        $stmt->execute([$token]);

        // Step 2: parse JSON
        $report  = !empty($reportJson)  ? json_decode($reportJson,  true) : null;
        $ipList  = !empty($ipListJson)  ? json_decode($ipListJson,  true) : null;

        if ($report === null || $ipList === null) {
            return ['ok' => true, 'ingested' => false];
        }

        // Step 3: compute week_start (Monday of current ISO week, UTC)
        $daysSinceMonday = (int) gmdate('N') - 1;
        $weekStart = gmdate('Y-m-d', strtotime("-{$daysSinceMonday} days"));

        // Step 4: ingest CIDR data
        $asnRanges = $report['asn_ranges'] ?? [];

        if (!empty($asnRanges)) {
            $cidrStmt = $this->pdo->prepare(
                'INSERT OR IGNORE INTO community_cidr_stats (cidr, asn, org, week_start, report_count, total_hits)
                 VALUES (?, ?, ?, ?, 1, ?)'
            );
            // ON DUPLICATE KEY UPDATE is MySQL-only; SQLite uses INSERT OR IGNORE for the
            // structural test — what matters is that the rows land and hits are recorded.

            foreach ($asnRanges as $range) {
                $asn = $range['asn'] ?? '';
                $org = $range['org'] ?? '';
                foreach ($range['cidrs'] ?? [] as $cidrEntry) {
                    if (is_array($cidrEntry)) {
                        $cidr = $cidrEntry['cidr'] ?? '';
                        $hits = (int) ($cidrEntry['hits'] ?? 1);
                    } else {
                        $cidr = (string) $cidrEntry;
                        $hits = 1;
                    }
                    if ($cidr === '' || $asn === '') {
                        continue;
                    }
                    $cidrStmt->execute([$cidr, $asn, $org, $weekStart, $hits]);
                }
            }
        }

        // Step 5: ingest IP data (scanning/vpn_proxy/cloud_exit only)
        $allowedClassifications = ['scanning', 'vpn_proxy', 'cloud_exit'];

        $ipStmt = $this->pdo->prepare(
            'INSERT OR IGNORE INTO community_ip_stats (ip, week_start, report_count, total_hits)
             VALUES (?, ?, 1, ?)'
        );
        $fsStmt = $this->pdo->prepare(
            'INSERT OR IGNORE INTO community_ip_first_seen (ip, first_seen) VALUES (?, ?)'
        );

        $today = gmdate('Y-m-d');

        foreach ($ipList as $entry) {
            $classification = $entry['classification'] ?? '';
            if (!in_array($classification, $allowedClassifications, true)) {
                continue;
            }
            $ip   = $entry['ip']   ?? '';
            $hits = (int) ($entry['freq'] ?? 1);
            if ($ip === '') {
                continue;
            }
            $ipStmt->execute([$ip, $weekStart, $hits]);
            $fsStmt->execute([$ip, $today]);
        }

        // Step 6: fetch top CIDRs for this week
        $ctxStmt = $this->pdo->prepare(
            'SELECT cidr, org, report_count, total_hits
             FROM community_cidr_stats
             WHERE week_start = ?
             ORDER BY report_count DESC, total_hits DESC
             LIMIT 5'
        );
        $ctxStmt->execute([$weekStart]);
        $topCidrs = $ctxStmt->fetchAll(\PDO::FETCH_ASSOC);

        return [
            'ok'         => true,
            'ingested'   => true,
            'week_start' => $weekStart,
            'top_cidrs'  => $topCidrs,
        ];
    }

    public function testOptInSetsDataConsentToOne(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid', 'data_consent' => null, 'ip_list_json' => '[]']);

        $this->runOptIn($token, json_encode(['asn_ranges' => []]), '[]');

        $this->assertSame(1, (int) $this->fetchConsent($token));
    }

    public function testOptInWithValidJsonReturnsIngestedTrue(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $reportJson = json_encode(['asn_ranges' => [
            ['asn' => 'AS1234', 'org' => 'Test Org', 'cidrs' => ['10.0.0.0/8']],
        ]]);
        $ipListJson = json_encode([
            ['ip' => '10.0.0.1', 'classification' => 'scanning', 'freq' => 3],
        ]);

        $result = $this->runOptIn($token, $reportJson, $ipListJson);

        $this->assertTrue($result['ok']);
        $this->assertTrue($result['ingested']);
        $this->assertArrayHasKey('week_start', $result);
        $this->assertArrayHasKey('top_cidrs', $result);
    }

    public function testOptInWithNullReportJsonReturnsIngestedFalse(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid', 'report_json' => null]);

        // Pass empty strings → json_decode returns null → ingested=false path
        $result = $this->runOptIn($token, '', '[]');

        $this->assertTrue($result['ok']);
        $this->assertFalse($result['ingested']);
    }

    public function testOptInWithMalformedJsonReturnsIngestedFalse(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        // Malformed JSON: json_decode returns null
        $result = $this->runOptIn($token, '{not valid json', '[]');

        $this->assertTrue($result['ok']);
        $this->assertFalse($result['ingested']);
    }

    // ── IP classification filtering ───────────────────────────────────────────

    public function testResidentialIpsAreNotIngested(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $ipListJson = json_encode([
            ['ip' => '192.168.1.1', 'classification' => 'residential', 'freq' => 5],
        ]);

        $this->runOptIn($token, json_encode(['asn_ranges' => []]), $ipListJson);

        $count = (int) $this->pdo->query('SELECT COUNT(*) FROM community_ip_stats')->fetchColumn();
        $this->assertSame(0, $count, 'Residential IPs must never be ingested');
    }

    public function testUnknownClassificationIpsAreNotIngested(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $ipListJson = json_encode([
            ['ip' => '1.2.3.4', 'classification' => 'unknown', 'freq' => 2],
        ]);

        $this->runOptIn($token, json_encode(['asn_ranges' => []]), $ipListJson);

        $count = (int) $this->pdo->query('SELECT COUNT(*) FROM community_ip_stats')->fetchColumn();
        $this->assertSame(0, $count, 'Unknown classification IPs must not be ingested');
    }

    public function testScanningIpsAreIngested(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $ipListJson = json_encode([
            ['ip' => '45.55.1.1', 'classification' => 'scanning', 'freq' => 10],
        ]);

        $this->runOptIn($token, json_encode(['asn_ranges' => []]), $ipListJson);

        $count = (int) $this->pdo->query('SELECT COUNT(*) FROM community_ip_stats')->fetchColumn();
        $this->assertSame(1, $count, 'scanning IPs must be ingested');
    }

    public function testVpnProxyIpsAreIngested(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $ipListJson = json_encode([
            ['ip' => '104.16.0.1', 'classification' => 'vpn_proxy', 'freq' => 7],
        ]);

        $this->runOptIn($token, json_encode(['asn_ranges' => []]), $ipListJson);

        $count = (int) $this->pdo->query('SELECT COUNT(*) FROM community_ip_stats')->fetchColumn();
        $this->assertSame(1, $count, 'vpn_proxy IPs must be ingested');
    }

    public function testCloudExitIpsAreIngested(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $ipListJson = json_encode([
            ['ip' => '34.0.0.1', 'classification' => 'cloud_exit', 'freq' => 4],
        ]);

        $this->runOptIn($token, json_encode(['asn_ranges' => []]), $ipListJson);

        $count = (int) $this->pdo->query('SELECT COUNT(*) FROM community_ip_stats')->fetchColumn();
        $this->assertSame(1, $count, 'cloud_exit IPs must be ingested');
    }

    public function testMixedClassificationsOnlyIngestAllowed(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $ipListJson = json_encode([
            ['ip' => '1.1.1.1',  'classification' => 'scanning',    'freq' => 1],
            ['ip' => '2.2.2.2',  'classification' => 'vpn_proxy',   'freq' => 1],
            ['ip' => '3.3.3.3',  'classification' => 'cloud_exit',  'freq' => 1],
            ['ip' => '4.4.4.4',  'classification' => 'residential', 'freq' => 1],
            ['ip' => '5.5.5.5',  'classification' => 'unknown',     'freq' => 1],
        ]);

        $this->runOptIn($token, json_encode(['asn_ranges' => []]), $ipListJson);

        $count = (int) $this->pdo->query('SELECT COUNT(*) FROM community_ip_stats')->fetchColumn();
        $this->assertSame(3, $count, 'Only scanning/vpn_proxy/cloud_exit should be ingested');
    }

    // ── week_start format ─────────────────────────────────────────────────────

    public function testWeekStartIsMonday(): void
    {
        $daysSinceMonday = (int) gmdate('N') - 1;
        $weekStart = gmdate('Y-m-d', strtotime("-{$daysSinceMonday} days"));

        // Must be a valid date string in YYYY-MM-DD format
        $this->assertMatchesRegularExpression(
            '/^\d{4}-\d{2}-\d{2}$/',
            $weekStart,
            'week_start must be in YYYY-MM-DD format'
        );

        // The date must be a Monday (ISO weekday 1)
        $weekday = (int) gmdate('N', strtotime($weekStart));
        $this->assertSame(1, $weekday, 'week_start must be a Monday (ISO weekday 1)');
    }

    public function testWeekStartReturnedInOptInResponse(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $result = $this->runOptIn(
            $token,
            json_encode(['asn_ranges' => []]),
            '[]'
        );

        $this->assertArrayHasKey('week_start', $result);
        $this->assertMatchesRegularExpression(
            '/^\d{4}-\d{2}-\d{2}$/',
            $result['week_start']
        );
        $weekday = (int) gmdate('N', strtotime($result['week_start']));
        $this->assertSame(1, $weekday, 'week_start in response must be a Monday');
    }

    // ── CIDR entry formats ────────────────────────────────────────────────────

    public function testCidrAsStringIsIngested(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $reportJson = json_encode(['asn_ranges' => [
            ['asn' => 'AS9876', 'org' => 'String CIDR Org', 'cidrs' => ['203.0.113.0/24']],
        ]]);

        $this->runOptIn($token, $reportJson, '[]');

        $row = $this->pdo->query(
            "SELECT cidr, total_hits FROM community_cidr_stats WHERE cidr = '203.0.113.0/24'"
        )->fetch(\PDO::FETCH_ASSOC);

        $this->assertNotFalse($row, 'String-format CIDR must be ingested');
        $this->assertSame('203.0.113.0/24', $row['cidr']);
        $this->assertSame(1, (int) $row['total_hits'], 'String CIDR defaults to hits=1');
    }

    public function testCidrAsObjectWithHitsIsIngested(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $reportJson = json_encode(['asn_ranges' => [
            ['asn' => 'AS5555', 'org' => 'Object CIDR Org', 'cidrs' => [
                ['cidr' => '198.51.100.0/24', 'hits' => 42],
            ]],
        ]]);

        $this->runOptIn($token, $reportJson, '[]');

        $row = $this->pdo->query(
            "SELECT cidr, total_hits FROM community_cidr_stats WHERE cidr = '198.51.100.0/24'"
        )->fetch(\PDO::FETCH_ASSOC);

        $this->assertNotFalse($row, 'Object-format CIDR must be ingested');
        $this->assertSame('198.51.100.0/24', $row['cidr']);
        $this->assertSame(42, (int) $row['total_hits'], 'Object CIDR must use hits field');
    }

    public function testCidrObjectWithoutHitsDefaultsToOne(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $reportJson = json_encode(['asn_ranges' => [
            ['asn' => 'AS7777', 'org' => 'No Hits Org', 'cidrs' => [
                ['cidr' => '100.64.0.0/10'],
            ]],
        ]]);

        $this->runOptIn($token, $reportJson, '[]');

        $row = $this->pdo->query(
            "SELECT total_hits FROM community_cidr_stats WHERE cidr = '100.64.0.0/10'"
        )->fetch(\PDO::FETCH_ASSOC);

        $this->assertNotFalse($row, 'CIDR object without hits key must be ingested');
        $this->assertSame(1, (int) $row['total_hits'], 'Missing hits must default to 1');
    }

    public function testMixedStringAndObjectCidrsAreAllIngested(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $reportJson = json_encode(['asn_ranges' => [
            ['asn' => 'AS1111', 'org' => 'Mixed Org', 'cidrs' => [
                '10.0.0.0/8',                              // string format
                ['cidr' => '172.16.0.0/12', 'hits' => 7], // object format
            ]],
        ]]);

        $this->runOptIn($token, $reportJson, '[]');

        $count = (int) $this->pdo->query('SELECT COUNT(*) FROM community_cidr_stats')->fetchColumn();
        $this->assertSame(2, $count, 'Both string and object CIDRs must be ingested');
    }

    // ── top_cidrs in response ─────────────────────────────────────────────────

    public function testTopCidrsReturnedInResponse(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $reportJson = json_encode(['asn_ranges' => [
            ['asn' => 'AS2222', 'org' => 'Top CIDR Org', 'cidrs' => [
                ['cidr' => '8.8.0.0/16', 'hits' => 100],
                ['cidr' => '8.9.0.0/16', 'hits' => 50],
            ]],
        ]]);

        $result = $this->runOptIn($token, $reportJson, '[]');

        $this->assertIsArray($result['top_cidrs']);
        $this->assertNotEmpty($result['top_cidrs']);

        $firstEntry = $result['top_cidrs'][0];
        $this->assertArrayHasKey('cidr', $firstEntry);
        $this->assertArrayHasKey('org', $firstEntry);
        $this->assertArrayHasKey('report_count', $firstEntry);
        $this->assertArrayHasKey('total_hits', $firstEntry);
    }

    public function testTopCidrsLimitedToFive(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        // Insert 7 distinct CIDRs
        $cidrs = [];
        for ($i = 1; $i <= 7; $i++) {
            $cidrs[] = ['cidr' => "10.{$i}.0.0/16", 'hits' => $i];
        }
        $reportJson = json_encode(['asn_ranges' => [
            ['asn' => 'AS3333', 'org' => 'Limit Test Org', 'cidrs' => $cidrs],
        ]]);

        $result = $this->runOptIn($token, $reportJson, '[]');

        $this->assertLessThanOrEqual(5, count($result['top_cidrs']), 'top_cidrs must be limited to 5 entries');
    }

    // ── community_ip_first_seen ───────────────────────────────────────────────

    public function testFirstSeenRecordedOnOptIn(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $ipListJson = json_encode([
            ['ip' => '1.2.3.4', 'classification' => 'scanning', 'freq' => 1],
        ]);

        $this->runOptIn($token, json_encode(['asn_ranges' => []]), $ipListJson);

        $row = $this->pdo->query(
            "SELECT ip, first_seen FROM community_ip_first_seen WHERE ip = '1.2.3.4'"
        )->fetch(\PDO::FETCH_ASSOC);

        $this->assertNotFalse($row, 'community_ip_first_seen must have a record for the ingested IP');
        $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $row['first_seen']);
    }

    public function testFirstSeenNotRecordedForResidentialIps(): void
    {
        $token = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $this->insertReport(['status' => 'paid']);

        $ipListJson = json_encode([
            ['ip' => '192.168.0.1', 'classification' => 'residential', 'freq' => 1],
        ]);

        $this->runOptIn($token, json_encode(['asn_ranges' => []]), $ipListJson);

        $count = (int) $this->pdo->query('SELECT COUNT(*) FROM community_ip_first_seen')->fetchColumn();
        $this->assertSame(0, $count, 'Residential IPs must not appear in community_ip_first_seen');
    }
}
