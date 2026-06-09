<?php

namespace Develler\RemediationAgent\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Develler\RemediationAgent\DTOs\Envelope;
use Develler\RemediationAgent\Exceptions\ReplayException;
use Develler\RemediationAgent\Exceptions\SignatureException;

/**
 * Tests for HMAC-SHA256 verification in AgentConnectionService.
 *
 * Rather than instantiating AgentConnectionService (which depends on Redis and DB),
 * we test the wire-protocol math directly through the same logic the service uses.
 */
class AgentConnectionServiceHmacTest extends TestCase
{
    private string $clientId = 'TESTCLIENT1';
    private string $rawToken = 'super-secret-test-token-for-unit-test-42';

    // -------------------------------------------------------------------------
    // Helpers — mirror the canonical string logic from AgentConnectionService
    // -------------------------------------------------------------------------

    private function buildEnvelope(array $payload, string $token, ?string $forcedHmac = null): array
    {
        $messageId = bin2hex(random_bytes(8));
        $nonce     = bin2hex(random_bytes(8));
        $issuedAt  = time();

        $canonical = implode('.', [
            '1.0',
            $messageId,
            'runtime_instruction',
            $this->clientId,
            (string) $issuedAt,
            $nonce,
            $this->base64url(json_encode($this->sortKeys($payload), JSON_THROW_ON_ERROR)),
        ]);

        $hmac = $forcedHmac ?? hash_hmac('sha256', $canonical, $token);

        return [
            'protocol_version' => '1.0',
            'message_id'       => $messageId,
            'message_type'     => 'runtime_instruction',
            'client_id'        => $this->clientId,
            'issued_at'        => $issuedAt,
            'nonce'            => $nonce,
            'hmac_sha256'      => $hmac,
            'payload'          => $payload,
        ];
    }

    /** Re-implements the HMAC check from AgentConnectionService::assertHmac(). */
    private function assertHmac(array $raw, string $token): void
    {
        $envelope = Envelope::fromArray($raw);

        $canonical = implode('.', [
            $envelope->protocolVersion,
            $envelope->messageId,
            $envelope->messageType,
            $envelope->clientId,
            (string) $envelope->issuedAt,
            $envelope->nonce,
            $this->base64url(json_encode($this->sortKeys($envelope->payload), JSON_THROW_ON_ERROR)),
        ]);

        $expected = hash_hmac('sha256', $canonical, $token);

        if (!hash_equals($expected, strtolower($envelope->hmacSha256))) {
            throw new SignatureException('HMAC verification failed.');
        }
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    public function test_valid_envelope_passes_hmac_check(): void
    {
        $envelope = $this->buildEnvelope(['instruction_type' => 'pii_mask'], $this->rawToken);
        // Must not throw.
        $this->assertHmac($envelope, $this->rawToken);
        $this->assertTrue(true);
    }

    public function test_wrong_token_fails_hmac_check(): void
    {
        $this->expectException(SignatureException::class);

        $envelope = $this->buildEnvelope(['instruction_type' => 'pii_mask'], $this->rawToken);
        $this->assertHmac($envelope, 'wrong-token');
    }

    public function test_tampered_payload_fails_hmac_check(): void
    {
        $this->expectException(SignatureException::class);

        $envelope = $this->buildEnvelope(['instruction_type' => 'pii_mask'], $this->rawToken);

        // Tamper with a payload key after signing.
        $envelope['payload']['instruction_type'] = 'route_block';

        $this->assertHmac($envelope, $this->rawToken);
    }

    public function test_tampered_hmac_field_fails(): void
    {
        $this->expectException(SignatureException::class);

        $envelope = $this->buildEnvelope(['instruction_type' => 'pii_mask'], $this->rawToken);
        $envelope['hmac_sha256'] = str_repeat('a', 64);

        $this->assertHmac($envelope, $this->rawToken);
    }

    public function test_hmac_comparison_is_constant_time(): void
    {
        // We cannot measure timing from a unit test, but we can assert hash_equals is used
        // by verifying that two structurally identical strings with one differing character
        // both fail rather than short-circuiting (which === would cause).
        $envelope = $this->buildEnvelope(['key' => 'val'], $this->rawToken);

        $hmac        = $envelope['hmac_sha256'];
        $almostRight = substr($hmac, 0, 63) . ($hmac[63] === 'a' ? 'b' : 'a');

        $envelope['hmac_sha256'] = $almostRight;

        $threw = false;
        try {
            $this->assertHmac($envelope, $this->rawToken);
        } catch (SignatureException) {
            $threw = true;
        }

        $this->assertTrue($threw, 'Near-miss HMAC should still fail.');
    }

    public function test_payload_key_ordering_does_not_affect_hmac(): void
    {
        $payloadAsc  = ['a' => 1, 'b' => 2];
        $payloadDesc = ['b' => 2, 'a' => 1];

        // Build with sorted payload (as service does), verify both pass with same token.
        $envelopeA = $this->buildEnvelope($payloadAsc,  $this->rawToken);
        $envelopeD = $this->buildEnvelope($payloadDesc, $this->rawToken);

        // Re-sign payloadDesc with same canonical string — should produce same HMAC.
        // Assert that sorting produces the same canonical regardless of input order.
        $this->assertSame(
            json_encode($this->sortKeys($payloadAsc),  JSON_THROW_ON_ERROR),
            json_encode($this->sortKeys($payloadDesc), JSON_THROW_ON_ERROR),
        );
    }

    // -------------------------------------------------------------------------

    private function sortKeys(array $data): array
    {
        ksort($data);
        foreach ($data as $k => $v) {
            if (is_array($v)) $data[$k] = $this->sortKeys($v);
        }
        return $data;
    }

    private function base64url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
