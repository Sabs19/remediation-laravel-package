<?php

namespace Develler\RemediationAgent\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Redis;
use Develler\RemediationAgent\Contracts\AgentConnectionInterface;
use Develler\RemediationAgent\DTOs\Envelope;
use Develler\RemediationAgent\DTOs\InstructionCollection;
use Develler\RemediationAgent\DTOs\RuntimeInstruction;
use Develler\RemediationAgent\Exceptions\ReplayException;
use Develler\RemediationAgent\Exceptions\SignatureException;
use Develler\RemediationAgent\Models\RemediationConnection;
use Develler\RemediationAgent\Models\RemediationInstructionLog;

final class AgentConnectionService implements AgentConnectionInterface
{
    private const PROTOCOL_MAJOR      = 1;
    private const NONCE_TTL           = 300;
    private const ISSUED_AT_TOLERANCE = 300;

    public function __construct(
        private readonly InstructionCacheService $cache,
    ) {}

    // -------------------------------------------------------------------------
    // AgentConnectionInterface
    // -------------------------------------------------------------------------

    public function verifyEnvelope(array $rawEnvelope): Envelope
    {
        $envelope = Envelope::fromArray($rawEnvelope);

        $this->assertProtocolVersion($envelope);
        $this->assertIssuedAtWindow($envelope);
        $this->assertClientId($envelope);
        $this->assertNonceUnique($envelope);
        $this->assertHmac($envelope);

        return $envelope;
    }

    public function cacheInstruction(RuntimeInstruction $instruction): void
    {
        $this->cache->store($instruction);

        RemediationInstructionLog::create([
            'instruction_id'   => $instruction->instructionId,
            'instruction_type' => $instruction->instructionType,
            'payload_hash'     => hash('sha256', $instruction->toJson()),
            'received_at'      => now(),
            'expires_at'       => now()->setTimestamp($instruction->expiresAt),
            'acknowledged'     => false,
        ]);
    }

    public function getActiveInstructions(): InstructionCollection
    {
        return $this->cache->getActive();
    }

    public function acknowledgeInstruction(string $instructionId): void
    {
        $connection = RemediationConnection::current();
        if ($connection === null) {
            return;
        }

        try {
            Http::withHeaders($this->authHeaders($connection))
                ->timeout(5)
                ->post(
                    rtrim($connection->saas_url, '/') . "/api/remediation/v1/instructions/{$instructionId}/acknowledge"
                );
        } catch (\Throwable $e) {
            Log::channel('remediation')->warning('RemediationEngine: acknowledge failed.', [
                'instruction_id' => $instructionId,
                'error'          => $e->getMessage(),
            ]);
        }

        RemediationInstructionLog::where('instruction_id', $instructionId)
            ->update(['acknowledged' => true]);
    }

    public function pollPendingInstructions(): InstructionCollection
    {
        $connection = RemediationConnection::current();
        if ($connection === null) {
            return InstructionCollection::empty();
        }

        try {
            $response = Http::withHeaders($this->authHeaders($connection))
                ->timeout(10)
                ->get(rtrim($connection->saas_url, '/') . rtrim($connection->poll_url ?? '/api/remediation/v1/instructions/pending', '/'));

            if (!$response->successful()) {
                return InstructionCollection::empty();
            }

            $instructions = [];
            foreach ($response->json('instructions', []) as $raw) {
                // Each item from the poll endpoint is a full signed envelope.
                try {
                    $envelope     = $this->verifyEnvelope($raw);
                    $instruction  = RuntimeInstruction::fromArray($envelope->payload);
                    $this->cacheInstruction($instruction);
                    $this->acknowledgeInstruction($instruction->instructionId);
                    $instructions[] = $instruction;
                } catch (\Throwable $e) {
                    Log::channel('remediation')->error('RemediationEngine: poll envelope verification failed.', [
                        'error' => $e->getMessage(),
                    ]);
                }
            }

            return new InstructionCollection($instructions);
        } catch (\Throwable $e) {
            Log::channel('remediation')->error('RemediationEngine: poll failed.', ['error' => $e->getMessage()]);
            return InstructionCollection::empty();
        }
    }

    // -------------------------------------------------------------------------
    // Verification helpers
    // -------------------------------------------------------------------------

    /** @throws SignatureException */
    private function assertProtocolVersion(Envelope $envelope): void
    {
        if ($envelope->majorVersion() !== self::PROTOCOL_MAJOR) {
            throw new SignatureException(
                "Unsupported protocol major version: {$envelope->protocolVersion}"
            );
        }
    }

    /** @throws SignatureException */
    private function assertIssuedAtWindow(Envelope $envelope): void
    {
        $delta = abs(time() - $envelope->issuedAt);
        if ($delta > self::ISSUED_AT_TOLERANCE) {
            throw new SignatureException(
                "Envelope issued_at out of tolerance window ({$delta}s)."
            );
        }
    }

    /** @throws SignatureException */
    private function assertClientId(Envelope $envelope): void
    {
        $connection = RemediationConnection::current();
        if ($connection === null || $connection->client_id !== $envelope->clientId) {
            throw new SignatureException('client_id mismatch.');
        }
    }

    /**
     * Redis SET NX with ISSUED_AT_TOLERANCE TTL — atomic deduplication.
     *
     * @throws ReplayException
     */
    private function assertNonceUnique(Envelope $envelope): void
    {
        $connection = config('remediation.redis.connection', 'default');
        $nonceKey   = "remediation:nonce:{$envelope->clientId}:{$envelope->nonce}";

        try {
            $set = Redis::connection($connection)->set(
                $nonceKey,
                '1',
                'EX',
                self::NONCE_TTL,
                'NX'
            );

            if ($set === null || $set === false) {
                throw new ReplayException("Replayed nonce detected: {$envelope->nonce}");
            }
        } catch (ReplayException $e) {
            throw $e;
        } catch (\Throwable $e) {
            // Redis unavailable — treat as non-replay to avoid rejecting legitimate
            // instructions during a Redis outage. The circuit breaker handles safety.
            Log::channel('remediation')->warning('RemediationEngine: nonce Redis unavailable, skipping dedup.', [
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Recompute HMAC-SHA256 over the canonical string and constant-time compare.
     *
     * @throws SignatureException
     */
    private function assertHmac(Envelope $envelope): void
    {
        $connection = RemediationConnection::current();
        if ($connection === null) {
            throw new SignatureException('No active agent connection — cannot verify HMAC.');
        }

        $rawToken  = $connection->rawToken();
        $canonical = implode('.', [
            $envelope->protocolVersion,
            $envelope->messageId,
            $envelope->messageType,
            $envelope->clientId,
            (string) $envelope->issuedAt,
            $envelope->nonce,
            $this->base64url(json_encode($this->sortKeysRecursive($envelope->payload), JSON_THROW_ON_ERROR)),
        ]);

        $expected = hash_hmac('sha256', $canonical, $rawToken);

        if (!hash_equals($expected, strtolower($envelope->hmacSha256))) {
            throw new SignatureException('HMAC verification failed.');
        }
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    private function sortKeysRecursive(array $data): array
    {
        ksort($data);
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->sortKeysRecursive($value);
            }
        }
        return $data;
    }

    private function base64url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /** @return array<string,string> */
    private function authHeaders(RemediationConnection $connection): array
    {
        return [
            'X-Remediation-Client-Id' => $connection->client_id,
            'X-Remediation-Token'     => $connection->rawToken(),
        ];
    }
}
