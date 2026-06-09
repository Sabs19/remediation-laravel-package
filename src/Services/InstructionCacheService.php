<?php

namespace Develler\RemediationAgent\Services;

use Illuminate\Support\Facades\Redis;
use Develler\RemediationAgent\DTOs\InstructionCollection;
use Develler\RemediationAgent\DTOs\RuntimeInstruction;

/**
 * Reads and writes RuntimeInstructions from/to Redis.
 *
 * Storage strategy: one Redis STRING key per instruction, keyed by instruction_id,
 * with a TTL matching the instruction's expires_at. A Redis SET tracks active IDs
 * so getActive() can MGET all of them in a single roundtrip after SMEMBERS.
 *
 * Key namespace:
 *   remediation:instruction:{client_id}:{instruction_id}  → serialised instruction JSON
 *   remediation:active:{client_id}                        → SET of instruction IDs
 */
final class InstructionCacheService
{
    private string $indexKey;
    private string $connection;

    public function __construct(private readonly string $clientId)
    {
        $this->indexKey   = "remediation:active:{$clientId}";
        $this->connection = config('remediation.redis.connection', 'default');
    }

    public function store(RuntimeInstruction $instruction): void
    {
        $redis = Redis::connection($this->connection);
        $ttl   = max(1, $instruction->expiresAt - time());
        $key   = $this->instructionKey($instruction->instructionId);

        $redis->setex($key, $ttl, $instruction->toJson());

        // Add to the active index. The index member will outlive the instruction key
        // but MGET returns null for missing keys — those are filtered on read.
        $redis->sadd($this->indexKey, $instruction->instructionId);

        // Keep index TTL at least as long as the longest instruction.
        $currentTtl = $redis->ttl($this->indexKey);
        if ($currentTtl < $ttl) {
            $redis->expire($this->indexKey, $ttl + 60);
        }
    }

    /**
     * Return all currently active (non-expired) instructions.
     * Two Redis roundtrips: SMEMBERS → MGET. Total time <1ms on a local socket.
     */
    public function getActive(): InstructionCollection
    {
        $redis = Redis::connection($this->connection);
        $ids   = $redis->smembers($this->indexKey);

        if (empty($ids)) {
            return InstructionCollection::empty();
        }

        $keys   = array_map(fn (string $id) => $this->instructionKey($id), $ids);
        $values = $redis->mget($keys);

        $instructions = [];
        $staleIds     = [];

        foreach ($ids as $i => $id) {
            $json = $values[$i] ?? null;

            if ($json === null || $json === false) {
                $staleIds[] = $id;
                continue;
            }

            try {
                $instruction = RuntimeInstruction::fromJson($json);
                if ($instruction->isEffective()) {
                    $instructions[] = $instruction;
                }
            } catch (\Throwable) {
                $staleIds[] = $id;
            }
        }

        // Lazy cleanup — remove IDs whose keys have already expired.
        if (!empty($staleIds)) {
            $redis->srem($this->indexKey, ...$staleIds);
        }

        return new InstructionCollection($instructions);
    }

    public function evict(string $instructionId): void
    {
        $redis = Redis::connection($this->connection);
        $redis->del($this->instructionKey($instructionId));
        $redis->srem($this->indexKey, $instructionId);
    }

    private function instructionKey(string $instructionId): string
    {
        return "remediation:instruction:{$this->clientId}:{$instructionId}";
    }
}
