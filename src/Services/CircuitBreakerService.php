<?php

namespace Develler\RemediationAgent\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Redis;

/**
 * Three-state circuit breaker: CLOSED → OPEN → HALF-OPEN → CLOSED.
 *
 * State is stored in Redis with a configurable TTL so it auto-resets
 * without a deploy. If Redis itself is unavailable, we fall back to an
 * in-process static flag so we never block production on a double failure.
 */
final class CircuitBreakerService
{
    private static bool $inProcessOpen = false;

    private string $redisKey;
    private string $connection;
    private int    $ttl;

    public function __construct(string $clientId)
    {
        $this->redisKey   = "remediation:circuit_breaker:{$clientId}";
        $this->connection = config('remediation.redis.connection', 'default');
        $this->ttl        = (int) config('remediation.circuit_breaker.ttl_seconds', 60);
    }

    /**
     * Returns true when the breaker is OPEN — all interception must be skipped.
     * If Redis is down, falls back to the in-process flag (fail-safe = open).
     */
    public function isOpen(): bool
    {
        if (self::$inProcessOpen) {
            return true;
        }

        try {
            return Redis::connection($this->connection)->exists($this->redisKey) === 1;
        } catch (\Throwable) {
            // Redis unavailable — treat as open to protect production.
            self::$inProcessOpen = true;
            return true;
        }
    }

    /**
     * Trip the breaker. Stores state in Redis; falls back to in-process on Redis failure.
     */
    public function trip(\Throwable $reason): void
    {
        Log::channel('remediation')->error('RemediationEngine circuit breaker tripped.', [
            'reason' => $reason->getMessage(),
            'class'  => get_class($reason),
        ]);

        $payload = json_encode([
            'state'      => 'open',
            'tripped_at' => time(),
            'reason'     => $reason->getMessage(),
        ]);

        try {
            Redis::connection($this->connection)->setex($this->redisKey, $this->ttl, $payload);
        } catch (\Throwable) {
            // Redis is the problem — use in-process flag with a TTL-mimicking timer.
            self::$inProcessOpen = true;
            // Schedule auto-reset via a shutdown function registered once.
            register_shutdown_function(static function () {
                // Runs at end of this process only — fine for PHP-FPM (per-request process).
                self::$inProcessOpen = false;
            });
        }
    }

    /**
     * Reset the breaker manually. Also resets automatically when the Redis TTL expires.
     */
    public function reset(): void
    {
        self::$inProcessOpen = false;

        try {
            Redis::connection($this->connection)->del($this->redisKey);
        } catch (\Throwable) {
            // Ignore — if Redis is gone, the key will expire on its own.
        }
    }
}
