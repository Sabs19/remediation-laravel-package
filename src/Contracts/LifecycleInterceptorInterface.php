<?php

namespace Develler\RemediationAgent\Contracts;

use Illuminate\Http\Request;
use Develler\RemediationAgent\DTOs\MaskRule;
use Symfony\Component\HttpFoundation\Response;

interface LifecycleInterceptorInterface
{
    /**
     * Hook into the inbound HTTP request.
     * Returns null to pass through, or a Response to short-circuit (route block).
     * Must never throw.
     */
    public function interceptRequest(Request $request): ?Response;

    /**
     * Hook into the outbound HTTP response.
     * Applies masking in memory before the response is dispatched. Never throws.
     */
    public function interceptResponse(Request $request, Response $response): Response;

    /**
     * Apply PII masking rules to an arbitrary data structure.
     * Operates on a deep clone — never mutates the original until masking is complete.
     *
     * @param  mixed      $data
     * @param  MaskRule[] $maskRules
     * @return mixed
     */
    public function applyMaskingRules(mixed $data, array $maskRules): mixed;

    /** Returns true when the circuit breaker is open (all interception bypassed). */
    public function isCircuitBreakerOpen(): bool;

    /** Trip the circuit breaker on Redis failure or unhandled exception. */
    public function tripCircuitBreaker(\Throwable $reason): void;

    /** Reset the circuit breaker manually (also resets automatically via Redis TTL). */
    public function resetCircuitBreaker(): void;
}
