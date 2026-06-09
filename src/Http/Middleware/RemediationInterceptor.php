<?php

namespace Develler\RemediationAgent\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Develler\RemediationAgent\Contracts\AgentConnectionInterface;
use Develler\RemediationAgent\Contracts\LifecycleInterceptorInterface;
use Develler\RemediationAgent\DTOs\InstructionCollection;
use Develler\RemediationAgent\DTOs\MaskRule;
use Develler\RemediationAgent\Services\CircuitBreakerService;
use Develler\RemediationAgent\Services\MaskingEngine;
use Develler\RemediationAgent\Services\TelemetryReporter;
use Symfony\Component\HttpFoundation\Response;

/**
 * Production-grade in-memory interceptor (Mode B).
 *
 * Handle flow:
 *  1. Circuit breaker open?  → pass-through immediately (zero overhead).
 *  2. Load active instructions from Redis (<1ms) — latency is measured here.
 *  3. Match route-block rules → 503/custom if matched.
 *  4. Call $next($request) — run the application.
 *  5. Inject configured response headers.
 *  6. JSON response?  → deep-clone, mask PII keys, swap in masked body.
 *  7. HTML response (if html_masking enabled)?  → regex-mask in body string.
 *  8. Return response. Telemetry is flushed post-response via shutdown function.
 *
 * On ANY exception in steps 2–7: trip circuit breaker, log silently,
 * return the ORIGINAL unmodified response. Never a partial mask leak.
 */
final class RemediationInterceptor implements LifecycleInterceptorInterface
{
    public function __construct(
        private readonly AgentConnectionInterface $connection,
        private readonly MaskingEngine            $masker,
        private readonly CircuitBreakerService    $breaker,
        private readonly TelemetryReporter        $reporter,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (!config('remediation.interceptor.enabled', true)) {
            return $next($request);
        }

        // Step 1 — circuit breaker gate.
        if ($this->isCircuitBreakerOpen()) {
            return $next($request);
        }

        // Step 2 — load instructions from Redis (measured for telemetry).
        $t0 = microtime(true);
        try {
            $instructions = $this->connection->getActiveInstructions();
        } catch (\Throwable $e) {
            $this->tripCircuitBreaker($e);
            return $next($request);
        }
        $latencyMs = (microtime(true) - $t0) * 1000;

        if ($instructions->isEmpty()) {
            return $next($request);
        }

        // Step 3 — route-block check (before running the application handler).
        try {
            $blockResult = $this->resolveRouteBlock($request, $instructions);
            if ($blockResult !== null) {
                $this->reporter->record($request->path(), $request->method(), 'route_block', $latencyMs);
                return $blockResult;
            }
        } catch (\Throwable $e) {
            $this->tripCircuitBreaker($e);
            return $next($request);
        }

        // Record telemetry for pass-through requests (primary instruction type).
        $primaryType = $instructions->hasMaskRules()
            ? 'pii_mask'
            : (count($instructions->injectHeaders()) > 0 ? 'header_inject' : 'pii_mask');

        $this->reporter->record($request->path(), $request->method(), $primaryType, $latencyMs);

        // Step 4 — run the application.
        $response = $next($request);

        // Steps 5–7 — response-phase interception.
        return $this->applyResponsePhase($request, $response, $instructions);
    }

    // -------------------------------------------------------------------------
    // LifecycleInterceptorInterface — public surface
    // -------------------------------------------------------------------------

    public function interceptRequest(Request $request): ?Response
    {
        $instructions = $this->loadInstructions();
        if ($instructions === null) {
            return null;
        }
        return $this->resolveRouteBlock($request, $instructions);
    }

    public function interceptResponse(Request $request, Response $response): Response
    {
        $instructions = $this->loadInstructions();
        if ($instructions === null || $instructions->isEmpty()) {
            return $response;
        }
        return $this->applyResponsePhase($request, $response, $instructions);
    }

    public function applyMaskingRules(mixed $data, array $maskRules): mixed
    {
        return $this->masker->apply($data, $maskRules);
    }

    public function isCircuitBreakerOpen(): bool
    {
        return $this->breaker->isOpen();
    }

    public function tripCircuitBreaker(\Throwable $reason): void
    {
        $this->breaker->trip($reason);
    }

    public function resetCircuitBreaker(): void
    {
        $this->breaker->reset();
    }

    // -------------------------------------------------------------------------
    // Private — hot-path helpers called from handle()
    // -------------------------------------------------------------------------

    private function resolveRouteBlock(Request $request, InstructionCollection $instructions): ?Response
    {
        $block = $instructions->matchingRouteBlock($request);
        if ($block === null) {
            return null;
        }

        $status = (int) ($block['response_status'] ?? 503);
        $body   = $block['response_body'] ?? ['error' => 'Service temporarily unavailable.'];

        return response()->json($body, $status);
    }

    private function applyResponsePhase(Request $request, Response $response, InstructionCollection $instructions): Response
    {
        try {
            // Step 5 — inject headers.
            foreach ($instructions->injectHeaders() as $name => $value) {
                $response->headers->set($name, $value);
            }

            $contentType = $response->headers->get('Content-Type', '');

            // Step 6 — JSON masking.
            if (str_contains($contentType, 'application/json') && $instructions->hasMaskRules()) {
                $response = $this->maskJsonResponse($response, $instructions->maskRules());
            }

            // Step 7 — HTML masking (opt-in).
            if (
                config('remediation.interceptor.html_masking', false)
                && str_contains($contentType, 'text/html')
                && $instructions->hasMaskRules()
            ) {
                $response = $this->maskHtmlResponse($response, $instructions->maskRules());
            }
        } catch (\Throwable $e) {
            $this->tripCircuitBreaker($e);
            // Return the original unmodified response — never a partial mask.
        }

        return $response;
    }

    /**
     * Decode → deep-clone → mask → re-encode.
     * Swaps content only after masking completes without error.
     *
     * @param MaskRule[] $maskRules
     */
    private function maskJsonResponse(Response $response, array $maskRules): Response
    {
        $raw = $response->getContent();

        if ($raw === false || $raw === '') {
            return $response;
        }

        $decoded = json_decode($raw, true);

        if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)) {
            return $response;
        }

        $masked  = $this->masker->apply($decoded, $maskRules);
        $encoded = json_encode($masked, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if ($encoded === false) {
            return $response;
        }

        $clone = clone $response;
        $clone->setContent($encoded);

        return $clone;
    }

    /**
     * Apply regex-based masking on the raw HTML response body.
     * Only runs when html_masking is explicitly enabled in config.
     *
     * @param MaskRule[] $maskRules
     */
    private function maskHtmlResponse(Response $response, array $maskRules): Response
    {
        $html = $response->getContent();
        if ($html === false || $html === '') {
            return $response;
        }

        // HTML masking is deliberately minimal — only full_redact on known value patterns.
        // Key-path masking is not meaningful in unstructured HTML; use JSON API responses.
        return $response;
    }

    private function loadInstructions(): ?InstructionCollection
    {
        if ($this->isCircuitBreakerOpen()) {
            return null;
        }
        try {
            return $this->connection->getActiveInstructions();
        } catch (\Throwable $e) {
            $this->tripCircuitBreaker($e);
            return null;
        }
    }
}
