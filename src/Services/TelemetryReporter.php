<?php

namespace Develler\RemediationAgent\Services;

use Develler\RemediationAgent\Models\RemediationConnection;
use Illuminate\Support\Facades\Http;

/**
 * Fire-and-forget telemetry reporter.
 *
 * Events are buffered in a static array and flushed via register_shutdown_function
 * after the response has been sent to the client (uses fastcgi_finish_request when
 * available, otherwise runs at PHP shutdown — still safe, just slightly later).
 *
 * All failures are silently swallowed — telemetry must never affect the application.
 */
class TelemetryReporter
{
    private static array $buffer     = [];
    private static bool  $registered = false;

    public function record(
        string $route,
        string $method,
        string $instructionType,
        float  $latencyMs,
    ): void {
        static::$buffer[] = [
            'route'            => $route,
            'method'           => strtoupper($method),
            'instruction_type' => $instructionType,
            'latency_ms'       => round($latencyMs, 3),
            'applied_at'       => now()->toIso8601String(),
        ];

        if (!static::$registered) {
            static::$registered = true;
            register_shutdown_function(fn () => $this->flush());
        }
    }

    private function flush(): void
    {
        if (empty(static::$buffer)) {
            return;
        }

        $events         = static::$buffer;
        static::$buffer = [];

        // Release the HTTP connection so the client gets its response first.
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        }

        try {
            $connection = RemediationConnection::current();
            if ($connection === null) {
                return;
            }

            Http::withOptions(['connect_timeout' => 0.5, 'timeout' => 2])
                ->withHeaders([
                    'X-Remediation-Client-Id' => $connection->client_id,
                    'X-Remediation-Token'     => $connection->rawToken(),
                ])
                ->post("{$connection->saas_url}/api/remediation/v1/telemetry", [
                    'events' => $events,
                ]);
        } catch (\Throwable) {
            // Telemetry is best-effort — never throw.
        }
    }
}
