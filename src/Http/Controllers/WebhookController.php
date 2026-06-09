<?php

namespace Develler\RemediationAgent\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Log;
use Develler\RemediationAgent\Contracts\AgentConnectionInterface;
use Develler\RemediationAgent\DTOs\ExtractionRequestPayload;
use Develler\RemediationAgent\DTOs\RuntimeInstruction;
use Develler\RemediationAgent\Exceptions\ReplayException;
use Develler\RemediationAgent\Exceptions\SignatureException;
use Develler\RemediationAgent\Jobs\ProcessExtractionJob;
use Develler\RemediationAgent\Models\RemediationConnection;

/**
 * Receives signed envelopes pushed by the SaaS.
 *
 * Authentication is entirely via HMAC verification inside AgentConnectionService.
 * Any failure returns a generic 400 — no oracle detail exposed.
 *
 * Supported message_types:
 *   runtime_instruction  → cache the instruction for RemediationInterceptor
 *   extraction_request   → dispatch ProcessExtractionJob
 */
final class WebhookController extends Controller
{
    public function __construct(private readonly AgentConnectionInterface $connection) {}

    public function receive(Request $request): JsonResponse
    {
        if (!config('remediation.webhook.enabled', true)) {
            return response()->json(['error' => 'Webhook disabled.'], 404);
        }

        $raw = $request->json()->all();

        try {
            $envelope = $this->connection->verifyEnvelope($raw);
        } catch (SignatureException | ReplayException $e) {
            Log::channel('remediation')->warning('RemediationEngine: webhook verification failed.', [
                'error' => $e->getMessage(),
                'class' => get_class($e),
            ]);
            return response()->json(['error' => 'Bad request.'], 400);
        } catch (\Throwable $e) {
            Log::channel('remediation')->error('RemediationEngine: webhook error.', [
                'error' => $e->getMessage(),
            ]);
            return response()->json(['error' => 'Internal error.'], 500);
        }

        return match ($envelope->messageType) {
            'runtime_instruction' => $this->handleInstruction($envelope->payload),
            'extraction_request'  => $this->handleExtractionRequest($envelope->payload),
            default               => response()->json(['error' => 'Unknown message_type.'], 400),
        };
    }

    private function handleInstruction(array $payload): JsonResponse
    {
        try {
            $instruction = RuntimeInstruction::fromArray($payload);
            $this->connection->cacheInstruction($instruction);
            $this->connection->acknowledgeInstruction($instruction->instructionId);
        } catch (\Throwable $e) {
            Log::channel('remediation')->error('RemediationEngine: instruction processing error.', [
                'error' => $e->getMessage(),
            ]);
            return response()->json(['error' => 'Internal error.'], 500);
        }

        return response()->json(['status' => 'accepted'], 200);
    }

    private function handleExtractionRequest(array $payload): JsonResponse
    {
        try {
            $extractionPayload = ExtractionRequestPayload::fromPayload($payload);

            $connection = RemediationConnection::current();
            if ($connection === null) {
                return response()->json(['error' => 'Not connected.'], 503);
            }

            ProcessExtractionJob::dispatch(
                config('remediation.saas_url'),
                $connection->client_id,
                $connection->rawToken(),
                $extractionPayload,
            );
        } catch (\Throwable $e) {
            Log::channel('remediation')->error('RemediationEngine: extraction dispatch error.', [
                'error' => $e->getMessage(),
            ]);
            return response()->json(['error' => 'Internal error.'], 500);
        }

        return response()->json(['status' => 'queued'], 202);
    }
}
