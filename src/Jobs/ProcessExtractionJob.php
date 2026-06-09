<?php

namespace Develler\RemediationAgent\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Develler\RemediationAgent\DTOs\ExtractionRequestPayload;
use Develler\RemediationAgent\Services\AstExtractorService;

final class ProcessExtractionJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries   = 3;
    public int $timeout = 120;

    public function __construct(
        private readonly string $saasBaseUrl,
        private readonly string $clientId,
        private readonly string $rawToken,
        private readonly ExtractionRequestPayload $request,
    ) {}

    public function handle(AstExtractorService $extractor): void
    {
        $results = [];

        foreach ($this->request->targets as $target) {
            // Resolve file path relative to base_path() in the host application.
            $absolutePath = base_path($target->filePath);

            $result = $extractor->extract($absolutePath, $target);

            if ($result === null) {
                Log::channel('remediation')->warning('AstExtractor: symbol not found.', [
                    'file'   => $target->filePath,
                    'symbol' => $target->symbolName,
                ]);
                continue;
            }

            $results[] = $result->toArray();
        }

        if (empty($results)) {
            Log::channel('remediation')->error('ProcessExtraction: no results extracted.', [
                'extraction_id' => $this->request->extractionId,
            ]);
            return;
        }

        $callbackUrl = rtrim($this->saasBaseUrl, '/') . $this->request->callbackUrl;

        Http::withHeaders([
            'X-Remediation-Client-Id' => $this->clientId,
            'X-Remediation-Token'     => $this->rawToken,
        ])
            ->timeout(30)
            ->retry(3, 1000)
            ->post($callbackUrl, ['results' => $results])
            ->throw();
    }

    public function failed(\Throwable $exception): void
    {
        Log::channel('remediation')->error('ProcessExtractionJob failed.', [
            'extraction_id' => $this->request->extractionId,
            'error'         => $exception->getMessage(),
        ]);
    }
}
