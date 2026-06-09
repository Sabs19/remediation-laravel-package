<?php

namespace Develler\RemediationAgent\DTOs;

final class ExtractionRequestPayload
{
    /** @param ExtractionTarget[] $targets */
    public function __construct(
        public readonly string $extractionId,
        public readonly string $extractionType,
        public readonly array  $targets,         // ExtractionTarget[]
        public readonly string $callbackUrl,
        public readonly bool   $includeAst         = true,
        public readonly bool   $includeDocblock     = true,
        public readonly bool   $includeLineNumbers  = true,
        public readonly int    $maxLinesPerSymbol   = 500,
    ) {}

    public static function fromPayload(array $payload): self
    {
        $targets = array_map(
            static fn (array $t): ExtractionTarget => ExtractionTarget::fromArray($t),
            (array) ($payload['targets'] ?? [])
        );

        return new self(
            extractionId:       (string) ($payload['extraction_id']       ?? ''),
            extractionType:     (string) ($payload['extraction_type']     ?? 'generic'),
            targets:            $targets,
            callbackUrl:        (string) ($payload['callback_url']        ?? ''),
            includeAst:         (bool)   ($payload['include_ast']         ?? true),
            includeDocblock:    (bool)   ($payload['include_docblock']    ?? true),
            includeLineNumbers: (bool)   ($payload['include_line_numbers'] ?? true),
            maxLinesPerSymbol:  (int)    ($payload['max_lines_per_symbol'] ?? 500),
        );
    }
}
