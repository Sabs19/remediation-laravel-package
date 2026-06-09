<?php

namespace Develler\RemediationAgent\DTOs;

final class ExtractionTarget
{
    public function __construct(
        public readonly string $filePath,
        public readonly string $symbolName,
        public readonly string $symbolType,  // 'method' | 'function' | 'class' | 'route'
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            filePath:   (string) ($data['file_path']   ?? ''),
            symbolName: (string) ($data['symbol_name'] ?? ''),
            symbolType: (string) ($data['symbol_type'] ?? 'method'),
        );
    }
}
