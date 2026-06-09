<?php

namespace Develler\RemediationAgent\DTOs;

final class ExtractionResult
{
    public function __construct(
        public readonly string $filePath,
        public readonly int    $startLine,
        public readonly int    $endLine,
        public readonly string $sourceCode,
        public readonly string $symbolName,
        public readonly string $symbolType,
        public readonly ?string $docBlock,
    ) {}

    public function toArray(): array
    {
        return [
            'file_path'   => $this->filePath,
            'start_line'  => $this->startLine,
            'end_line'    => $this->endLine,
            'source_code' => $this->sourceCode,
            'symbol_name' => $this->symbolName,
            'symbol_type' => $this->symbolType,
            'doc_block'   => $this->docBlock,
        ];
    }
}
