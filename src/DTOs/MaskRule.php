<?php

namespace Develler\RemediationAgent\DTOs;

final class MaskRule
{
    public function __construct(
        public readonly string  $ruleId,
        public readonly string  $key,
        public readonly string  $matchType,      // 'exact' | 'regex'
        public readonly string  $maskStrategy,   // 'partial_last4' | 'email_domain_only' | 'last4_only' | 'full_redact' | 'hash_stable'
        public readonly ?string $pattern,        // regex pattern when matchType === 'regex'
        public readonly string  $maskChar,
        public readonly string  $separator,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            ruleId:       (string)  ($data['rule_id']      ?? ''),
            key:          (string)  ($data['key']          ?? ''),
            matchType:    (string)  ($data['match_type']   ?? 'exact'),
            maskStrategy: (string)  ($data['mask_strategy'] ?? 'full_redact'),
            pattern:      isset($data['pattern']) ? (string) $data['pattern'] : null,
            maskChar:     (string)  ($data['mask_char']    ?? 'X'),
            separator:    (string)  ($data['separator']    ?? '-'),
        );
    }

    public function matchesKey(string $key): bool
    {
        if ($this->matchType === 'exact') {
            return $this->key === $key;
        }

        if ($this->matchType === 'regex' && $this->pattern !== null) {
            return (bool) @preg_match($this->pattern, $key);
        }

        return false;
    }
}
