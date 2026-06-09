<?php

namespace Develler\RemediationAgent\Services;

use Develler\RemediationAgent\DTOs\MaskRule;

/**
 * Pure stateless masking engine — no I/O, no Redis, no logging.
 *
 * Applies PII masking rules to an arbitrary data structure via deep recursive
 * traversal. All mutations happen on a deep clone of the input; the original
 * is never touched until the full masked copy is ready to be returned.
 *
 * Supported strategies:
 *   partial_last4      — keeps last 4 digits, masks the rest (phone numbers)
 *   email_domain_only  — masks local part, keeps @domain
 *   last4_only         — keeps last 4 digits only (credit cards)
 *   full_redact        — replaces value with '[REDACTED]'
 *   hash_stable        — deterministic SHA-256 truncated to 16 hex chars
 */
final class MaskingEngine
{
    private const MAX_DEPTH = 20;

    /** @param MaskRule[] $rules */
    public function apply(mixed $data, array $rules): mixed
    {
        if (empty($rules)) {
            return $data;
        }

        // Deep clone via JSON round-trip — cheapest in PHP for mixed structures.
        $clone = json_decode(json_encode($data), true);

        return $this->traverse($clone, $rules, 0);
    }

    // -------------------------------------------------------------------------

    private function traverse(mixed $data, array $rules, int $depth): mixed
    {
        if ($depth > self::MAX_DEPTH) {
            return $data;
        }

        if (!is_array($data)) {
            return $data;
        }

        foreach ($data as $key => $value) {
            $matchedRule = $this->findMatchingRule((string) $key, $rules);

            if ($matchedRule !== null && !is_array($value) && $value !== null) {
                $data[$key] = $this->maskValue($value, $matchedRule);
            } elseif (is_array($value)) {
                $data[$key] = $this->traverse($value, $rules, $depth + 1);
            }
        }

        return $data;
    }

    /** @param MaskRule[] $rules */
    private function findMatchingRule(string $key, array $rules): ?MaskRule
    {
        foreach ($rules as $rule) {
            if ($rule->matchesKey($key)) {
                return $rule;
            }
        }
        return null;
    }

    private function maskValue(mixed $value, MaskRule $rule): string
    {
        $str = (string) $value;

        return match ($rule->maskStrategy) {
            'partial_last4'     => $this->maskPartialLast4($str, $rule->maskChar, $rule->separator),
            'email_domain_only' => $this->maskEmailDomainOnly($str),
            'last4_only'        => $this->maskLast4Only($str, $rule->maskChar),
            'full_redact'       => '[REDACTED]',
            'hash_stable'       => substr(hash('sha256', $str), 0, 16),
            default             => '[REDACTED]',
        };
    }

    private function maskPartialLast4(string $value, string $maskChar, string $separator): string
    {
        $digits = preg_replace('/\D/', '', $value);
        if (strlen($digits) < 4) {
            return str_repeat($maskChar, 4) . $separator . str_repeat($maskChar, 4) . $separator . str_pad($digits, 4, $maskChar, STR_PAD_LEFT);
        }
        $last4 = substr($digits, -4);
        return str_repeat($maskChar, 4) . $separator . str_repeat($maskChar, 4) . $separator . $last4;
    }

    private function maskEmailDomainOnly(string $value): string
    {
        $at = strpos($value, '@');
        if ($at === false) {
            return '****';
        }
        return '****' . substr($value, $at);
    }

    private function maskLast4Only(string $value, string $maskChar): string
    {
        $digits = preg_replace('/\D/', '', $value);
        if (strlen($digits) <= 4) {
            return $digits;
        }
        $last4  = substr($digits, -4);
        $prefix = str_repeat($maskChar, strlen($digits) - 4);
        return $prefix . $last4;
    }
}
