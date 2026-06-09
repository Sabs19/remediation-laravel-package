<?php

namespace Develler\RemediationAgent\DTOs;

final class RuntimeInstruction
{
    /**
     * @param MaskRule[]            $maskRules
     * @param array<int,array>      $routeBlocks
     * @param array<string,string>  $injectHeaders
     */
    public function __construct(
        public readonly string $instructionId,
        public readonly string $instructionType,
        public readonly int    $priority,
        public readonly int    $effectiveAt,
        public readonly int    $expiresAt,
        public readonly array  $includeRoutes,
        public readonly array  $excludeRoutes,
        public readonly array  $httpMethods,
        public readonly array  $maskRules,
        public readonly array  $routeBlocks,
        public readonly array  $injectHeaders,
        public readonly string $rulesChecksum,
    ) {}

    public static function fromArray(array $data): self
    {
        $targets       = $data['targets'] ?? [];
        $maskRules     = [];
        $routeBlocks   = [];
        $injectHeaders = [];

        foreach ($data['rules'] ?? [] as $rule) {
            $type   = $rule['rule_type'] ?? '';
            $config = $rule['config']    ?? [];
            $ruleId = $rule['rule_id']   ?? '';

            match ($type) {
                'pii_mask' => array_push(
                    $maskRules,
                    ...array_map(
                        static fn (array $kp) => MaskRule::fromArray($kp + ['rule_id' => $ruleId]),
                        $config['key_patterns'] ?? []
                    )
                ),
                'route_block'   => array_push($routeBlocks, $config),
                'header_inject' => $injectHeaders = array_merge($injectHeaders, $config['headers'] ?? []),
                default         => null,
            };
        }

        return new self(
            instructionId:   (string) ($data['instruction_id']   ?? ''),
            instructionType: (string) ($data['instruction_type'] ?? ''),
            priority:        (int)    ($data['priority']         ?? 100),
            effectiveAt:     (int)    ($data['effective_at']     ?? 0),
            expiresAt:       (int)    ($data['expires_at']       ?? 0),
            includeRoutes:   $targets['routes']['include'] ?? ['*'],
            excludeRoutes:   $targets['routes']['exclude'] ?? [],
            httpMethods:     $targets['http_methods']      ?? ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
            maskRules:       $maskRules,
            routeBlocks:     $routeBlocks,
            injectHeaders:   $injectHeaders,
            rulesChecksum:   (string) ($data['checksum'] ?? ''),
        );
    }

    public function isExpired(): bool
    {
        return time() > $this->expiresAt;
    }

    public function isEffective(): bool
    {
        return time() >= $this->effectiveAt && !$this->isExpired();
    }

    public function toJson(): string
    {
        return json_encode([
            'instruction_id'   => $this->instructionId,
            'instruction_type' => $this->instructionType,
            'priority'         => $this->priority,
            'effective_at'     => $this->effectiveAt,
            'expires_at'       => $this->expiresAt,
            'include_routes'   => $this->includeRoutes,
            'exclude_routes'   => $this->excludeRoutes,
            'http_methods'     => $this->httpMethods,
            'mask_rules'       => array_map(fn (MaskRule $r) => [
                'rule_id'      => $r->ruleId,
                'key'          => $r->key,
                'match_type'   => $r->matchType,
                'mask_strategy'=> $r->maskStrategy,
                'pattern'      => $r->pattern,
                'mask_char'    => $r->maskChar,
                'separator'    => $r->separator,
            ], $this->maskRules),
            'route_blocks'     => $this->routeBlocks,
            'inject_headers'   => $this->injectHeaders,
            'checksum'         => $this->rulesChecksum,
        ], JSON_THROW_ON_ERROR);
    }

    public static function fromJson(string $json): self
    {
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        $maskRules = array_map(
            static fn (array $r) => MaskRule::fromArray([
                'rule_id'       => $r['rule_id']       ?? '',
                'key'           => $r['key']           ?? '',
                'match_type'    => $r['match_type']    ?? 'exact',
                'mask_strategy' => $r['mask_strategy'] ?? 'full_redact',
                'pattern'       => $r['pattern']       ?? null,
                'mask_char'     => $r['mask_char']     ?? 'X',
                'separator'     => $r['separator']     ?? '-',
            ]),
            $data['mask_rules'] ?? []
        );

        return new self(
            instructionId:   $data['instruction_id']   ?? '',
            instructionType: $data['instruction_type'] ?? '',
            priority:        (int) ($data['priority']  ?? 100),
            effectiveAt:     (int) ($data['effective_at'] ?? 0),
            expiresAt:       (int) ($data['expires_at']   ?? 0),
            includeRoutes:   $data['include_routes']   ?? ['*'],
            excludeRoutes:   $data['exclude_routes']   ?? [],
            httpMethods:     $data['http_methods']     ?? [],
            maskRules:       $maskRules,
            routeBlocks:     $data['route_blocks']     ?? [],
            injectHeaders:   $data['inject_headers']   ?? [],
            rulesChecksum:   $data['checksum']         ?? '',
        );
    }
}
