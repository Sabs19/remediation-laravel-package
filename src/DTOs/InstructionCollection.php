<?php

namespace Develler\RemediationAgent\DTOs;

use Illuminate\Http\Request;

final class InstructionCollection
{
    /** @param RuntimeInstruction[] $instructions */
    public function __construct(private readonly array $instructions) {}

    public static function empty(): self
    {
        return new self([]);
    }

    /** @return RuntimeInstruction[] */
    public function all(): array
    {
        return $this->instructions;
    }

    public function isEmpty(): bool
    {
        return empty($this->instructions);
    }

    /** @return MaskRule[] */
    public function maskRules(): array
    {
        $rules = [];
        foreach ($this->sortedByPriority() as $instruction) {
            foreach ($instruction->maskRules as $rule) {
                $rules[] = $rule;
            }
        }
        return $rules;
    }

    /** @return array<string,string> Merged headers; higher-priority instruction wins on conflict */
    public function injectHeaders(): array
    {
        $headers = [];
        foreach ($this->sortedByPriority() as $instruction) {
            foreach ($instruction->injectHeaders as $name => $value) {
                $headers[$name] = $value;
            }
        }
        return $headers;
    }

    /**
     * Returns the first matching route-block config for the given request,
     * or null if no block applies.
     *
     * @return array<string,mixed>|null
     */
    public function matchingRouteBlock(Request $request): ?array
    {
        foreach ($this->sortedByPriority() as $instruction) {
            foreach ($instruction->routeBlocks as $block) {
                foreach ($block['blocked_routes'] ?? [] as $route) {
                    if ($this->routeMatches($request, $route)) {
                        return $block;
                    }
                }
            }
        }
        return null;
    }

    public function hasMaskRules(): bool
    {
        return !empty($this->maskRules());
    }

    // -------------------------------------------------------------------------

    /** @return RuntimeInstruction[] */
    private function sortedByPriority(): array
    {
        $copy = $this->instructions;
        usort($copy, static fn (RuntimeInstruction $a, RuntimeInstruction $b) => $a->priority <=> $b->priority);
        return $copy;
    }

    /** @param array<string,mixed> $route */
    private function routeMatches(Request $request, array $route): bool
    {
        $method  = strtoupper($route['method'] ?? 'GET');
        $pattern = ltrim((string) ($route['path'] ?? ''), '/');

        if (strtoupper($request->method()) !== $method) {
            return false;
        }

        return fnmatch($pattern, ltrim($request->path(), '/'));
    }
}
