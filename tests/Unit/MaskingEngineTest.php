<?php

namespace Develler\RemediationAgent\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Develler\RemediationAgent\DTOs\MaskRule;
use Develler\RemediationAgent\Services\MaskingEngine;

class MaskingEngineTest extends TestCase
{
    private MaskingEngine $engine;

    protected function setUp(): void
    {
        $this->engine = new MaskingEngine();
    }

    // -------------------------------------------------------------------------
    // partial_last4
    // -------------------------------------------------------------------------

    public function test_partial_last4_masks_all_but_last_four(): void
    {
        $rule = $this->rule('card', 'partial_last4');
        $result = $this->engine->apply(['card' => '4111111111111234'], [$rule]);
        $this->assertSame('XXXX-XXXX-XXXX-1234', $result['card']);
    }

    public function test_partial_last4_passes_short_value_through(): void
    {
        $rule = $this->rule('card', 'partial_last4');
        $result = $this->engine->apply(['card' => '123'], [$rule]);
        $this->assertSame('123', $result['card']);
    }

    // -------------------------------------------------------------------------
    // email_domain_only
    // -------------------------------------------------------------------------

    public function test_email_domain_only_preserves_domain(): void
    {
        $rule = $this->rule('email', 'email_domain_only');
        $result = $this->engine->apply(['email' => 'user@example.com'], [$rule]);
        $this->assertSame('****@example.com', $result['email']);
    }

    public function test_email_domain_only_falls_back_for_non_email(): void
    {
        $rule = $this->rule('email', 'email_domain_only');
        $result = $this->engine->apply(['email' => 'not-an-email'], [$rule]);
        $this->assertSame('[REDACTED]', $result['email']);
    }

    // -------------------------------------------------------------------------
    // last4_only
    // -------------------------------------------------------------------------

    public function test_last4_only_shows_last_four_digits(): void
    {
        $rule = $this->rule('phone', 'last4_only');
        $result = $this->engine->apply(['phone' => '5551234567'], [$rule]);
        $this->assertSame('****4567', $result['phone']);
    }

    // -------------------------------------------------------------------------
    // full_redact
    // -------------------------------------------------------------------------

    public function test_full_redact_replaces_with_marker(): void
    {
        $rule = $this->rule('ssn', 'full_redact');
        $result = $this->engine->apply(['ssn' => '123-45-6789'], [$rule]);
        $this->assertSame('[REDACTED]', $result['ssn']);
    }

    // -------------------------------------------------------------------------
    // hash_stable
    // -------------------------------------------------------------------------

    public function test_hash_stable_produces_deterministic_16char_hex(): void
    {
        $rule = $this->rule('user_id', 'hash_stable');
        $a    = $this->engine->apply(['user_id' => 'abc123'], [$rule]);
        $b    = $this->engine->apply(['user_id' => 'abc123'], [$rule]);

        $this->assertSame($a['user_id'], $b['user_id']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $a['user_id']);
    }

    public function test_hash_stable_differs_for_different_values(): void
    {
        $rule = $this->rule('user_id', 'hash_stable');
        $a    = $this->engine->apply(['user_id' => 'alice'], [$rule]);
        $b    = $this->engine->apply(['user_id' => 'bob'],   [$rule]);

        $this->assertNotSame($a['user_id'], $b['user_id']);
    }

    // -------------------------------------------------------------------------
    // Deep traversal
    // -------------------------------------------------------------------------

    public function test_masks_nested_key(): void
    {
        $rule = $this->rule('email', 'full_redact');
        $data = ['user' => ['email' => 'a@b.com', 'name' => 'Alice']];

        $result = $this->engine->apply($data, [$rule]);

        $this->assertSame('[REDACTED]', $result['user']['email']);
        $this->assertSame('Alice',      $result['user']['name']);
    }

    public function test_does_not_mutate_original_data(): void
    {
        $rule     = $this->rule('email', 'full_redact');
        $original = ['email' => 'original@test.com'];

        $this->engine->apply($original, [$rule]);

        $this->assertSame('original@test.com', $original['email']);
    }

    public function test_respects_max_depth_and_does_not_recurse_infinitely(): void
    {
        $rule = $this->rule('secret', 'full_redact');

        // Build a deeply nested array (25 levels).
        $deep = [];
        $ref  = &$deep;
        for ($i = 0; $i < 25; $i++) {
            $ref['child'] = [];
            $ref          = &$ref['child'];
        }
        $ref['secret'] = 'hidden';

        // Should not throw — stops at MAX_DEPTH (20) and leaves deeper values alone.
        $result = $this->engine->apply($deep, [$rule]);
        $this->assertIsArray($result);
    }

    public function test_masks_values_inside_arrays(): void
    {
        $rule   = $this->rule('email', 'full_redact');
        $data   = ['contacts' => [['email' => 'a@b.com'], ['email' => 'c@d.com']]];
        $result = $this->engine->apply($data, [$rule]);

        $this->assertSame('[REDACTED]', $result['contacts'][0]['email']);
        $this->assertSame('[REDACTED]', $result['contacts'][1]['email']);
    }

    // -------------------------------------------------------------------------
    // Regex match_type
    // -------------------------------------------------------------------------

    public function test_regex_match_type_masks_matching_key(): void
    {
        $rule = $this->rule('/^credit_/', 'partial_last4', 'regex');
        $data = ['credit_card' => '4111111111111234', 'name' => 'Bob'];

        $result = $this->engine->apply($data, [$rule]);

        $this->assertStringContainsString('1234', $result['credit_card']);
        $this->assertSame('Bob', $result['name']);
    }

    // -------------------------------------------------------------------------

    private function rule(string $key, string $strategy, string $matchType = 'exact'): MaskRule
    {
        return new MaskRule(
            ruleId:       'test-rule',
            key:          $key,
            matchType:    $matchType,
            maskStrategy: $strategy,
            pattern:      $matchType === 'regex' ? $key : null,
            maskChar:     '*',
            separator:    '',
        );
    }
}
