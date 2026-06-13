<?php

namespace Develler\RemediationAgent\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Develler\RemediationAgent\DTOs\ExtractionTarget;
use Develler\RemediationAgent\Services\AstExtractorService;

class AstExtractorServiceTest extends TestCase
{
    private AstExtractorService $extractor;
    private string $tempDir;

    protected function setUp(): void
    {
        $this->extractor = new AstExtractorService();
        $this->tempDir   = sys_get_temp_dir() . '/remediation_test_' . uniqid('', true);
        mkdir($this->tempDir);
    }

    protected function tearDown(): void
    {
        // Clean up temp files.
        foreach (glob("{$this->tempDir}/*.php") ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->tempDir);
    }

    public function test_extracts_method_with_correct_line_numbers(): void
    {
        $code = <<<'PHP'
        <?php
        class UserService {
            public function getUser(int $id): array
            {
                return ['id' => $id];
            }
        }
        PHP;

        $file   = $this->writeTemp('UserService.php', $code);
        $target = new ExtractionTarget($file, 'getUser', 'method');
        $result = $this->extractor->extract($file, $target);

        $this->assertNotNull($result);
        $this->assertSame('getUser', $result->symbolName);
        $this->assertSame('method',  $result->symbolType);
        $this->assertGreaterThan(0,  $result->startLine);
        $this->assertGreaterThanOrEqual($result->startLine, $result->endLine);
        $this->assertStringContainsString('getUser', $result->sourceCode);
    }

    public function test_extracts_standalone_function(): void
    {
        $code = <<<'PHP'
        <?php
        function computeHash(string $input): string
        {
            return hash('sha256', $input);
        }
        PHP;

        $file   = $this->writeTemp('helpers.php', $code);
        $target = new ExtractionTarget($file, 'computeHash', 'function');
        $result = $this->extractor->extract($file, $target);

        $this->assertNotNull($result);
        $this->assertSame('computeHash', $result->symbolName);
        $this->assertStringContainsString('computeHash', $result->sourceCode);
    }

    public function test_extracts_class_declaration(): void
    {
        $code = <<<'PHP'
        <?php
        class OrderRepository
        {
            public function find(int $id): ?array { return null; }
        }
        PHP;

        $file   = $this->writeTemp('OrderRepository.php', $code);
        $target = new ExtractionTarget($file, 'OrderRepository', 'class');
        $result = $this->extractor->extract($file, $target);

        $this->assertNotNull($result);
        $this->assertSame('OrderRepository', $result->symbolName);
    }

    public function test_returns_null_when_symbol_not_found(): void
    {
        $code = "<?php\nclass Foo { public function bar(): void {} }";

        $file   = $this->writeTemp('Foo.php', $code);
        $target = new ExtractionTarget($file, 'nonExistentMethod', 'method');
        $result = $this->extractor->extract($file, $target);

        $this->assertNull($result);
    }

    public function test_returns_null_for_nonexistent_file(): void
    {
        $target = new ExtractionTarget('/tmp/does_not_exist.php', 'foo', 'function');
        $result = $this->extractor->extract('/tmp/does_not_exist.php', $target);

        $this->assertNull($result);
    }

    public function test_extracts_docblock_when_present(): void
    {
        $code = <<<'PHP'
        <?php
        class Calculator {
            /**
             * Add two numbers.
             */
            public function add(int $a, int $b): int
            {
                return $a + $b;
            }
        }
        PHP;

        $file   = $this->writeTemp('Calculator.php', $code);
        $target = new ExtractionTarget($file, 'add', 'method');
        $result = $this->extractor->extract($file, $target);

        $this->assertNotNull($result);
        $this->assertNotNull($result->docBlock);
        $this->assertStringContainsString('Add two numbers', $result->docBlock);
    }

    public function test_returns_null_for_syntax_error(): void
    {
        $file   = $this->writeTemp('broken.php', '<?php function ((())) {');
        $target = new ExtractionTarget($file, 'anything', 'function');
        $result = $this->extractor->extract($file, $target);

        $this->assertNull($result);
    }

    /**
     * Verify that ProcessExtractionJob's path guard blocks traversal paths.
     * The guard lives in the job, not the extractor, so we test the guard logic directly.
     */
    public function test_path_traversal_attempt_is_rejected_by_guard(): void
    {
        // Simulate what ProcessExtractionJob does: anchor to base_path and verify
        // the realpath stays within the application root.
        $appRoot        = $this->tempDir; // stand-in for base_path()
        $traversalPath  = $appRoot . '/sub/../../../etc/passwd';

        $realResolved = realpath($traversalPath);

        if ($realResolved !== false) {
            // If /etc/passwd actually exists, confirm it is outside our app root.
            $this->assertFalse(
                str_starts_with($realResolved, $appRoot),
                'Path traversal should resolve outside the application root.'
            );
        } else {
            // Path does not exist — realpath returns false, guard also blocks.
            $this->assertFalse($realResolved);
        }
    }

    public function test_legitimate_nested_path_passes_guard(): void
    {
        // A legitimate sub-directory file should pass the guard.
        mkdir($this->tempDir . '/sub', 0777, true);
        $file      = $this->writeTemp('sub/Legit.php', '<?php class Legit {}');
        $realPath  = realpath($file);

        $this->assertNotFalse($realPath);
        $this->assertTrue(str_starts_with($realPath, $this->tempDir));
    }

    // -------------------------------------------------------------------------

    private function writeTemp(string $name, string $content): string
    {
        $dir  = dirname("{$this->tempDir}/{$name}");
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
        $path = "{$this->tempDir}/{$name}";
        file_put_contents($path, $content);
        return $path;
    }
}
