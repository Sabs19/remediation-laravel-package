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

    // -------------------------------------------------------------------------

    private function writeTemp(string $name, string $content): string
    {
        $path = "{$this->tempDir}/{$name}";
        file_put_contents($path, $content);
        return $path;
    }
}
