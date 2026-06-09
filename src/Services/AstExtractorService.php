<?php

namespace Develler\RemediationAgent\Services;

use PhpParser\Error as ParserError;
use PhpParser\Node;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard as PrettyPrinter;
use Develler\RemediationAgent\DTOs\ExtractionResult;
use Develler\RemediationAgent\DTOs\ExtractionTarget;

final class AstExtractorService
{
    private readonly \PhpParser\Parser $parser;
    private readonly NodeFinder $finder;
    private readonly PrettyPrinter $printer;

    public function __construct()
    {
        $this->parser  = (new ParserFactory())->createForHostVersion();
        $this->finder  = new NodeFinder();
        $this->printer = new PrettyPrinter();
    }

    /**
     * Extract source for a single target from the given file.
     * Returns null when the symbol cannot be found.
     */
    public function extract(string $absoluteFilePath, ExtractionTarget $target): ?ExtractionResult
    {
        if (!is_readable($absoluteFilePath)) {
            return null;
        }

        $code = file_get_contents($absoluteFilePath);
        if ($code === false) {
            return null;
        }

        try {
            $ast = $this->parser->parse($code);
        } catch (ParserError) {
            return null;
        }

        if ($ast === null) {
            return null;
        }

        return match ($target->symbolType) {
            'method'   => $this->findMethod($ast, $target, $absoluteFilePath),
            'function' => $this->findFunction($ast, $target, $absoluteFilePath),
            'class'    => $this->findClass($ast, $target, $absoluteFilePath),
            default    => null,
        };
    }

    // -------------------------------------------------------------------------

    /** @param Node[] $ast */
    private function findMethod(array $ast, ExtractionTarget $target, string $filePath): ?ExtractionResult
    {
        /** @var Stmt\ClassMethod|null $node */
        $node = $this->finder->findFirst($ast, function (Node $n) use ($target): bool {
            return $n instanceof Stmt\ClassMethod
                && $n->name->toString() === $target->symbolName;
        });

        if ($node === null) {
            return null;
        }

        return $this->buildResult($node, $target, $filePath);
    }

    /** @param Node[] $ast */
    private function findFunction(array $ast, ExtractionTarget $target, string $filePath): ?ExtractionResult
    {
        /** @var Stmt\Function_|null $node */
        $node = $this->finder->findFirst($ast, function (Node $n) use ($target): bool {
            return $n instanceof Stmt\Function_
                && $n->name->toString() === $target->symbolName;
        });

        if ($node === null) {
            return null;
        }

        return $this->buildResult($node, $target, $filePath);
    }

    /** @param Node[] $ast */
    private function findClass(array $ast, ExtractionTarget $target, string $filePath): ?ExtractionResult
    {
        /** @var Stmt\Class_|null $node */
        $node = $this->finder->findFirst($ast, function (Node $n) use ($target): bool {
            return $n instanceof Stmt\Class_
                && $n->name?->toString() === $target->symbolName;
        });

        if ($node === null) {
            return null;
        }

        return $this->buildResult($node, $target, $filePath);
    }

    private function buildResult(Node $node, ExtractionTarget $target, string $filePath): ExtractionResult
    {
        $startLine  = $node->getStartLine();
        $endLine    = $node->getEndLine();
        $sourceCode = $this->printer->prettyPrint([$node]);

        $docBlock = null;
        $doc = $node->getDocComment();
        if ($doc !== null) {
            $docBlock = $doc->getText();
        }

        return new ExtractionResult(
            filePath:   $filePath,
            startLine:  $startLine,
            endLine:    $endLine,
            sourceCode: $sourceCode,
            symbolName: $target->symbolName,
            symbolType: $target->symbolType,
            docBlock:   $docBlock,
        );
    }
}
