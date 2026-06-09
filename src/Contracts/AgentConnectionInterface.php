<?php

namespace Develler\RemediationAgent\Contracts;

use Develler\RemediationAgent\DTOs\Envelope;
use Develler\RemediationAgent\DTOs\InstructionCollection;
use Develler\RemediationAgent\DTOs\RuntimeInstruction;
use Develler\RemediationAgent\Exceptions\ReplayException;
use Develler\RemediationAgent\Exceptions\SignatureException;

interface AgentConnectionInterface
{
    /**
     * Verify HMAC-SHA256 envelope signature plus replay-attack guards.
     * Uses constant-time comparison. Throws on any verification failure.
     *
     * @throws SignatureException
     * @throws ReplayException
     */
    public function verifyEnvelope(array $rawEnvelope): Envelope;

    /**
     * Persist a verified RuntimeInstruction to the Redis instruction cache.
     * TTL is derived from instruction->expiresAt - now().
     */
    public function cacheInstruction(RuntimeInstruction $instruction): void;

    /**
     * Return all currently active (non-expired) RuntimeInstructions from cache.
     * Must complete in <1ms on a local Redis socket. Never does I/O to SaaS.
     */
    public function getActiveInstructions(): InstructionCollection;

    /**
     * POST an acknowledgement back to the SaaS for a delivered instruction.
     */
    public function acknowledgeInstruction(string $instructionId): void;

    /**
     * Poll the SaaS pending-instructions endpoint (used when channel = 'polling').
     */
    public function pollPendingInstructions(): InstructionCollection;
}
