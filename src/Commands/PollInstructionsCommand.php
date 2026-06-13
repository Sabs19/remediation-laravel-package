<?php

namespace Develler\RemediationAgent\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Develler\RemediationAgent\Contracts\AgentConnectionInterface;
use Develler\RemediationAgent\Models\RemediationConnection;

/**
 * php artisan remediation:poll
 *
 * Fetches pending instructions from the SaaS polling endpoint, verifies each
 * HMAC envelope, writes new instructions to Redis, and acknowledges them.
 *
 * Designed for agents that cannot expose a public webhook URL (e.g. behind a
 * corporate firewall). Register it in your application's scheduler:
 *
 *   Schedule::command('remediation:poll')->everyThirtySeconds();
 *   // or: ->everyMinute() for environments where 30s is impractical
 *
 * The command is a no-op when:
 *   - The agent is not yet connected (no RemediationConnection row).
 *   - The channel_type is 'webhook' — the SaaS pushes directly in that case.
 *   - The circuit breaker is open — Redis is unavailable, polling would fail anyway.
 *
 * All failures are caught and logged to the 'remediation' channel; the command
 * always exits 0 so the scheduler does not alert on transient network errors.
 */
final class PollInstructionsCommand extends Command
{
    protected $signature   = 'remediation:poll {--force : Run even when channel_type is webhook}';
    protected $description = 'Poll the Develler SaaS for pending runtime instructions (firewalled environments).';

    public function handle(AgentConnectionInterface $connection): int
    {
        $conn = RemediationConnection::current();

        if ($conn === null) {
            $this->warn('Remediation agent is not connected. Run: php artisan remediation:connect');
            return self::SUCCESS;
        }

        // Skip if the SaaS has assigned a webhook channel — instructions are pushed.
        if ($conn->channel_type === 'webhook' && !$this->option('force')) {
            $this->line('Channel type is webhook — polling is not needed. Use --force to override.');
            return self::SUCCESS;
        }

        try {
            $fetched = $connection->pollPendingInstructions();

            $count = count($fetched->all());

            if ($count === 0) {
                $this->line('No pending instructions.');
            } else {
                $this->info("Fetched and cached {$count} instruction(s).");
                Log::channel('remediation')->info('PollInstructionsCommand: instructions fetched.', [
                    'count'     => $count,
                    'client_id' => $conn->client_id,
                ]);
            }
        } catch (\Throwable $e) {
            // Never exit non-zero — transient network errors must not alert the scheduler.
            $this->error("Poll failed: {$e->getMessage()}");
            Log::channel('remediation')->error('PollInstructionsCommand: poll failed.', [
                'error'     => $e->getMessage(),
                'client_id' => $conn->client_id,
            ]);
        }

        return self::SUCCESS;
    }
}
