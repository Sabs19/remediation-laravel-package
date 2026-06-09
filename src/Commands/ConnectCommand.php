<?php

namespace Develler\RemediationAgent\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Develler\RemediationAgent\Models\RemediationConnection;
use Throwable;

/**
 * php artisan remediation:connect
 *
 * Performs the initial handshake with the SaaS, stores the returned
 * client_id and token, and writes the channel configuration.
 *
 * Safe to re-run — clears any existing connection before creating the new one.
 */
final class ConnectCommand extends Command
{
    protected $signature   = 'remediation:connect';
    protected $description = 'Connect this application to Develler.';

    public function handle(): int
    {
        $saasUrl       = $this->resolveSaasUrl();
        $connectionKey = $this->resolveConnectionKey();

        if ($saasUrl === '' || $connectionKey === '') {
            $this->error('REMEDIATION_SAAS_URL and REMEDIATION_CONNECTION_KEY must both be set.');
            return self::FAILURE;
        }

        $this->info("Connecting to: {$saasUrl}");

        try {
            $response = Http::timeout(15)->post("{$saasUrl}/api/remediation/v1/handshake", [
                'connection_key'  => $connectionKey,
                'site_url'        => rtrim((string) config('app.url'), '/'),
                'site_name'       => config('app.name'),
                'language_runtime'=> 'php',
                'runtime_version' => PHP_VERSION,
                'framework'       => 'laravel',
                'framework_version' => app()->version(),
                'agent_version'   => $this->agentVersion(),
                'environment'     => app()->environment(),
                'capabilities'    => [
                    'mode_a_ast'         => false,
                    'mode_b_interceptor' => true,
                    'redis_available'    => $this->redisAvailable(),
                    'git_access'         => false,
                ],
            ]);
        } catch (Throwable $e) {
            $this->error("Connection request failed: {$e->getMessage()}");
            return self::FAILURE;
        }

        if (!$response->successful()) {
            $this->error("SaaS returned HTTP {$response->status()}: {$response->body()}");
            return self::FAILURE;
        }

        $data = $response->json();

        if (($data['status'] ?? '') !== 'accepted') {
            $this->error('SaaS rejected the handshake. Check your REMEDIATION_CONNECTION_KEY.');
            return self::FAILURE;
        }

        $clientId = (string) ($data['client_id'] ?? '');
        $token    = (string) ($data['token']     ?? '');
        $channel  = $data['instruction_channel'] ?? [];

        if ($clientId === '' || $token === '') {
            $this->error('SaaS response missing client_id or token.');
            return self::FAILURE;
        }

        RemediationConnection::query()->delete();

        RemediationConnection::create([
            'client_id'            => $clientId,
            'token_hash'           => Hash::make($token),
            'token_encrypted'      => Crypt::encryptString($token),
            'saas_url'             => rtrim($saasUrl, '/'),
            'channel_type'         => $channel['type']                    ?? 'polling',
            'poll_url'             => $channel['poll_url']                ?? null,
            'poll_interval_seconds'=> (int) ($channel['poll_interval_seconds'] ?? 30),
            'connected_at'         => now(),
        ]);

        $this->info("Connected successfully. client_id: {$clientId}");
        $this->line("Channel: " . ($channel['type'] ?? 'polling'));

        Log::info('RemediationEngine: connected successfully.', ['client_id' => $clientId]);

        return self::SUCCESS;
    }

    // -------------------------------------------------------------------------

    private function resolveSaasUrl(): string
    {
        return rtrim((string) config('remediation.saas_url', env('REMEDIATION_SAAS_URL', '')), '/');
    }

    private function resolveConnectionKey(): string
    {
        return (string) config('remediation.connection_key', env('REMEDIATION_CONNECTION_KEY', ''));
    }

    private function agentVersion(): ?string
    {
        if (class_exists(\Composer\InstalledVersions::class)) {
            try {
                return \Composer\InstalledVersions::getPrettyVersion('develler/remediation-agent');
            } catch (Throwable) {}
        }
        return null;
    }

    private function redisAvailable(): bool
    {
        try {
            \Illuminate\Support\Facades\Redis::connection(
                config('remediation.redis.connection', 'default')
            )->ping();
            return true;
        } catch (Throwable) {
            return false;
        }
    }
}
