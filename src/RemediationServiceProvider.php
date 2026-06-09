<?php

namespace Develler\RemediationAgent;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;
use Develler\RemediationAgent\Commands\ConnectCommand;
use Develler\RemediationAgent\Contracts\AgentConnectionInterface;
use Develler\RemediationAgent\Contracts\LifecycleInterceptorInterface;
use Develler\RemediationAgent\Http\Middleware\RemediationInterceptor;
use Develler\RemediationAgent\Models\RemediationConnection;
use Develler\RemediationAgent\Services\AgentConnectionService;
use Develler\RemediationAgent\Services\CircuitBreakerService;
use Develler\RemediationAgent\Services\InstructionCacheService;
use Develler\RemediationAgent\Services\AstExtractorService;
use Develler\RemediationAgent\Services\MaskingEngine;
use Develler\RemediationAgent\Services\TelemetryReporter;
use Throwable;

final class RemediationServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/remediation.php', 'remediation');

        // Resolve client_id once; all cache/breaker keys derive from it.
        $this->app->singleton(InstructionCacheService::class, function () {
            return new InstructionCacheService($this->resolveClientId());
        });

        $this->app->singleton(CircuitBreakerService::class, function () {
            return new CircuitBreakerService($this->resolveClientId());
        });

        $this->app->singleton(MaskingEngine::class);
        $this->app->singleton(AstExtractorService::class);
        $this->app->singleton(TelemetryReporter::class);

        $this->app->singleton(AgentConnectionInterface::class, function ($app) {
            return new AgentConnectionService(
                $app->make(InstructionCacheService::class),
            );
        });

        $this->app->singleton(LifecycleInterceptorInterface::class, function ($app) {
            return new RemediationInterceptor(
                $app->make(AgentConnectionInterface::class),
                $app->make(MaskingEngine::class),
                $app->make(CircuitBreakerService::class),
                $app->make(TelemetryReporter::class),
            );
        });

        // Alias so middleware stack can resolve by class name.
        $this->app->alias(LifecycleInterceptorInterface::class, RemediationInterceptor::class);
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        $this->publishes([
            __DIR__ . '/../config/remediation.php' => config_path('remediation.php'),
        ], 'remediation-config');

        if ($this->app->runningInConsole()) {
            $this->commands([ConnectCommand::class]);
        }

        $this->registerLoggingChannel();
        $this->registerMiddleware();
        $this->registerWebhookRoutes();
    }

    // -------------------------------------------------------------------------

    private function registerMiddleware(): void
    {
        if (!config('remediation.interceptor.enabled', true)) {
            return;
        }

        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app['router'];

        // Register on both groups so it covers API and web routes.
        $router->pushMiddlewareToGroup('api', RemediationInterceptor::class);
        $router->pushMiddlewareToGroup('web', RemediationInterceptor::class);
    }

    private function registerWebhookRoutes(): void
    {
        if (!config('remediation.webhook.enabled', true)) {
            return;
        }

        $this->loadRoutesFrom(__DIR__ . '/../routes/webhook.php');
    }

    private function registerLoggingChannel(): void
    {
        // Inject a dedicated 'remediation' log channel so all agent logs
        // are isolated and never mix PII-adjacent data into the default channel.
        $config = $this->app['config'];

        if ($config->get('logging.channels.remediation') !== null) {
            return;
        }

        $config->set('logging.channels.remediation', [
            'driver' => 'daily',
            'path'   => storage_path('logs/remediation.log'),
            'level'  => 'debug',
            'days'   => 14,
        ]);
    }

    private function resolveClientId(): string
    {
        try {
            $connection = RemediationConnection::current();
            return $connection?->client_id ?? 'unconnected';
        } catch (Throwable) {
            // DB not yet migrated (e.g. fresh install) — use a safe placeholder.
            return 'unconnected';
        }
    }
}
