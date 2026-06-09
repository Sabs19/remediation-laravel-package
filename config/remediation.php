<?php

return [

    'saas_url'       => env('REMEDIATION_SAAS_URL', ''),
    'connection_key' => env('REMEDIATION_CONNECTION_KEY', ''),

    'redis' => [
        'connection' => env('REMEDIATION_REDIS_CONNECTION', 'default'),
    ],

    'circuit_breaker' => [
        'ttl_seconds' => (int) env('REMEDIATION_CB_TTL', 60),
    ],

    'interceptor' => [
        'enabled'      => (bool) env('REMEDIATION_INTERCEPTOR_ENABLED', true),
        'html_masking' => (bool) env('REMEDIATION_HTML_MASKING', false),
        'exclude_paths' => [],
        'max_depth'    => 20,
    ],

    'webhook' => [
        'enabled' => (bool) env('REMEDIATION_WEBHOOK_ENABLED', true),
        'path'    => env('REMEDIATION_WEBHOOK_PATH', 'api/remediation/v1/webhook'),
    ],

    'polling' => [
        'interval_seconds' => (int) env('REMEDIATION_POLL_INTERVAL', 30),
    ],

];
