<?php

use Illuminate\Support\Facades\Route;
use Develler\RemediationAgent\Http\Controllers\WebhookController;

Route::post(
    config('remediation.webhook.path', 'api/remediation/v1/webhook'),
    [WebhookController::class, 'receive']
)->name('remediation.webhook');
