<?php

namespace Develler\RemediationAgent\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Crypt;

class RemediationConnection extends Model
{
    protected $table = 'remediation_connection';

    protected $fillable = [
        'client_id',
        'token_hash',
        'token_encrypted',
        'saas_url',
        'channel_type',
        'poll_url',
        'poll_interval_seconds',
        'connected_at',
    ];

    protected function casts(): array
    {
        return [
            'connected_at' => 'datetime',
        ];
    }

    public static function current(): ?self
    {
        return static::query()->latest()->first();
    }

    public static function exists(): bool
    {
        return static::query()->exists();
    }

    /** Decrypt and return the raw 40-char token for HMAC computation. */
    public function rawToken(): string
    {
        return Crypt::decryptString($this->token_encrypted);
    }
}
