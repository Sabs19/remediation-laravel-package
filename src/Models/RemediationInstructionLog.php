<?php

namespace Develler\RemediationAgent\Models;

use Illuminate\Database\Eloquent\Model;

class RemediationInstructionLog extends Model
{
    protected $table = 'remediation_instruction_log';

    protected $fillable = [
        'instruction_id',
        'instruction_type',
        'payload_hash',
        'received_at',
        'expires_at',
        'acknowledged',
    ];

    protected function casts(): array
    {
        return [
            'received_at'  => 'datetime',
            'expires_at'   => 'datetime',
            'acknowledged' => 'boolean',
        ];
    }
}
