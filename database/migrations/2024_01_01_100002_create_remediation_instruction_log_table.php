<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('remediation_instruction_log', function (Blueprint $table) {
            $table->id();
            $table->uuid('instruction_id')->unique();
            $table->string('instruction_type', 50);
            $table->string('payload_hash', 64);     // SHA-256 of rules array — integrity audit trail
            $table->timestamp('received_at');
            $table->timestamp('expires_at');
            $table->boolean('acknowledged')->default(false);
            $table->timestamps();

            $table->index(['expires_at', 'acknowledged']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('remediation_instruction_log');
    }
};
