<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('remediation_connection', function (Blueprint $table) {
            $table->id();
            $table->string('client_id', 12)->unique();
            $table->string('token_hash');
            $table->text('token_encrypted');        // AES-256-GCM via Laravel Crypt; key = APP_KEY
            $table->string('saas_url');
            $table->string('channel_type', 20)->default('polling');
            $table->string('poll_url')->nullable();
            $table->unsignedSmallInteger('poll_interval_seconds')->default(30);
            $table->timestamp('connected_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('remediation_connection');
    }
};
