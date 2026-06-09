<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('remediation_extraction_log', function (Blueprint $table): void {
            $table->id();
            $table->uuid('extraction_id')->index();
            $table->string('extraction_type', 64);
            $table->string('status', 32)->default('received'); // received | queued | complete | failed
            $table->unsignedSmallInteger('result_count')->default(0);
            $table->text('error_message')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('remediation_extraction_log');
    }
};
