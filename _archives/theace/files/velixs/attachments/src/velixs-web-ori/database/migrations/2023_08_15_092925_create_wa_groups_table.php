<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('wa_groups', function (Blueprint $table) {
            $table->bigIncrements('id');
            $table->string('whatsapp_url');
            $table->string('name');
            $table->string('image');
            $table->string('description')->nullable();
            $table->string('labels')->nullable();
            $table->enum('status', ['published', 'pending', 'draft'])->default('pending');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('wa_groups');
    }
};
