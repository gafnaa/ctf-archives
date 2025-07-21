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
        Schema::create('apihub_endpoints', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->bigInteger('apihub_id');
            $table->string('title');
            $table->string('url');
            $table->enum('method', ['GET','POST','PUT','ALL'])->default('GET');
            $table->text('data')->nullable();
            $table->text('response')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('apihub_endpoints');
    }
};
