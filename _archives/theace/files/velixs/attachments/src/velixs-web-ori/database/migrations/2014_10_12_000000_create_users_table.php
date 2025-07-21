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
        Schema::create('users', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('name');
            $table->string('avatar')->nullable();
            $table->string('username')->unique();
            $table->string('email')->unique();
            $table->string('whatsapp')->unique()->nullable();
            $table->timestamp('email_verified_at')->nullable();
            $table->enum('role', ['admin', 'user'])->default('user');
            $table->string('password');
            $table->enum('private', ['yes', 'no'])->default('yes');

            $table->string('digital_product_wishlist')->default('[]');

            $table->text('about')->nullable();
            $table->string('title_profile')->nullable();
            $table->string('suspended')->nullable();

            $table->rememberToken();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
