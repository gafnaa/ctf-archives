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
        Schema::create('products', function (Blueprint $table) {
            $table->bigIncrements('id');
            $table->string('title');
            $table->string('slug')->unique();
            $table->string('image');
            $table->longText('content');
            $table->uuid('author');
            $table->foreign('author')->references('id')->on('users');
            $table->string('tags')->default('[]');
            $table->boolean('is_published')->default(false);
            $table->string('meta_description')->nullable();

            $table->string('price')->default('[]');
            $table->longText('preview')->nullable();

            $table->longText('release')->nullable();

            $table->softDeletes();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('products');
    }
};
