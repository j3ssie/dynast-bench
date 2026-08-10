<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

// An in-progress registration. The wizard writes one row on step 1 and carries
// its id across the remaining steps, so the server holds the flow state. The id
// is a plain auto-increment (addressable by counting - see SIGNUP-IDOR-001).
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('signup_drafts', function (Blueprint $table) {
            $table->id();
            $table->string('email');
            $table->string('code');
            $table->boolean('verified')->default(false);
            $table->string('display_name')->default('');
            $table->string('role')->default('user');
            $table->string('org_slug')->default('acme');
            $table->boolean('completed')->default(false);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('signup_drafts');
    }
};
