<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class SignupDraft extends Model
{
    // The profile step deliberately fills straight from the request, so every
    // column is mass assignable - including role and org_slug (SIGNUP-MASSASSIGN-001).
    protected $guarded = [];
}
