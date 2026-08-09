<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class AdminController extends Controller
{
    // AUTHZ-001 (CWE-862): the route is behind `auth` but NOT behind the `admin`
    // middleware, so any logged-in user can list every account across tenants.
    // The safe twin adds ->middleware('admin') to the route (as audit() has).
    public function users(Request $request)
    {
        $users = User::query()
            ->orderBy('id')
            ->get(['id', 'name', 'email', 'role', 'is_admin', 'organization_id']);

        return response()->json(['users' => $users]);
    }

    // NM-AUTHZ-001: the same shape of admin listing, correctly gated by the
    // `admin` middleware on the route. Present in both variants.
    public function audit(Request $request)
    {
        return response()->json([
            'ok' => true,
            'count' => User::count(),
        ]);
    }
}
