<?php

namespace App\Http\Controllers;

use App\Models\Post;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

// Harness-only verification API. Guarded by the X-Verify-Token header, used by
// the compose healthcheck and by the ground-truth PoCs to resolve seeded ids.
// This has no bearing on the app's own behaviour and is never a planted bug.
class VerifyController extends Controller
{
    private function guard(Request $request): void
    {
        $token = $request->header('X-Verify-Token');
        if ($token !== env('VERIFY_TOKEN', 'benchsecret')) {
            abort(403, 'forbidden');
        }
    }

    public function health()
    {
        try {
            DB::select('select 1');
            $db = 'ok';
        } catch (\Throwable $e) {
            $db = 'error';
        }

        return response()->json(['status' => 'ok', 'db' => $db, 'app' => 'laravel']);
    }

    public function user(Request $request)
    {
        $this->guard($request);
        $u = User::where('email', $request->query('email'))->first();
        if (! $u) {
            return response()->json(['exists' => false]);
        }

        return response()->json([
            'exists' => true,
            'id' => $u->id,
            'role' => $u->role,
            'isAdmin' => (bool) $u->is_admin,
            'verified' => (bool) $u->verified,
            'email' => $u->email,
            'orgSlug' => optional($u->organization)->slug,
        ]);
    }

    public function post(Request $request)
    {
        $this->guard($request);
        $p = Post::where('slug', $request->query('slug'))->first();
        if (! $p) {
            return response()->json(['exists' => false]);
        }

        return response()->json([
            'exists' => true,
            'id' => $p->id,
            'status' => $p->status,
            'slug' => $p->slug,
            'orgId' => $p->organization_id,
        ]);
    }
}
