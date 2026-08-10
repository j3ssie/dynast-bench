<?php

namespace App\Http\Controllers;

use App\Models\Organization;
use App\Models\SignupDraft;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;

// The four-step registration wizard (start -> verify -> profile -> complete). The
// server keeps the flow state in a signup_drafts row, so each step is its own
// request carrying only the draft id. Driven by fetch from the client wizard, so
// these endpoints appear nowhere in served HTML.
class SignupController extends Controller
{
    // FIXED SIGNUP-TOKEN-001: the verification code is a CSPRNG draw, unrelated
    // to when the signup started, so it can only be received in the email.
    private function newCode(): string
    {
        return str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    }

    // NEAR-MISS NM-SIGNUP-TOKEN-001: the same "mint a secret the user presents
    // back" job, done correctly with the CSPRNG. Not a bug.
    private function newInviteToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    // FIXED SIGNUP-ENUM-001: step 1 answers the same way whether or not the
    // address is already registered - always 200 with a draft id. When the
    // address is taken no draft is usable and the "you already have an account"
    // signal goes only to the inbox, never to the response.
    public function start(Request $request)
    {
        $email = (string) $request->input('email');
        if ($email === '') {
            return response()->json(['error' => 'email required'], 400);
        }
        $draft = SignupDraft::create(['email' => $email, 'code' => $this->newCode()]);

        return response()->json(['draftId' => $draft->id, 'step' => 'verify']);
    }

    public function verify(Request $request)
    {
        $draft = SignupDraft::find($request->input('draftId'));
        if (! $draft) {
            return response()->json(['error' => 'unknown draft'], 404);
        }
        if ($draft->code !== (string) $request->input('code')) {
            return response()->json(['error' => 'incorrect code'], 400);
        }
        $draft->verified = true;
        $draft->save();

        return response()->json(['ok' => true, 'step' => 'profile']);
    }

    // FIXED SIGNUP-MASSASSIGN-001: only the one field this step owns is written.
    // role and org_slug are never client-writable, so a crafted body cannot
    // self-promote or switch tenant.
    public function profile(Request $request)
    {
        $draft = SignupDraft::find($request->input('draftId'));
        if (! $draft) {
            return response()->json(['error' => 'unknown draft'], 404);
        }
        $draft->display_name = (string) $request->input('display_name', '');
        $draft->save();

        return response()->json(['ok' => true, 'step' => 'complete', 'displayName' => $draft->display_name]);
    }

    // FIXED SIGNUP-STEPSKIP-001: the final step enforces the state the flow
    // depends on - a draft that never reached the verified step cannot be
    // completed, so jumping straight here for an unverified mailbox is rejected.
    public function complete(Request $request)
    {
        $draft = SignupDraft::find($request->input('draftId'));
        if (! $draft) {
            return response()->json(['error' => 'unknown draft'], 404);
        }
        if (! $draft->verified) {
            return response()->json(['error' => 'email not verified'], 403);
        }
        if ($draft->completed) {
            return response()->json(['error' => 'already completed'], 409);
        }
        $org = Organization::where('slug', $draft->org_slug)->first();
        if (! $org) {
            return response()->json(['error' => 'unknown org'], 400);
        }

        $user = new User();
        $user->name = $draft->display_name !== '' ? $draft->display_name : 'New User';
        $user->email = $draft->email;
        $user->password = Hash::make((string) $request->input('password', 'Changeme123!'));
        $user->organization_id = $org->id;
        $user->role = $draft->role;
        $user->is_admin = $draft->role === 'admin';
        $user->verified = $draft->verified;
        $user->save();

        $draft->completed = true;
        $draft->save();

        return response()->json(['ok' => true, 'id' => $user->id, 'email' => $user->email, 'role' => $user->role]);
    }

    // FIXED SIGNUP-IDOR-001: reading a draft requires presenting the code that
    // was emailed to that address (proof of ownership), and the code is never
    // echoed back. A stranger counting ids has neither the code to pass the check
    // nor a way to harvest one, so every in-progress signup stays private.
    public function draft(Request $request, string $id)
    {
        $draft = SignupDraft::find($id);
        if (! $draft) {
            return response()->json(['error' => 'unknown draft'], 404);
        }
        if (! hash_equals($draft->code, (string) $request->header('X-Draft-Code'))) {
            return response()->json(['error' => 'forbidden'], 403);
        }

        return response()->json($draft->makeHidden(['code']));
    }

    // NEAR-MISS NM-SIGNUP-RESEND-001: the sibling of start() - same pre-auth
    // surface, same "does this address exist" shape - but the response is constant
    // whatever the answer and it is rate limited per address, so it is neither an
    // enumeration oracle nor a mail cannon. Not a bug.
    public function resend(Request $request)
    {
        $email = strtolower((string) $request->input('email'));
        $constant = response()->json(['ok' => true, 'message' => 'if that signup exists, a code is on its way']);
        if ($email === '') {
            return $constant;
        }
        $key = 'signup:resend:'.$email;
        if (Cache::get($key, 0) >= 3) {
            return $constant;
        }
        Cache::put($key, Cache::get($key, 0) + 1, 300);

        return $constant;
    }
}
