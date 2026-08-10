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
    // SIGNUP-TOKEN-001 (CWE-330/CWE-640): the emailed verification code is the
    // last six digits of the wall clock, not a CSPRNG draw - so anyone who can
    // start a signup for an address (or knows roughly when one started) can
    // recompute the code instead of receiving it. The safe twin uses random_int.
    private function newCode(): string
    {
        return substr((string) time(), -6);
    }

    // NEAR-MISS NM-SIGNUP-TOKEN-001: the same "mint a secret the user presents
    // back" job, done correctly with the CSPRNG. Not a bug.
    private function newInviteToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    // SIGNUP-ENUM-001 (CWE-204): step 1 answers 409 for a registered address and
    // 200 for an unknown one, so pre-auth, unthrottled registration is a free
    // oracle for testing an address list. The safe twin always returns 200 and
    // signals "already registered" only by email.
    public function start(Request $request)
    {
        $email = (string) $request->input('email');
        if ($email === '') {
            return response()->json(['error' => 'email required'], 400);
        }
        if (User::where('email', $email)->exists()) {
            return response()->json(['error' => 'that email is already registered', 'registered' => true], 409);
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

    // SIGNUP-MASSASSIGN-001 (CWE-915): the profile step fills the draft straight
    // from the request body. The wizard only sends display_name, but the draft
    // also carries role and org_slug - the two fields the final step hands to the
    // new User - so a crafted body registers an admin or joins another tenant.
    public function profile(Request $request)
    {
        $draft = SignupDraft::find($request->input('draftId'));
        if (! $draft) {
            return response()->json(['error' => 'unknown draft'], 404);
        }
        $draft->fill($request->except(['draftId', '_token']));
        $draft->save();

        return response()->json(['ok' => true, 'step' => 'complete', 'displayName' => $draft->display_name]);
    }

    // SIGNUP-STEPSKIP-001 (CWE-841): the final step never checks that the draft
    // reached the verified state. In the wizard a draft always is verified by the
    // time it gets here, but the steps are independent requests - posting straight
    // to this one with a fresh draft id registers an unverified, unowned mailbox.
    public function complete(Request $request)
    {
        $draft = SignupDraft::find($request->input('draftId'));
        if (! $draft) {
            return response()->json(['error' => 'unknown draft'], 404);
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

    // SIGNUP-IDOR-001 (CWE-639): the wizard reloads its own draft by id after a
    // refresh, and the handler returns whatever row that id names - no ownership
    // check, no session, over an auto-increment id, and the row carries the email
    // AND the verification code that was emailed to it. Count down to walk every
    // registration in progress.
    public function draft(Request $request, string $id)
    {
        $draft = SignupDraft::find($id);
        if (! $draft) {
            return response()->json(['error' => 'unknown draft'], 404);
        }

        return response()->json($draft);
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
