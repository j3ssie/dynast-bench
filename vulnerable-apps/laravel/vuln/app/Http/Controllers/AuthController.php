<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function showLogin()
    {
        return view('login');
    }

    public function showRegister()
    {
        return view('register');
    }

    // ENUM-001 (CWE-204): the login flow returns different messages for
    // "unknown email" vs "wrong password", so an attacker can enumerate valid
    // accounts. RATELIMIT-001 (CWE-307): there is no throttle middleware on this
    // route, so credential stuffing is unbounded. Both are fixed in the safe
    // twin (generic message + a throttle:5,1 middleware on the route).
    public function login(Request $request)
    {
        $email = (string) $request->input('email');
        $password = (string) $request->input('password');

        $user = User::where('email', $email)->first();
        if (! $user) {
            return response('No account exists for that email address.', 401);
        }
        if (! Hash::check($password, $user->password)) {
            return response('That password is incorrect for this account.', 401);
        }

        Auth::login($user);
        $request->session()->regenerate();

        return redirect('/dashboard');
    }

    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/');
    }

    public function register(Request $request)
    {
        // Explicit column assignment so registration is independent of the
        // User $fillable allowlist (which differs between the two variants).
        $user = new User();
        $user->name = (string) $request->input('name', 'New User');
        $user->email = (string) $request->input('email');
        $user->password = Hash::make((string) $request->input('password', 'changeme'));
        $user->organization_id = 1;
        $user->role = 'user';
        $user->verified = true;
        $user->save();

        Auth::login($user);

        return redirect('/dashboard');
    }

    // RESET-001 (CWE-640/CWE-330): the reset token is a deterministic hash of
    // the email + a static salt (so it is guessable) AND it is handed straight
    // back to the caller in the response. The safe twin issues a random token,
    // stores only its hash, compares with hash_equals, and never returns it.
    public function sendReset(Request $request)
    {
        $email = (string) $request->input('email');
        $user = User::where('email', $email)->first();
        if (! $user) {
            return response()->json(['ok' => true]); // do not leak existence here
        }

        $token = md5($email.'benchboard-reset-salt');
        $user->reset_token = $token;
        $user->save();

        return response()->json(['ok' => true, 'token' => $token]);
    }

    public function doReset(Request $request)
    {
        $email = (string) $request->input('email');
        $token = (string) $request->input('token');
        $password = (string) $request->input('password');

        $user = User::where('email', $email)->first();
        if (! $user || $user->reset_token === null || $token != $user->reset_token) {
            return response('invalid token', 400);
        }

        $user->password = Hash::make($password);
        $user->reset_token = null;
        $user->save();

        return response()->json(['ok' => true]);
    }
}
