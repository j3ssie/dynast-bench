<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;

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

    // ENUM-001 fixed: one generic message for both failure modes.
    // RATELIMIT-001 fixed: a per-identity limiter counts only FAILED attempts
    // (cleared on success), so credential stuffing on one account is throttled
    // without penalising legitimate logins.
    public function login(Request $request)
    {
        $email = (string) $request->input('email');
        $password = (string) $request->input('password');
        $key = 'login:'.strtolower($email).'|'.$request->ip();

        if (RateLimiter::tooManyAttempts($key, 5)) {
            return response('Too many login attempts. Try again later.', 429);
        }

        $user = User::where('email', $email)->first();
        if (! $user || ! Hash::check($password, $user->password)) {
            RateLimiter::hit($key, 60);

            // Generic message: do not reveal whether the email exists.
            return response('These credentials do not match our records.', 401);
        }

        RateLimiter::clear($key);
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

        // Random, unguessable token; store only its hash and never return it.
        $token = bin2hex(random_bytes(32));
        $user->reset_token = hash('sha256', $token);
        $user->save();
        // (a real app mails $token to the user here)

        return response()->json(['ok' => true]);
    }

    public function doReset(Request $request)
    {
        $email = (string) $request->input('email');
        $token = (string) $request->input('token');
        $password = (string) $request->input('password');

        $user = User::where('email', $email)->first();
        if (! $user || $user->reset_token === null
            || ! hash_equals($user->reset_token, hash('sha256', $token))) {
            return response('invalid token', 400);
        }

        $user->password = Hash::make($password);
        $user->reset_token = null;
        $user->save();

        return response()->json(['ok' => true]);
    }
}
