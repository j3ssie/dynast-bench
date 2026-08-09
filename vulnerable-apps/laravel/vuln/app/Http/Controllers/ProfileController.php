<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function show(Request $request)
    {
        return view('profile', ['user' => $request->user()]);
    }

    // MASSASSIGN-001 (CWE-915): the whole request is passed to update(), and the
    // User model has `$guarded = []`, so a plain user can set role/is_admin and
    // promote themselves. The safe twin restricts the model to an explicit
    // $fillable allowlist (name, email, avatar).
    public function update(Request $request)
    {
        $user = $request->user();
        // except() only drops the CSRF field, NOT a security control: role and
        // is_admin still flow straight into the model.
        $user->update($request->except(['_token', '_method']));

        return response()->json([
            'ok' => true,
            'role' => $user->role,
            'is_admin' => (bool) $user->is_admin,
        ]);
    }

    // UPLOAD-001 (CWE-434): the avatar is written under the public web root using
    // the client-supplied filename with no type/extension check, so uploading
    // shell.php yields an executable script at /uploads/shell.php. The safe twin
    // validates it is an image, re-encodes it, and stores it under a random
    // .png name.
    public function avatar(Request $request)
    {
        $file = $request->file('avatar');
        if (! $file) {
            return response('no file', 400);
        }

        $name = $file->getClientOriginalName();
        $dest = public_path('uploads');
        $file->move($dest, $name);
        $user = $request->user();
        $user->avatar = '/uploads/'.$name;
        $user->save();

        return response()->json(['ok' => true, 'avatar' => $user->avatar]);
    }

    // CSRF-001 (CWE-352): this state-changing route is in the CSRF `except` list
    // (see bootstrap/app.php), so a cross-site request with no token succeeds.
    public function rename(Request $request)
    {
        $user = $request->user();
        $user->name = (string) $request->input('name', $user->name);
        $user->save();

        return response()->json(['ok' => true, 'name' => $user->name]);
    }
}
