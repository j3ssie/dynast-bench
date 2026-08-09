<?php

namespace App\Http\Controllers;

use App\Models\Invitation;
use App\Models\Subscription;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class BillingController extends Controller
{
    public function status(Request $request)
    {
        $sub = Subscription::where('organization_id', $request->user()->organization_id)->first();

        return response()->json([
            'seats_total' => $sub->seats_total,
            'seats_used' => $sub->seats_used,
            'balance_cents' => $sub->balance_cents,
        ]);
    }

    // BILLING-001 (CWE-840): the top-up amount is applied with no bound check, so
    // a negative amount drains the balance below zero (a logic/insecure-design
    // bug a pattern scanner can't see). The safe twin rejects amounts <= 0.
    public function topup(Request $request)
    {
        $sub = Subscription::where('organization_id', $request->user()->organization_id)->first();
        $amount = (int) $request->input('amount', 0);
        $sub->balance_cents = $sub->balance_cents + $amount;
        $sub->save();

        return response()->json(['ok' => true, 'balance_cents' => $sub->balance_cents]);
    }

    // RACE-001 (CWE-362): seats are checked and then incremented without a lock,
    // so concurrent invites race past the seat limit. The `usleep` models the
    // check-then-act gap. The safe twin does the reservation inside a
    // transaction with lockForUpdate() and re-checks under the lock.
    public function invite(Request $request)
    {
        $sub = Subscription::where('organization_id', $request->user()->organization_id)->first();

        if ($sub->seats_used < $sub->seats_total) {
            usleep(50000); // check-then-act window
            $sub->seats_used = $sub->seats_used + 1;
            $sub->save();

            Invitation::create([
                'organization_id' => $sub->organization_id,
                'email' => (string) $request->input('email', 'invitee@bench.local'),
                'token' => Str::random(20),
            ]);

            return response()->json(['ok' => true, 'seats_used' => $sub->seats_used]);
        }

        return response('no seats remaining', 409);
    }
}
