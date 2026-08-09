<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ReportController extends Controller
{
    // SQLI-002 (CWE-89, second-order / cross-file): post titles are stored by
    // PostController::store, then here each stored title is concatenated into a
    // *new* raw query. A title of
    //   x' UNION SELECT body FROM posts WHERE slug='globex-internal' --
    // makes the inner query leak the confidential draft across tenants. The
    // taint enters in one request and detonates in another. The safe twin binds
    // the title as a parameter.
    public function titles(Request $request)
    {
        $orgId = $request->user()->organization_id;
        $posts = DB::select('SELECT id, title FROM posts WHERE organization_id = '.$orgId);

        $report = [];
        foreach ($posts as $p) {
            $rows = DB::select("SELECT title AS label FROM posts WHERE title = '".$p->title."'");
            foreach ($rows as $r) {
                $report[] = $r->label;
            }
        }

        return response()->json(['labels' => $report]);
    }
}
