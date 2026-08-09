<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class PostController extends Controller
{
    // SQLI-001 (CWE-89): the search term is concatenated straight into a raw
    // SQL string, so `q=%' OR 1=1 -- ` returns every row including the Globex
    // confidential draft. XSS-REFLECT-001 (CWE-79): the same term is echoed
    // back unescaped by the Blade view via {!! $q !!}.
    // NM-SQL-001 lives in index() below (a bound `where(...)` of the same shape).
    public function search(Request $request)
    {
        $q = (string) $request->query('q', '');
        $like = '%'.$q.'%';
        $rows = DB::select(
            "SELECT title, body, slug FROM posts WHERE status = 'published' AND (title LIKE ? OR body LIKE ?)",
            [$like, $like]
        );

        return view('search', ['q' => $q, 'rows' => $rows]);
    }

    // NM-SQL-001: same "filter posts by a substring" feature, but bound.
    // A scanner that flags this is producing a false positive.
    public function index(Request $request)
    {
        $needle = (string) $request->query('q', '');
        $orgId = $request->user()->organization_id;
        $rows = DB::select(
            'SELECT title, slug FROM posts WHERE organization_id = ? AND title LIKE ?',
            [$orgId, '%'.$needle.'%']
        );

        return view('posts', ['rows' => $rows]);
    }

    // IDOR-001 (CWE-639): implicit route-model binding loads any post by id and
    // renders it with no owner/org/status check, so an Acme user reads the
    // Globex draft. The safe twin adds the same org+visibility check that
    // audit() below already performs.
    public function show(Request $request, Post $post)
    {
        // Enforce the same org/owner/visibility rule audit() uses.
        $user = $request->user();
        $visible = $post->organization_id === $user->organization_id
            || $post->user_id === $user->id
            || $post->status === 'published';
        if (! $visible) {
            abort(403, 'Not your post.');
        }
        $post->load('comments.author');

        return view('post_show', ['post' => $post]);
    }

    // NM-IDOR-001: the audit view of the very same object, but access-controlled
    // (owner or same-org). Present in BOTH variants — flagging it is an FP.
    public function audit(Request $request, Post $post)
    {
        $user = $request->user();
        if ($post->organization_id !== $user->organization_id && $post->user_id !== $user->id) {
            abort(403, 'Not your post.');
        }

        return response()->json(['id' => $post->id, 'slug' => $post->slug, 'status' => $post->status]);
    }

    public function store(Request $request)
    {
        $title = (string) $request->input('title', 'Untitled');
        $post = Post::create([
            'organization_id' => $request->user()->organization_id,
            'user_id' => $request->user()->id,
            'slug' => Str::slug($title).'-'.Str::random(6),
            'title' => $title,
            'body' => (string) $request->input('body', ''),
            'status' => (string) $request->input('status', 'draft'),
        ]);

        return response()->json(['ok' => true, 'id' => $post->id, 'slug' => $post->slug]);
    }
}
