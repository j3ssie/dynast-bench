<?php

namespace App\Http\Controllers;

use App\Models\Comment;
use App\Models\Post;
use Illuminate\Http\Request;

class CommentController extends Controller
{
    // XSS-STORED-001 (CWE-79): the comment body is stored verbatim and later
    // rendered by post_show.blade.php through {!! $comment->body !!}, so an
    // attacker's <script> executes for every viewer. The safe twin renders the
    // body with the escaping {{ }} form.
    public function store(Request $request, Post $post)
    {
        $comment = Comment::create([
            'post_id' => $post->id,
            'user_id' => $request->user()->id,
            'body' => (string) $request->input('body', ''),
        ]);

        return redirect('/posts/'.$post->id);
    }
}
