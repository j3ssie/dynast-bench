<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{{ $post->title }} — BenchBoard</title></head>
<body>
{{-- NM-XSS-001: the title is rendered with the escaping {{ }} form (safe, both variants). --}}
<h1>{{ $post->title }}</h1>
<p><em>status: {{ $post->status }}</em></p>
<div>{{ $post->body }}</div>

<h2>Comments</h2>
<ul>
@foreach ($post->comments as $c)
  {{-- Escaped output: the stored comment body is HTML-encoded via {{ }}. --}}
  <li>{{ $c->body }}</li>
@endforeach
</ul>

<form method="post" action="/posts/{{ $post->id }}/comments">
  @csrf
  <input type="text" name="body">
  <button type="submit">Comment</button>
</form>
</body>
</html>
