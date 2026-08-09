<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Search — BenchBoard</title></head>
<body>
<h1>Search</h1>
{{-- Escaped output: the query is rendered with {{ }} (HTML-encoded). --}}
<p>Results for: {{ $q }}</p>
<ul>
@foreach ($rows as $r)
  <li><strong>{{ $r->title }}</strong> — {{ $r->body }} <em>({{ $r->slug }})</em></li>
@endforeach
</ul>
</body>
</html>
