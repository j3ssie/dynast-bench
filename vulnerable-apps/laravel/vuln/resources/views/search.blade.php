<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Search — BenchBoard</title></head>
<body>
<h1>Search</h1>
{{-- XSS-REFLECT-001 (CWE-79): the raw query is echoed with the unescaped {!! !!}. --}}
<p>Results for: {!! $q !!}</p>
<ul>
@foreach ($rows as $r)
  <li><strong>{{ $r->title }}</strong> — {{ $r->body }} <em>({{ $r->slug }})</em></li>
@endforeach
</ul>
</body>
</html>
