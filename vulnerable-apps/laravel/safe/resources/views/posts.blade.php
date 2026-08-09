<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Posts — BenchBoard</title></head>
<body>
<h1>Posts</h1>
<ul>
@foreach ($rows as $r)
  <li>{{ $r->title }} <em>({{ $r->slug }})</em></li>
@endforeach
</ul>
</body>
</html>
