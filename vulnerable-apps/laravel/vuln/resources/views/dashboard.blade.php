<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Dashboard — BenchBoard</title></head>
<body>
<h1>Dashboard</h1>
<p>Signed in as {{ auth()->user()->email }} ({{ auth()->user()->role }}).</p>
<ul>
  <li><a href="/posts">Posts</a></li>
  <li><a href="/profile">Profile</a></li>
  <li><a href="/billing">Billing</a></li>
</ul>
<form method="post" action="/logout">@csrf<button>Log out</button></form>
</body>
</html>
