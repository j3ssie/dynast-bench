<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Login — BenchBoard</title></head>
<body>
<h1>Login</h1>
<form method="post" action="/login">
  @csrf
  <label>Email <input type="text" name="email"></label><br>
  <label>Password <input type="password" name="password"></label><br>
  <button type="submit">Sign in</button>
</form>
</body>
</html>
