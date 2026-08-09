<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Register — BenchBoard</title></head>
<body>
<h1>Register</h1>
<form method="post" action="/register">
  @csrf
  <label>Name <input type="text" name="name"></label><br>
  <label>Email <input type="text" name="email"></label><br>
  <label>Password <input type="password" name="password"></label><br>
  <button type="submit">Create account</button>
</form>
</body>
</html>
