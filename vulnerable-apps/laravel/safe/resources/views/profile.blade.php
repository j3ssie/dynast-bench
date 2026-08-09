<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Profile — BenchBoard</title></head>
<body>
<h1>Profile</h1>
<p>{{ $user->name }} — {{ $user->email }} — role {{ $user->role }}</p>
<form method="post" action="/profile">
  @csrf
  <label>Name <input type="text" name="name" value="{{ $user->name }}"></label><br>
  <label>Email <input type="text" name="email" value="{{ $user->email }}"></label><br>
  <button type="submit">Save</button>
</form>
<form method="post" action="/profile/avatar" enctype="multipart/form-data">
  @csrf
  <input type="file" name="avatar">
  <button type="submit">Upload avatar</button>
</form>
</body>
</html>
