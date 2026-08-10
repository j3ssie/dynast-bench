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

{{-- The companion-widget bridge: other windows post the profile page a notice to
     display. --}}
<div data-notice></div>

<script>
  // VULN POSTMSG-001 (CWE-346/CWE-79): the message bridge handles a message from
  // ANY window, without ever checking event.origin, and writes the payload it is
  // handed into the page as HTML. Any frame or opener that can reach this window
  // scripts it. The safe twin checks the origin and renders text, not HTML.
  window.addEventListener("message", function (ev) {
    var data = ev.data || {};
    if (data.type === "benchboard:notice") {
      document.querySelector("[data-notice]").innerHTML = String(data.html || "");
    }
  });
</script>
</body>
</html>
