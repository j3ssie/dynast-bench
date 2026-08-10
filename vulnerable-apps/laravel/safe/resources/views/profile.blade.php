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
  // FIXED POSTMSG-001: the bridge rejects any message whose origin is not this
  // app's own, and renders the payload as text, not HTML - so a message from
  // another frame can neither be trusted nor script the page.
  window.addEventListener("message", function (ev) {
    if (ev.origin !== window.location.origin) return;
    var data = ev.data || {};
    if (data.type === "benchboard:notice") {
      document.querySelector("[data-notice]").textContent = String(data.text || "");
    }
  });
</script>
</body>
</html>
