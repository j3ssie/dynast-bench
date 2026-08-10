<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>BenchBoard</title></head>
<body>
<h1>BenchBoard</h1>
<p style="color:#a00"><strong>⚠️ INTENTIONALLY VULNERABLE — local benchmark only.</strong></p>

<p>Sign in to your workspace, or <a href="/signup">create an account</a>.</p>

{{-- The navigation is rendered client-side from a session-scoped manifest, and
     every app URL is assembled at runtime from the route registry below. The
     served HTML lists no app routes, so the surface is only visible to a client
     that runs this script and (for the authenticated links) has a session. --}}
<nav data-nav></nav>

<script>
  // Route registry: path segments per link, joined at call time. A full app
  // path never exists as a single string literal - it is assembled by url().
  var API = "";
  var ROUTES = {
    search:   ["search"],
    posts:    ["posts"],
    profile:  ["profile"],
    billing:  ["billing"],
    reports:  ["reports", "titles"],
    adminUsers: ["admin", "users"],
    toolsFetch:   ["tools", "fetch"],
    toolsDownload:["tools", "download"],
    toolsExport:  ["tools", "export"],
    toolsPreview: ["tools", "preview"],
    toolsImport:  ["tools", "import"],
    diagnostics:  ["diagnostics"],
    go:       ["go"]
  };
  function url(name) { return [API].concat(ROUTES[name]).join("/"); }

  fetch("/nav", { headers: { "accept": "application/json" } })
    .then(function (r) { return r.ok ? r.json() : { items: [] }; })
    .then(function (j) {
      var nav = document.querySelector("[data-nav]");
      (j.items || []).forEach(function (it) {
        var a = document.createElement("a");
        a.href = url(it.route);
        a.textContent = it.label;
        a.style.marginRight = "12px";
        nav.appendChild(a);
      });
    })
    .catch(function () {});
</script>
</body>
</html>
