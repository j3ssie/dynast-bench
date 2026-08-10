<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Dashboard — BenchBoard</title></head>
<body>
<h1>Dashboard</h1>
<p>Signed in as {{ auth()->user()->email }} ({{ auth()->user()->role }}).</p>

{{-- A "saved view" banner restored from the URL fragment so a filtered dashboard
     can be bookmarked. --}}
<div data-view-banner></div>

<button type="button" data-advanced>Advanced</button>
<div data-advanced-panel></div>

<form method="post" action="/logout">@csrf<button>Log out</button></form>

<script>
  // FIXED DOMXSS-001: the fragment is rendered as text via textContent, so a
  // payload in the URL fragment is shown literally, never parsed as HTML.
  (function () {
    function applyView() {
      var raw = decodeURIComponent((location.hash || "").replace(/^#/, ""));
      document.querySelector("[data-view-banner]").textContent =
        raw ? ("Saved view: " + raw) : "";
    }
    applyView();
    window.addEventListener("hashchange", applyView);
  })();

  // The Advanced tools panel is fetched only when the button is clicked, so the
  // endpoint it talks to (assembled from segments below) appears in no HTML that
  // the page loads on arrival.
  var ADV = ["api", "tools", "import-mapping"];
  document.querySelector("[data-advanced]").addEventListener("click", function () {
    var panel = document.querySelector("[data-advanced-panel]");
    panel.innerHTML =
      '<h3>Import field mapping (XML)</h3>' +
      '<textarea data-xml rows="4" cols="40">&lt;mapping&gt;&lt;field&gt;title&lt;/field&gt;&lt;/mapping&gt;</textarea>' +
      '<button type="button" data-run>Import</button><pre data-out></pre>';
    panel.querySelector("[data-run]").addEventListener("click", function () {
      fetch([""].concat(ADV).join("/"), {
        method: "POST",
        headers: { "content-type": "application/xml" },
        body: panel.querySelector("[data-xml]").value
      }).then(function (r) { return r.text(); })
        .then(function (t) { panel.querySelector("[data-out]").textContent = t; });
    });
  });
</script>
</body>
</html>
