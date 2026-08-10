<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Create account — BenchBoard</title></head>
<body>
<h1>Create your account</h1>
<p><small data-step>step 1 of 4</small></p>

{{-- The wizard is four independent fetch requests against endpoints assembled at
     runtime from the registry below. Only the step the wizard is currently on is
     ever issued, so the later endpoints exist in no served HTML and are not
     reached until a client has typed an address and submitted. --}}
<div data-panel></div>
<p data-msg></p>

<script>
  var API = "";
  // Path segments per step, joined at call time - no full path is a literal.
  var SIGNUP = {
    start:    ["api", "signup", "start"],
    verify:   ["api", "signup", "verify"],
    profile:  ["api", "signup", "profile"],
    complete: ["api", "signup", "complete"],
    resend:   ["api", "signup", "resend"]
  };
  function url(name) { return [API].concat(SIGNUP[name]).join("/"); }

  var draftId = null, email = "";
  var panel = document.querySelector("[data-panel]");
  var msg = document.querySelector("[data-msg]");
  var stepLabel = document.querySelector("[data-step]");

  function post(name, body) {
    return fetch(url(name), {
      method: "POST",
      headers: { "content-type": "application/json", "accept": "application/json" },
      body: JSON.stringify(body)
    }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); });
  }

  function render(step) {
    var forms = {
      1: '<form data-f="start"><input name="email" placeholder="work email"><button>Continue</button></form>',
      2: '<form data-f="verify"><input name="code" placeholder="6-digit code"><button>Verify</button> <button type="button" data-resend>Resend</button></form>',
      3: '<form data-f="profile"><input name="display_name" placeholder="display name"><button>Continue</button></form>',
      4: '<form data-f="complete"><input name="password" type="password" placeholder="choose a password"><button>Finish</button></form>'
    };
    stepLabel.textContent = "step " + step + " of 4";
    panel.innerHTML = forms[step];
  }

  panel.addEventListener("submit", function (e) {
    e.preventDefault();
    var f = e.target.getAttribute("data-f");
    var fd = new FormData(e.target);
    if (f === "start") {
      email = fd.get("email");
      post("start", { email: email }).then(function (r) {
        if (!r.ok) { msg.textContent = r.j.error || "could not start"; return; }
        draftId = r.j.draftId; msg.textContent = "We emailed you a 6-digit code."; render(2);
      });
    } else if (f === "verify") {
      post("verify", { draftId: draftId, code: fd.get("code") }).then(function (r) {
        if (!r.ok) { msg.textContent = r.j.error || "could not verify"; return; }
        msg.textContent = ""; render(3);
      });
    } else if (f === "profile") {
      post("profile", { draftId: draftId, display_name: fd.get("display_name") }).then(function (r) {
        if (!r.ok) { msg.textContent = r.j.error || "could not save"; return; }
        msg.textContent = ""; render(4);
      });
    } else if (f === "complete") {
      post("complete", { draftId: draftId, password: fd.get("password") }).then(function (r) {
        msg.textContent = r.ok ? ("Welcome, " + r.j.email + " (" + r.j.role + ").") : (r.j.error || "could not finish");
      });
    }
  });

  panel.addEventListener("click", function (e) {
    if (e.target.hasAttribute("data-resend")) {
      post("resend", { email: email }).then(function () { msg.textContent = "If that signup exists, a code is on its way."; });
    }
  });

  render(1);
</script>
</body>
</html>
