package com.bench.springboot;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

// The four-step registration wizard (start -> verify -> profile -> complete). The
// server keeps flow state in a signup_drafts row, so each step is its own request
// carrying only the draft id. Driven by fetch from the wizard page, so these
// endpoints appear nowhere in served HTML.
@RestController
class SignupController {
    private final SignupDraftRepository drafts;
    private final UserRepository users;
    private final OrgRepository orgs;
    private final PasswordEncoder encoder;
    private final Map<String, Integer> resendCounts = new ConcurrentHashMap<>();

    SignupController(SignupDraftRepository drafts, UserRepository users, OrgRepository orgs, PasswordEncoder encoder) {
        this.drafts = drafts; this.users = users; this.orgs = orgs; this.encoder = encoder;
    }

    // SIGNUP-TOKEN-001 (CWE-330/CWE-640): the emailed verification code is the last
    // six digits of the wall clock, not a CSPRNG draw, so it can be recomputed
    // instead of received. The safe twin uses SecureRandom.
    private String signupCode() {
        return String.valueOf(System.currentTimeMillis() / 1000L % 1000000L);
    }

    // NEAR-MISS NM-SIGNUP-TOKEN-001: the same job done correctly with the CSPRNG.
    private String inviteToken() {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    // SIGNUP-ENUM-001 (CWE-204): step 1 answers 409 for a registered address and
    // 200 for an unknown one - a pre-auth enumeration oracle. Safe twin always 200s.
    @PostMapping("/api/signup/start")
    ResponseEntity<Map<String, Object>> start(@RequestBody Map<String, Object> body) {
        String email = String.valueOf(body.getOrDefault("email", ""));
        if (email.isEmpty()) return ResponseEntity.badRequest().body(Map.of("error", "email required"));
        if (users.findByEmail(email).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "that email is already registered", "registered", true));
        }
        SignupDraft d = drafts.save(new SignupDraft(email, signupCode()));
        return ResponseEntity.ok(Map.of("draftId", d.getId(), "step", "verify"));
    }

    @PostMapping("/api/signup/verify")
    ResponseEntity<Map<String, Object>> verify(@RequestBody Map<String, Object> body) {
        SignupDraft d = drafts.findById(asLong(body.get("draftId"))).orElse(null);
        if (d == null) return ResponseEntity.status(404).body(Map.of("error", "unknown draft"));
        if (!d.getCode().equals(String.valueOf(body.getOrDefault("code", "")))) {
            return ResponseEntity.badRequest().body(Map.of("error", "incorrect code"));
        }
        d.setVerified(true); drafts.save(d);
        return ResponseEntity.ok(Map.of("ok", true, "step", "profile"));
    }

    // SIGNUP-MASSASSIGN-001 (CWE-915): the profile step copies role and org_slug
    // from the body onto the draft - the two fields the final step hands to the new
    // user - so a crafted body registers an admin or joins another tenant.
    @PostMapping("/api/signup/profile")
    ResponseEntity<Map<String, Object>> profile(@RequestBody Map<String, Object> body) {
        SignupDraft d = drafts.findById(asLong(body.get("draftId"))).orElse(null);
        if (d == null) return ResponseEntity.status(404).body(Map.of("error", "unknown draft"));
        if (body.containsKey("display_name")) d.setDisplayName(String.valueOf(body.get("display_name")));
        if (body.containsKey("role")) d.setRole(String.valueOf(body.get("role")));
        if (body.containsKey("org_slug")) d.setOrgSlug(String.valueOf(body.get("org_slug")));
        drafts.save(d);
        return ResponseEntity.ok(Map.of("ok", true, "step", "complete", "displayName", d.getDisplayName()));
    }

    // SIGNUP-STEPSKIP-001 (CWE-841): the final step never checks that the draft
    // reached the verified state, so posting straight to it registers an
    // unverified, unowned mailbox as a real user.
    @PostMapping("/api/signup/complete")
    ResponseEntity<Map<String, Object>> complete(@RequestBody Map<String, Object> body) {
        SignupDraft d = drafts.findById(asLong(body.get("draftId"))).orElse(null);
        if (d == null) return ResponseEntity.status(404).body(Map.of("error", "unknown draft"));
        if (d.isCompleted()) return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "already completed"));
        Org org = orgs.findBySlug(d.getOrgSlug()).orElse(null);
        if (org == null) return ResponseEntity.badRequest().body(Map.of("error", "unknown org"));
        String pw = encoder.encode(String.valueOf(body.getOrDefault("password", "Changeme123!")));
        String name = d.getDisplayName().isEmpty() ? "New User" : d.getDisplayName();
        BenchUser u = users.save(new BenchUser(d.getEmail(), pw, d.getRole(), "admin".equals(d.getRole()), d.isVerified(), org, name));
        d.setCompleted(true); drafts.save(d);
        return ResponseEntity.ok(Map.of("ok", true, "id", u.getId(), "email", u.getEmail(), "role", u.getRole()));
    }

    // SIGNUP-IDOR-001 (CWE-639): any draft is readable by its serial id,
    // unauthenticated, and the row carries the email AND the verification code
    // emailed to it - count down to walk every registration in progress.
    @GetMapping("/api/signup/draft/{id}")
    ResponseEntity<Map<String, Object>> draft(@PathVariable Long id) {
        SignupDraft d = drafts.findById(id).orElse(null);
        if (d == null) return ResponseEntity.status(404).body(Map.of("error", "unknown draft"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", d.getId()); out.put("email", d.getEmail()); out.put("code", d.getCode());
        out.put("verified", d.isVerified()); out.put("display_name", d.getDisplayName());
        out.put("role", d.getRole()); out.put("org_slug", d.getOrgSlug()); out.put("completed", d.isCompleted());
        return ResponseEntity.ok(out);
    }

    // NEAR-MISS NM-SIGNUP-RESEND-001: same pre-auth "does this address exist" shape
    // as start(), but the response is constant and it is rate limited per address.
    @PostMapping("/api/signup/resend")
    Map<String, Object> resend(@RequestBody Map<String, Object> body) {
        String email = String.valueOf(body.getOrDefault("email", "")).toLowerCase();
        Map<String, Object> constant = Map.of("ok", true, "message", "if that signup exists, a code is on its way");
        if (email.isEmpty()) return constant;
        resendCounts.merge(email, 1, Integer::sum);
        return constant;
    }

    // CONFIGDUMP-001 (CWE-200/CWE-215): the hidden "report builder" backend returns
    // the full process environment (including SPRINGBOOT_ACTUATOR_SECRET and the DB
    // credentials) for any non-"public" section. Referenced only from the wizard's
    // Advanced panel. The safe twin returns only an allow-listed public subset.
    @PostMapping("/api/tools/report")
    Map<String, Object> report(@RequestBody Map<String, Object> body) {
        String section = String.valueOf(body.getOrDefault("section", "all"));
        Map<String, Object> out = new LinkedHashMap<>();
        if ("public".equals(section)) {
            out.put("appName", "TaskFlow"); out.put("locale", "en-US");
            return out;
        }
        out.put("env", new TreeMap<>(System.getenv()));
        out.put("props", System.getProperties());
        return out;
    }

    @GetMapping(value = "/signup", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    String wizard() {
        return WIZARD_HTML;
    }

    private static Long asLong(Object v) {
        if (v == null) return -1L;
        try { return Long.parseLong(String.valueOf(v)); } catch (NumberFormatException e) { return -1L; }
    }

    static final String WIZARD_HTML = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Create account</title></head><body>
<h1>Create your account</h1><p><small data-step>step 1 of 4</small></p>
<div data-ref-banner></div><div data-panel></div><p data-msg></p>
<button type="button" data-advanced>Advanced</button><div data-advanced-panel></div>
<div data-notice></div>
<script>
  // VULN DOMXSS-001 (CWE-79): the URL fragment is read from location.hash and
  // written into the page with innerHTML - the payload never reaches the server.
  (function(){function ap(){var raw=decodeURIComponent((location.hash||'').replace(/^#/,''));
    document.querySelector('[data-ref-banner]').innerHTML=raw?('Referred by <b>'+raw+'</b>'):'';}
    ap();window.addEventListener('hashchange',ap);})();
  // VULN POSTMSG-001 (CWE-346/CWE-79): the bridge handles a message from ANY
  // window without checking event.origin and writes the payload as HTML.
  window.addEventListener('message',function(ev){var d=ev.data||{};
    if(d.type==='taskflow:notice'){document.querySelector('[data-notice]').innerHTML=String(d.html||'');}});
  var API='';var ROUTES={start:['api','signup','start'],verify:['api','signup','verify'],
    profile:['api','signup','profile'],complete:['api','signup','complete'],
    resend:['api','signup','resend'],report:['api','tools','report']};
  function url(n){return [API].concat(ROUTES[n]).join('/');}
  var draftId=null,email='';var panel=document.querySelector('[data-panel]');
  var msg=document.querySelector('[data-msg]');var stepLabel=document.querySelector('[data-step]');
  function post(n,b){return fetch(url(n),{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify(b)}).then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});});}
  function render(s){var f={1:'<form data-f="start"><input name="email" placeholder="work email"><button>Continue</button></form>',
    2:'<form data-f="verify"><input name="code" placeholder="6-digit code"><button>Verify</button> <button type="button" data-resend>Resend</button></form>',
    3:'<form data-f="profile"><input name="display_name" placeholder="display name"><button>Continue</button></form>',
    4:'<form data-f="complete"><input name="password" type="password" placeholder="choose a password"><button>Finish</button></form>'};
    stepLabel.textContent='step '+s+' of 4';panel.innerHTML=f[s];}
  panel.addEventListener('submit',function(e){e.preventDefault();var f=e.target.getAttribute('data-f');
    var fd=new FormData(e.target);
    if(f==='start'){email=fd.get('email');post('start',{email:email}).then(function(r){
      if(!r.ok){msg.textContent=r.j.error||'could not start';return;}draftId=r.j.draftId;
      msg.textContent='We emailed you a 6-digit code.';render(2);});}
    else if(f==='verify'){post('verify',{draftId:draftId,code:fd.get('code')}).then(function(r){
      if(!r.ok){msg.textContent=r.j.error||'could not verify';return;}msg.textContent='';render(3);});}
    else if(f==='profile'){post('profile',{draftId:draftId,display_name:fd.get('display_name')}).then(function(r){
      if(!r.ok){msg.textContent=r.j.error||'could not save';return;}msg.textContent='';render(4);});}
    else if(f==='complete'){post('complete',{draftId:draftId,password:fd.get('password')}).then(function(r){
      msg.textContent=r.ok?('Welcome, '+r.j.email+' ('+r.j.role+').'):(r.j.error||'could not finish');});}});
  panel.addEventListener('click',function(e){if(e.target.hasAttribute('data-resend')){
    post('resend',{email:email}).then(function(){msg.textContent='If that signup exists, a code is on its way.';});}});
  document.querySelector('[data-advanced]').addEventListener('click',function(){
    var ap=document.querySelector('[data-advanced-panel]');
    ap.innerHTML='<h3>Report builder</h3><button type="button" data-run>Load config</button><pre data-out></pre>';
    ap.querySelector('[data-run]').addEventListener('click',function(){
      fetch(url('report'),{method:'POST',headers:{'content-type':'application/json'},
        body:JSON.stringify({section:'all'})}).then(function(r){return r.text();})
        .then(function(t){ap.querySelector('[data-out]').textContent=t;});});});
  render(1);
</script></body></html>
""";
}
