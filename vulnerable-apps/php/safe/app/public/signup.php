<?php require_once __DIR__ . '/../inc/bootstrap.php'; header('Content-Type: text/html'); ?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Create account</title></head><body>
<h1>Create your account</h1><p><small data-step>step 1 of 4</small></p>
<div data-ref-banner></div><div data-panel></div><p data-msg></p>
<button type="button" data-advanced>Advanced</button><div data-advanced-panel></div>
<div data-notice></div>
<script>
  // FIXED DOMXSS-001: the fragment is rendered as text via textContent, never HTML.
  (function(){function ap(){var raw=decodeURIComponent((location.hash||'').replace(/^#/,''));
    document.querySelector('[data-ref-banner]').textContent=raw?('Referred by '+raw):'';}
    ap();window.addEventListener('hashchange',ap);})();
  // FIXED POSTMSG-001: the bridge rejects a foreign origin and renders text.
  window.addEventListener('message',function(ev){if(ev.origin!==window.location.origin)return;var d=ev.data||{};
    if(d.type==='taskflow:notice'){document.querySelector('[data-notice]').textContent=String(d.text||'');}});
  var API='';var ROUTES={start:['api','signup','start.php'],verify:['api','signup','verify.php'],
    profile:['api','signup','profile.php'],complete:['api','signup','complete.php'],
    resend:['api','signup','resend.php'],report:['tools','report.php']};
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
    ap.innerHTML='<h3>Report builder</h3><input data-formula value="strlen(title)"> <button type="button" data-run>Run</button><pre data-out></pre>';
    ap.querySelector('[data-run]').addEventListener('click',function(){
      fetch(url('report'),{method:'POST',headers:{'content-type':'application/json'},
        body:JSON.stringify({formula:ap.querySelector('[data-formula]').value})}).then(function(r){return r.text();})
        .then(function(t){ap.querySelector('[data-out]').textContent=t;});});});
  render(1);
</script></body></html>
