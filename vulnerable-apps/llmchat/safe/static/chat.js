// Intentionally vulnerable rendering path for LLM output. The safe twin flips the
// server-side feature flag so responses are escaped before this HTML sink.
async function login(email, password) {
  const res = await fetch('/api/auth/login', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({email, password})});
  return res.json();
}
function renderAssistant(markdown) {
  const el = document.getElementById('chat');
  if (el) el.innerHTML = markdown;
}
window.llmchat = { login, renderAssistant };
