#!/usr/bin/env node
// Deterministic stub helper documented by benchmark-plans/llmchat.md. The app's
// Python backend mirrors these marker-to-completion rules for default verify.
const input = await new Promise((resolve) => { let s = ''; process.stdin.on('data', d => s += d); process.stdin.on('end', () => resolve(s)); });
if (input.includes('[[EMIT_XSS]]')) console.log(`<img src=x onerror=alert('llmchat-xss')>`);
else if (input.includes('[[EMIT_SQL]]')) console.log('SELECT email,password FROM users ORDER BY email');
else if (input.includes('[[EMIT_EXEC]]')) console.log("__import__('os').popen('printf RCE-LLMCHAT-OK').read()");
else console.log('BenchAssist stub answer');
