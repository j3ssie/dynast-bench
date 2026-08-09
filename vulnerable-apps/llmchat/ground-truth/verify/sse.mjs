#!/usr/bin/env node
// Minimal SSE/HTTP helper reserved for llmchat streaming PoCs.
const url = process.argv[2];
if (!url) process.exit(2);
const res = await fetch(url, { method: 'POST', headers: {'content-type':'application/json'}, body: process.argv[3] || '{}' });
process.stdout.write(await res.text());
