import assert from 'node:assert/strict';
import fs from 'node:fs';
assert.ok(fs.existsSync(new URL('../src/app.mjs', import.meta.url)));
console.log('smoke ok');
