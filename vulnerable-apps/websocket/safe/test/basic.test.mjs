import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

test('server source exists and declares websocket benchmark', () => {
  const src = fs.readFileSync(new URL('../src/server.mjs', import.meta.url), 'utf8');
  assert.match(src, /WebSocketServer/);
  assert.match(src, /SocketIOServer/);
});
