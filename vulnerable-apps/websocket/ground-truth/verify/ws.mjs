#!/usr/bin/env node
const args = process.argv.slice(2);
if (!args.length) process.exit(2);
let url = args.shift();
const sends = [];
let expect = '', token = '', protocol = '', timeout = 1500, sleepBefore = 0;
let sendLarge = 0, rateTest = 0, roomFlood = 0, raceTest = false, socketioAdmin = false;
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--token') token = args[++i];
  else if (a === '--protocol') protocol = args[++i];
  else if (a === '--send') sends.push(args[++i]);
  else if (a === '--expect') expect = args[++i];
  else if (a === '--timeout') timeout = Number(args[++i]);
  else if (a === '--sleep-before-send-ms') sleepBefore = Number(args[++i]);
  else if (a === '--send-large') sendLarge = Number(args[++i]);
  else if (a === '--rate-test') rateTest = Number(args[++i]);
  else if (a === '--room-flood') roomFlood = Number(args[++i]);
  else if (a === '--race-test') raceTest = true;
  else if (a === '--socketio-admin') socketioAdmin = true;
}
if (token) { const u = new URL(url); u.searchParams.set('token', token); url = u.toString(); }
let output = '', okFrames = 0;
const ws = new WebSocket(url, protocol ? [protocol] : undefined);
const done = (code) => { try { ws.close(); } catch {} setTimeout(() => process.exit(code), 20); };
const timer = setTimeout(() => {
  if (expect && output.includes(expect)) return done(0);
  if (!expect && output) return done(0);
  done(1);
}, timeout);
ws.addEventListener('open', async () => {
  if (sleepBefore) await new Promise((r) => setTimeout(r, sleepBefore));
  if (socketioAdmin) { ws.send('40/admin,'); setTimeout(() => ws.send('42/admin,1["stats"]'), 100); return; }
  let id = 1;
  for (const s of sends) ws.send(s);
  if (sendLarge) ws.send(JSON.stringify({ id: id++, type: 'echo', data: { text: 'A'.repeat(sendLarge) } }));
  for (let i = 0; i < rateTest; i++) ws.send(JSON.stringify({ id: id++, type: 'rate.ping', data: {} }));
  for (let i = 0; i < roomFlood; i++) ws.send(JSON.stringify({ id: id++, type: 'subscribe', data: { channel: `room:${i}` } }));
  if (raceTest) {
    ws.send(JSON.stringify({ id: id++, type: 'billing.reset', data: { used: 4 } }));
    setTimeout(() => {
      ws.send(JSON.stringify({ id: id++, type: 'invite.create', data: { email: 'a@example.test' } }));
      ws.send(JSON.stringify({ id: id++, type: 'invite.create', data: { email: 'b@example.test' } }));
      setTimeout(() => ws.send(JSON.stringify({ id: id++, type: 'billing.status', data: {} })), 220);
    }, 30);
  }
});
ws.addEventListener('message', (ev) => {
  const text = String(ev.data);
  console.log(text); output += text + '\n';
  try { const j = JSON.parse(text); if (j.ok) okFrames++; } catch {}
  if (rateTest && okFrames >= rateTest) { console.log(`rate-ok:${okFrames}`); clearTimeout(timer); return done(0); }
  if (roomFlood && okFrames >= roomFlood) { console.log(`room-flood-ok:${okFrames}`); clearTimeout(timer); return done(0); }
  if (raceTest && /"used":6/.test(text)) { clearTimeout(timer); return done(0); }
  if (expect && output.includes(expect)) { clearTimeout(timer); return done(0); }
});
ws.addEventListener('close', () => { setTimeout(() => { if (expect && output.includes(expect)) return done(0); if (rateTest || roomFlood || raceTest || sendLarge) return done(1); }, 50); });
ws.addEventListener('error', () => {});
