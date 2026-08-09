#!/usr/bin/env node
const target = process.argv[2] || process.env.TARGET || 'http://127.0.0.1:13311';
const token = process.argv[3] || '';
const orgId = process.argv[4] || '2';
const wsUrl = target.replace(/^http/, 'ws') + '/graphql/ws';
const ws = new WebSocket(wsUrl, 'graphql-transport-ws');
const timeout = setTimeout(() => process.exit(2), 5000);
ws.onopen = () => ws.send(JSON.stringify({ type: 'connection_init', payload: { Authorization: token ? `Bearer ${token}` : '' } }));
ws.onmessage = ev => {
  const msg = JSON.parse(ev.data);
  if (msg.type === 'connection_ack') {
    ws.send(JSON.stringify({ id: '1', type: 'subscribe', payload: { query: 'subscription($orgId:ID!){ postUpdated(orgId:$orgId){ id body status } }', variables: { orgId } } }));
  } else if (msg.type === 'next' || msg.type === 'error') {
    console.log(JSON.stringify(msg));
    clearTimeout(timeout);
    ws.close();
    process.exit(0);
  }
};
ws.onerror = () => process.exit(3);
