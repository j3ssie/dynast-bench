import http from 'node:http';
http.createServer((req, res) => {
  const url = new URL(req.url || '/', 'http://billing-svc:9099');
  res.setHeader('content-type', 'text/plain; charset=utf-8');
  if (url.pathname === '/internal/secret') return res.end('BILLING-INTERNAL-SECRET-8d12');
  if (url.pathname === '/balance') return res.end(`billing-balance:org=${url.searchParams.get('orgId') || 'unknown'}:BILLING-INTERNAL-SECRET-8d12`);
  res.end('billing-svc ok');
}).listen(9099, '0.0.0.0');
