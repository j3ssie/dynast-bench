import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import dgram from 'node:dgram';
import fs from 'node:fs';

const ROLE = process.env.ROLE || 'scanner';
const VARIANT = process.env.VARIANT || 'vuln';
const VULN = VARIANT === 'vuln';
const STANDALONE = process.env.STANDALONE === '1';
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || 'benchsecret';
const MARKER = 'GLOBEX-CONFIDENTIAL-MARKER-7f3a';
const bindHost = process.env.BIND_HOST || '0.0.0.0';
const NETMETA_PORT = Number(process.env.NETMETA_PORT || '3000');

const hosts = {
  'edge-proxy': { ip: '10.89.1.10', solo: '127.0.0.10', segment: 'edge', service: 'nginx' },
  'edge-bastion': { ip: '10.89.1.11', solo: '127.0.0.11', segment: 'edge', service: 'ssh' },
  'edge-ftp': { ip: '10.89.1.12', solo: '127.0.0.12', segment: 'edge', service: 'ftp' },
  'edge-mail': { ip: '10.89.1.13', solo: '127.0.0.13', segment: 'edge', service: 'smtp' },
  'app-web': { ip: '10.89.2.10', solo: '127.0.0.20', segment: 'app', service: 'web' },
  'app-legacy': { ip: '10.89.2.11', solo: '127.0.0.21', segment: 'app', service: 'legacy' },
  'data-postgres': { ip: '10.89.3.10', solo: '127.0.0.30', segment: 'data', service: 'postgres' },
  'data-redis': { ip: '10.89.3.11', solo: '127.0.0.31', segment: 'data', service: 'redis' },
  'data-redis-secure': { ip: '10.89.3.12', solo: '127.0.0.32', segment: 'data', service: 'redis-secure' },
  'data-mongo': { ip: '10.89.3.13', solo: '127.0.0.33', segment: 'data', service: 'mongo' },
  'data-elastic': { ip: '10.89.3.14', solo: '127.0.0.34', segment: 'data', service: 'elastic' },
  'data-memcached': { ip: '10.89.3.15', solo: '127.0.0.35', segment: 'data', service: 'memcached' },
  'mgmt-jenkins': { ip: '10.89.4.10', solo: '127.0.0.40', segment: 'mgmt', service: 'jenkins' },
  'mgmt-grafana': { ip: '10.89.4.11', solo: '127.0.0.41', segment: 'mgmt', service: 'grafana' },
  'mgmt-rabbitmq': { ip: '10.89.4.12', solo: '127.0.0.42', segment: 'mgmt', service: 'rabbitmq' },
  'mgmt-phpmyadmin': { ip: '10.89.4.13', solo: '127.0.0.43', segment: 'mgmt', service: 'phpmyadmin' },
  'mgmt-minio': { ip: '10.89.4.14', solo: '127.0.0.44', segment: 'mgmt', service: 'minio' },
  'mgmt-snmp': { ip: '10.89.4.15', solo: '127.0.0.45', segment: 'mgmt', service: 'snmp' },
  'scanner': { ip: '10.89.1.200', solo: '127.0.0.2', segment: 'edge', service: 'netmeta' }
};

const openPorts = [
  ['edge-proxy',80,'tcp','nginx http','nginx/1.19.0'],
  ['edge-proxy',443,'tcp','nginx https weak-tls','nginx/1.19.0 OpenSSL/1.0.1'],
  ['edge-proxy',8443,'tcp','nginx https strong near-miss','nginx/1.27 TLSv1.3'],
  ['edge-proxy',3306,'tcp','mysql decoy','filtered'],
  ['edge-bastion',22,'tcp','ssh','OpenSSH_7.2p2'],
  ['edge-bastion',2222,'tcp','ssh hardened near-miss','OpenSSH_9.7 key-only'],
  ['edge-ftp',21,'tcp','ftp','Pure-FTPd anonymous'],
  ...Array.from({length:10}, (_,i)=>['edge-ftp',30000+i,'tcp','ftp passive','Pure-FTPd passive']),
  ['edge-mail',25,'tcp','smtp','Postfix open-relay no-starttls'],
  ['app-web',8080,'tcp','http app','bench-web/1.0'],
  ['app-web',31337,'tcp','rogue bind shell','bench-shell'],
  ['app-legacy',23,'tcp','telnet','BusyBox telnetd cleartext'],
  ['app-legacy',8000,'tcp','legacy http','Apache-Coyote/1.1 vulnerable'],
  ['data-postgres',5432,'tcp','postgres','PostgreSQL 16 trust'],
  ['data-redis',6379,'tcp','redis','Redis 7 noauth'],
  ['data-redis-secure',6380,'tcp','redis secure near-miss','Redis 7 requirepass'],
  ['data-mongo',27017,'tcp','mongodb','MongoDB 7 noauth'],
  ['data-elastic',9200,'tcp','elasticsearch http','Elasticsearch 8 security-disabled'],
  ['data-elastic',9300,'tcp','elasticsearch transport','Elasticsearch transport no-tls'],
  ['data-memcached',11211,'tcp','memcached','memcached noauth'],
  ['data-memcached',11211,'udp','memcached udp','memcached udp enabled'],
  ['mgmt-jenkins',8080,'tcp','jenkins','Jenkins anonymous script-console'],
  ['mgmt-grafana',3000,'tcp','grafana','Grafana 11 default-admin anonymous'],
  ['mgmt-rabbitmq',5672,'tcp','amqp','RabbitMQ guest/guest'],
  ['mgmt-rabbitmq',15672,'tcp','rabbitmq management','RabbitMQ management guest/guest'],
  ['mgmt-phpmyadmin',8081,'tcp','phpmyadmin','phpMyAdmin AllowNoPassword'],
  ['mgmt-minio',9000,'tcp','minio api','MinIO default-root anonymous-bucket'],
  ['mgmt-minio',9001,'tcp','minio console','MinIO console default-root'],
  ['mgmt-snmp',161,'udp','snmp','SNMPv2c public'],
  ['scanner',3000,'tcp','netmeta api','network-benchmark netmeta']
].map(([host,port,proto,service,version]) => ({ host, ip: hosts[host].ip, segment: hosts[host].segment, port, proto, service, version, state: version === 'filtered' ? 'filtered' : 'open' }));

const checkMeta = {
  'tls_expired': ['edge-proxy',443,'Expired self-signed certificate accepted'],
  'tls_weak': ['edge-proxy',443,'TLSv1.0 / weak cipher suite offered'],
  'cleartext_http': ['edge-proxy',80,'Admin/API content served over cleartext HTTP'],
  'status_exposed': ['edge-proxy',80,'/nginx_status and /server-status exposed'],
  'proxy_internal': ['edge-proxy',80,'/internal/* proxies from edge to data tier'],
  'ssh_weak_root': ['edge-bastion',22,'root/admin password login accepted'],
  'ssh_old_banner': ['edge-bastion',22,'OpenSSH_7.2p2 banner maps to known CVEs'],
  'ftp_anon': ['edge-ftp',21,'anonymous FTP read/write accepted'],
  'ftp_cleartext': ['edge-ftp',21,'FTP is cleartext and FTPS is not required'],
  'smtp_relay': ['edge-mail',25,'unauthenticated relay accepted'],
  'smtp_vrfy_no_starttls': ['edge-mail',25,'VRFY enumerates users and STARTTLS absent'],
  'rogue_port': ['app-web',31337,'unexpected unauthenticated bind shell'],
  'telnet_open': ['app-legacy',23,'cleartext telnet admin service'],
  'legacy_banner': ['app-legacy',8000,'legacy HTTP banner advertises vulnerable version'],
  'pg_trust': ['data-postgres',5432,'Postgres trust authentication exposes seeded rows'],
  'redis_open': ['data-redis',6379,'Redis PING/GET works without AUTH'],
  'mongo_open': ['data-mongo',27017,'Mongo database readable without auth'],
  'elastic_open': ['data-elastic',9200,'Elasticsearch security disabled and marker searchable'],
  'memcached_open': ['data-memcached',11211,'Memcached TCP/UDP no-auth marker read'],
  'seg_edge_to_data': ['data-redis',6379,'edge segment can reach data tier'],
  'jenkins_anon': ['mgmt-jenkins',8080,'Jenkins anonymous script console reachable'],
  'grafana_default': ['mgmt-grafana',3000,'Grafana admin/Admin123! and anonymous view enabled'],
  'rabbit_default': ['mgmt-rabbitmq',15672,'RabbitMQ guest/guest management UI exposed'],
  'phpmyadmin_nopass': ['mgmt-phpmyadmin',8081,'phpMyAdmin root no-password login accepted'],
  'minio_default': ['mgmt-minio',9000,'MinIO default root credential and anonymous bucket'],
  'snmp_public': ['mgmt-snmp',161,'SNMP public community walk returns system data'],
  'seg_app_to_mgmt': ['mgmt-jenkins',8080,'app segment can reach management tier'],
  'headers_missing': ['edge-proxy',80,'security headers missing and verbose Server banner'],
  'marker_leak': ['data-redis',6379,'seeded Globex confidential marker leaks from no-auth datastores'],
  'ssh_no_rate_limit': ['edge-bastion',22,'no SSH rate limit or lockout for credential stuffing'],
  'ftp_passive_range': ['edge-ftp',30000,'wide FTP passive port range open'],
  'default_admin_admin': ['edge-bastion',22,'shared admin/admin service credential remains valid']
};

function send(res, code, body, headers={}) {
  const payload = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
  res.writeHead(code, { 'content-type': typeof body === 'string' ? 'text/plain' : 'application/json', 'content-length': Buffer.byteLength(payload), 'connection': 'close', ...headers });
  res.end(payload);
}

function parseBody(req) {
  return new Promise(resolve => {
    let data = '';
    req.on('data', c => { data += c; });
    req.on('end', () => resolve(data));
  });
}

function tokenOK(req) {
  return req.headers['x-verify-token'] === VERIFY_TOKEN;
}

function checkResult(check) {
  const meta = checkMeta[check];
  if (!meta) return null;
  const [host, port, evidence] = meta;
  return {
    check,
    vulnerable: VULN,
    variant: VARIANT,
    host,
    port,
    segment: hosts[host].segment,
    evidence: VULN ? `${evidence}; marker=${MARKER}` : `hardened: ${evidence} no longer exploitable`,
    marker: VULN && ['redis_open','mongo_open','elastic_open','memcached_open','pg_trust','marker_leak','proxy_internal','seg_edge_to_data'].includes(check) ? MARKER : null
  };
}

function startHttp(port, handler, host=bindHost, name=`http:${port}`) {
  const srv = http.createServer(handler);
  srv.listen(port, host, () => console.log(`[${ROLE}] ${name} listening on ${host}:${port}`));
}

function startHttps(port, handler, tlsMode, host=bindHost) {
  const opts = {
    key: fs.readFileSync('/app/tls/server.key'),
    cert: fs.readFileSync('/app/tls/server.crt'),
    minVersion: tlsMode === 'weak' ? 'TLSv1' : 'TLSv1.3'
  };
  const srv = https.createServer(opts, handler);
  srv.listen(port, host, () => console.log(`[${ROLE}] https:${port}/${tlsMode} listening on ${host}:${port}`));
}

function startTcp(port, onLine, host=bindHost, banner='') {
  const srv = net.createServer(sock => {
    sock.setEncoding('utf8');
    if (banner) sock.write(banner);
    let buf = '';
    sock.on('data', data => {
      buf += data;
      if (buf.includes('\n') || buf.includes('\r')) {
        const line = buf.trim();
        buf = '';
        const out = onLine(line, sock);
        if (out !== undefined && out !== null) sock.write(out);
      }
    });
  });
  srv.listen(port, host, () => console.log(`[${ROLE}] tcp:${port} listening on ${host}:${port}`));
}

function startUdp(port, onMsg, host=bindHost) {
  const srv = dgram.createSocket('udp4');
  srv.on('message', (msg, rinfo) => {
    const out = onMsg(msg.toString());
    if (out) srv.send(Buffer.from(out), rinfo.port, rinfo.address);
  });
  srv.bind(port, host, () => console.log(`[${ROLE}] udp:${port} listening on ${host}:${port}`));
}

function startScanner(host=bindHost) {
  startHttp(NETMETA_PORT, async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (url.pathname === '/api/_verify/health') {
      return send(res, 200, { status: 'ok', variant: VARIANT, app: 'network', hosts: Object.keys(hosts).length, checks: Object.keys(checkMeta).length });
    }
    if (!tokenOK(req)) return send(res, 403, { error: 'bad verify token' });
    if (url.pathname === '/api/_verify/ports') {
      const hostQ = url.searchParams.get('host');
      const ports = openPorts.filter(p => !hostQ || p.host === hostQ);
      return send(res, 200, { variant: VARIANT, ports });
    }
    if (url.pathname === '/api/_verify/probe') {
      const check = url.searchParams.get('check') || '';
      const result = checkResult(check);
      if (!result) return send(res, 404, { error: 'unknown check', check });
      return send(res, 200, result);
    }
    return send(res, 404, { error: 'not found' });
  }, host, 'netmeta');
}

function startEdgeProxy(host=bindHost) {
  const handler = (req, res) => {
    if (!VULN) {
      if (req.url.startsWith('/internal/') || req.url === '/nginx_status' || req.url === '/server-status') return send(res, 403, 'forbidden', { 'strict-transport-security': 'max-age=63072000', 'x-content-type-options': 'nosniff' });
      return send(res, 301, 'https required', { location: 'https://edge-proxy/', 'strict-transport-security': 'max-age=63072000', 'x-content-type-options': 'nosniff' });
    }
    if (req.url === '/nginx_status' || req.url === '/server-status') return send(res, 200, 'Active connections: 1\nserver accepts handled requests\n 1 1 1\n', { server: 'nginx/1.19.0' });
    if (req.url.startsWith('/internal/')) return send(res, 200, `proxied data-tier marker ${MARKER}\n`, { server: 'nginx/1.19.0' });
    return send(res, 200, 'Bench admin API over cleartext HTTP\n', { server: 'nginx/1.19.0' });
  };
  startHttp(80, handler, host, 'edge-http');
  startHttps(443, handler, VULN ? 'weak' : 'strong', host);
  startHttps(8443, (req,res) => send(res, 200, 'strong TLS near-miss\n', { 'strict-transport-security': 'max-age=63072000', 'x-content-type-options': 'nosniff' }), 'strong', host);
}

function startEdgeBastion(host=bindHost) {
  startTcp(22, line => {
    if (!VULN) return 'Permission denied (publickey).\r\n';
    if (/admin|root|password/i.test(line)) return `login accepted; service-cred=admin/admin; marker=${MARKER}\r\n`;
    return 'PasswordAuthentication yes; PermitRootLogin yes; try admin/admin\r\n';
  }, host, VULN ? 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10\r\n' : 'SSH-2.0-OpenSSH_9.7 key-only\r\n');
  startTcp(2222, () => 'Permission denied (publickey).\r\n', host, 'SSH-2.0-OpenSSH_9.7 key-only\r\n');
}

function startEdgeFtp(host=bindHost) {
  startTcp(21, line => {
    if (!VULN) return '530 anonymous disabled; AUTH TLS required\r\n';
    if (/^USER anonymous/i.test(line)) return '331 Anonymous login ok, send password\r\n';
    if (/^PASS/i.test(line)) return `230 Anonymous access granted; marker=${MARKER}\r\n`;
    if (/^STOR|^RETR|^LIST/i.test(line)) return '150 opening cleartext data connection\r\n226 transfer complete\r\n';
    return '220 Pure-FTPd anonymous cleartext ready\r\n';
  }, host, VULN ? '220 Pure-FTPd anonymous FTP ready\r\n' : '220 Pure-FTPd FTPS-only ready\r\n');
  if (VULN) for (let p=30000; p<=30009; p++) startTcp(p, () => '220 passive data socket\r\n', host, '');
}

function startEdgeMail(host=bindHost) {
  startTcp(25, line => {
    if (!VULN) {
      if (/STARTTLS/i.test(line)) return '220 Ready to start TLS\r\n';
      if (/RCPT TO:<outside@external.test>/i.test(line)) return '554 relay access denied\r\n';
      return '250-auth required\r\n250-STARTTLS\r\n';
    }
    if (/VRFY/i.test(line)) return '250 admin@bench.local\r\n';
    if (/STARTTLS/i.test(line)) return '454 TLS not available\r\n';
    if (/RCPT TO:<outside@external.test>/i.test(line)) return '250 2.1.5 Ok relay accepted\r\n';
    return '250 OK open relay\r\n';
  }, host, VULN ? '220 bench-mail ESMTP Postfix no STARTTLS\r\n' : '220 bench-mail ESMTP Postfix hardened\r\n');
}

function startAppWeb(host=bindHost) {
  startHttp(8080, (req,res) => send(res, 200, `Bench SaaS demo users: admin@bench.local user1@bench.local user2@bench.local ${MARKER}\n`), host, 'app-web');
  if (VULN) startTcp(31337, line => line ? `uid=0(root) simulated shell: ${line}\n` : 'bench bind shell ready\n', host, 'bench bind shell ready\n');
}

function startAppLegacy(host=bindHost) {
  if (VULN) startTcp(23, line => /admin/i.test(line) ? 'Welcome admin (cleartext telnet)\r\n' : 'login: ', host, 'BusyBox telnetd ready\r\nlogin: ');
  startHttp(8000, (req,res) => send(res, 200, VULN ? 'Apache-Coyote/1.1 vulnerable legacy endpoint\n' : 'nginx/1.27 patched legacy replacement\n', { server: VULN ? 'Apache-Coyote/1.1' : 'nginx/1.27' }), host, 'legacy-http');
}

function startPostgres(host=bindHost) {
  startTcp(5432, line => VULN ? `PostgreSQL trust auth ok; SELECT body='${MARKER}'\n` : 'FATAL: password authentication failed; scram-sha-256 required\n', host, VULN ? 'PostgreSQL 16 trust ready\n' : 'PostgreSQL 16 scram-sha-256 ready\n');
}

function startRedis(host=bindHost, secure=false) {
  startTcp(secure ? 6380 : 6379, line => {
    const l = line.toUpperCase();
    if (secure || !VULN) {
      if (l.includes('AUTH') && line.includes('S3cure')) return '+OK\r\n';
      return '-NOAUTH Authentication required.\r\n';
    }
    if (l.includes('PING')) return '+PONG\r\n';
    if (l.includes('GET') || l.includes('KEYS')) return `$${MARKER.length}\r\n${MARKER}\r\n`;
    return '+OK noauth redis\r\n';
  }, host, VULN && !secure ? '+Redis noauth ready\r\n' : '+Redis requirepass ready\r\n');
}

function startMongo(host=bindHost) {
  startTcp(27017, () => VULN ? `MongoDB no-auth bench.posts body=${MARKER}\n` : 'MongoDB auth required\n', host, VULN ? 'MongoDB 7 noauth ready\n' : 'MongoDB 7 auth enabled\n');
}

function startElastic(host=bindHost) {
  startHttp(9200, (req,res) => {
    if (!VULN) return send(res, 401, { error: 'security_exception', reason: 'missing authentication credentials' });
    return send(res, 200, { cluster_name: 'bench-elastic', security: 'disabled', hits: [{ _source: { org: 'Globex', body: MARKER } }] });
  }, host, 'elastic-http');
  startTcp(9300, () => VULN ? 'Elasticsearch transport no TLS\n' : 'TLS required\n', host, VULN ? 'ES transport plaintext\n' : 'ES transport TLS\n');
}

function startMemcached(host=bindHost) {
  startTcp(11211, line => VULN ? `VALUE marker 0 ${MARKER.length}\r\n${MARKER}\r\nEND\r\n` : 'CLIENT_ERROR authentication required\r\n', host, '');
  if (VULN) startUdp(11211, () => `VALUE marker 0 ${MARKER.length}\r\n${MARKER}\r\nEND\r\n`, host);
}

function startJenkins(host=bindHost) {
  startHttp(8080, (req,res) => {
    if (!VULN) return send(res, 403, 'authentication required');
    if (req.url.startsWith('/script')) return send(res, 200, `Jenkins script console anonymous; println '${MARKER}'\n`);
    return send(res, 200, 'Jenkins anonymous read enabled\n');
  }, host, 'jenkins');
}

function startGrafana(host=bindHost) {
  startHttp(3000, async (req,res) => {
    if (req.url.startsWith('/api/login') || req.url.startsWith('/login')) {
      const body = await parseBody(req);
      if (VULN && body.includes('admin') && body.includes('Admin123')) return send(res, 200, { message: 'Logged in', marker: MARKER });
      return send(res, 401, { message: 'Invalid username or password' });
    }
    if (VULN) return send(res, 200, 'Grafana anonymous dashboard view enabled\n');
    return send(res, 302, 'login required', { location: '/login' });
  }, host, 'grafana');
}

function startRabbit(host=bindHost) {
  startTcp(5672, () => VULN ? 'AMQP guest/guest accepted\n' : 'AMQP default guest disabled\n', host, 'AMQP 0-0-9-1\r\n');
  startHttp(15672, (req,res) => {
    const auth = req.headers.authorization || '';
    if (VULN && auth === 'Basic Z3Vlc3Q6Z3Vlc3Q=') return send(res, 200, { management: 'ok', marker: MARKER });
    return send(res, 401, 'authentication required', { 'www-authenticate': 'Basic realm="RabbitMQ"' });
  }, host, 'rabbit-management');
}

function startPhpMyAdmin(host=bindHost) {
  startHttp(8081, async (req,res) => {
    const body = await parseBody(req);
    if (VULN && (req.method === 'GET' || body.includes('pma_username=root'))) return send(res, 200, `phpMyAdmin AllowNoPassword root login; ${MARKER}\n`);
    return send(res, 403, 'AllowNoPassword disabled');
  }, host, 'phpmyadmin');
}

function startMinio(host=bindHost) {
  const handler = async (req,res) => {
    const auth = req.headers.authorization || '';
    if (VULN && (auth.includes('minioadmin') || req.url.includes('/public'))) return send(res, 200, `MinIO public bucket ${MARKER}\n`);
    if (VULN && req.url === '/') return send(res, 200, 'MinIO console default root minioadmin/minioadmin\n');
    return send(res, 403, 'private bucket; root credential rotated');
  };
  startHttp(9000, handler, host, 'minio-api');
  startHttp(9001, handler, host, 'minio-console');
}

function startSnmp(host=bindHost) {
  startUdp(161, msg => VULN && msg.toLowerCase().includes('public') ? `SNMPv2-MIB::sysDescr.0 = bench-router ${MARKER}\n` : '', host);
}

function startRole(role, host=bindHost) {
  switch(role) {
    case 'scanner': return startScanner(host);
    case 'edge-proxy': return startEdgeProxy(host);
    case 'edge-bastion': return startEdgeBastion(host);
    case 'edge-ftp': return startEdgeFtp(host);
    case 'edge-mail': return startEdgeMail(host);
    case 'app-web': return startAppWeb(host);
    case 'app-legacy': return startAppLegacy(host);
    case 'data-postgres': return startPostgres(host);
    case 'data-redis': return startRedis(host, false);
    case 'data-redis-secure': return startRedis(host, true);
    case 'data-mongo': return startMongo(host);
    case 'data-elastic': return startElastic(host);
    case 'data-memcached': return startMemcached(host);
    case 'mgmt-jenkins': return startJenkins(host);
    case 'mgmt-grafana': return startGrafana(host);
    case 'mgmt-rabbitmq': return startRabbit(host);
    case 'mgmt-phpmyadmin': return startPhpMyAdmin(host);
    case 'mgmt-minio': return startMinio(host);
    case 'mgmt-snmp': return startSnmp(host);
    default:
      console.error(`unknown ROLE ${role}`);
      process.exit(2);
  }
}

if (STANDALONE) {
  for (const [name, meta] of Object.entries(hosts)) {
    if (name === 'scanner') continue;
    startRole(name, meta.solo);
  }
  startScanner(process.env.NETMETA_BIND || '0.0.0.0');
} else {
  startRole(ROLE, bindHost);
}

setInterval(() => {}, 1 << 30);
