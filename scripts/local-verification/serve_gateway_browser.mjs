// Disposable, loopback-only static frontend + transparent real gateway proxy.
// No fixture responses, credentials, request bodies or WebSocket frames are logged.
import { createServer, request } from 'node:http';
import { readFile, realpath } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';

const [build, upstream, requestedPort = '0'] = process.argv.slice(2);
if (!build || !upstream) throw new Error('Usage: node serve_gateway_browser.mjs BUILD GATEWAY [PORT]');
const root = await realpath(build);
const gateway = new URL(upstream);
if (gateway.protocol !== 'http:' || gateway.hostname !== '127.0.0.1' || gateway.username || gateway.password)
  throw new Error('Only a disposable loopback HTTP gateway is supported');
const sockets = new Set();
const isApi = (path) => /^\/(?:v1\/|api\/|ws(?:\?|$)|attestation(?:\/|\?|$))/.test(path);
const server = createServer(async (req, res) => {
  if (isApi(req.url)) {
    const proxy = request(new URL(req.url, gateway), {
      method: req.method, headers: { ...req.headers, host: gateway.host },
    }, response => {
      res.writeHead(response.statusCode, response.headers);
      response.pipe(res);
    });
    proxy.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    res.on('close', () => proxy.destroy());
    req.pipe(proxy);
    return;
  }
  res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  try {
    const url = new URL(req.url, 'http://127.0.0.1');
    const path = await realpath(resolve(root, '.' + (url.pathname === '/' ? '/tests/browser/index.html' : decodeURIComponent(url.pathname))));
    if (!path.startsWith(root + sep)) { res.writeHead(403).end(); return; }
    const body = await readFile(path);
    res.setHeader('content-type', ({ '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css' })[extname(path)] || 'application/octet-stream');
    res.end(body);
  } catch { res.writeHead(404).end(); }
});
server.on('upgrade', (req, socket, head) => {
  if (!['/ws', '/v1/ws'].includes(req.url)) { socket.destroy(); return; }
  const proxy = request(new URL(req.url, gateway), {
    headers: { ...req.headers, host: gateway.host },
  });
  proxy.on('upgrade', (response, remote, remoteHead) => {
    sockets.add(remote);
    remote.on('close', () => sockets.delete(remote));
    socket.write(`HTTP/1.1 ${response.statusCode} Switching Protocols\r\n` +
      Object.entries(response.headers).map(([k, v]) => `${k}: ${v}\r\n`).join('') + '\r\n');
    if (remoteHead.length) socket.write(remoteHead);
    if (head.length) remote.write(head);
    remote.on('error', () => socket.destroy());
    socket.on('error', () => remote.destroy());
    socket.on('close', () => remote.destroy());
    remote.on('close', () => socket.destroy());
    socket.pipe(remote).pipe(socket);
  });
  proxy.on('response', response => { socket.end(`HTTP/1.1 ${response.statusCode} Rejected\r\nConnection: close\r\n\r\n`); response.resume(); });
  proxy.on('error', () => socket.destroy());
  proxy.end();
});
server.on('connection', socket => {
  sockets.add(socket);
  socket.on('error', () => {});
  socket.on('close', () => sockets.delete(socket));
});
server.listen(Number(requestedPort), '127.0.0.1', () => {
  console.log(JSON.stringify({ url: `http://127.0.0.1:${server.address().port}`, gateway: gateway.origin, policy: 'same-origin CSP; real HTTP/WS proxy; loopback only' }));
});
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  for (const socket of sockets) socket.destroy();
  server.close();
});
