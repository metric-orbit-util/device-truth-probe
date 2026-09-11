'use strict';
/*
 * Device Truth Probe â€” Reference TLS/HTTP2 Observation Trap
 * -----------------------------------------------------------
 * Measures how REAL Safari speaks on the transport, at packet depth,
 * with zero runtime dependencies. Three capture surfaces:
 *
 *   1. hello-sniffer (raw TCP port): reads the RAW TLS ClientHello record,
 *      parses the exact ordered cipher list, extension order, groups,
 *      sig algs, ALPN, GREASE -> canonical tlsSig (sha256 over ordered raw).
 *      (We then close the connection; TLS sessions themselves are handled by
 *      Node's own battle-tested stack, so nothing depends on hand-rolled
 *      crypto.)
 *   2. http2 session (Node TLS server, ALPN h2/http1 -> Safari picks h2):
 *      decrypted application data -> connection preface, SETTINGS parameter
 *      order/values, frame sequence, WINDOW_UPDATE increments, first
 *      HEADERS block hex prefix.
 *   3. http1 session (Node TLS server, ALPN http1 only): plaintext request
 *      line + header ORDER preserved verbatim.
 *
 * A measurement harness only: it observes the genuine client the harvest
 * lane already runs (real Safari, hosted-truth label). Never ships in the
 * product, never proxies user traffic.
 *
 * Pure Node + openssl CLI for the ephemeral self-signed CA (runner side).
 * Parser units are offline-testable on Windows (tls-trap.test.js).
 */
const crypto = require('crypto');
const net = require('net');
const tls = require('tls');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync, execFileSync } = require('child_process');

const GREASE = [
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
  0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];
const isGrease = (v) => GREASE.indexOf(v) !== -1;
const hex16 = (v) => ('0000' + (v & 0xffff).toString(16)).slice(-4);

/* ------------------------------------------------------------------ */
/* TLS record layer helpers                                            */
/* ------------------------------------------------------------------ */
function u8(n) { return Buffer.from([n & 0xff]); }
function u16(n) { const b = Buffer.alloc(2); b.writeUInt16BE(n & 0xffff, 0); return b; }
function u24(n) { const b = Buffer.alloc(3); b.writeUIntBE(n & 0xffffff, 0, 3); return b; }
function u32(n) { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0, 0); return b; }

function rec(type, payload) {
  return Buffer.concat([u8(type), Buffer.from([0x03, 0x03]), u16(payload.length), payload]);
}
function hs(type, body) {
  return Buffer.concat([u8(type), u24(body.length), body]);
}

/* ------------------------------------------------------------------ */
/* ClientHello parser â€”â€” exactness first (ordered arrays)              */
/* ------------------------------------------------------------------ */
function parseClientHello(buf) {
  const out = { ok: false };
  if (!buf || buf.length < 6) return out;
  if (buf[0] !== 0x16) return out;
  const recordLen = buf.readUInt16BE(3);
  if (buf.length < 5 + recordLen) return out;
  const body = buf.subarray(5, 5 + recordLen);
  let q = 0;
  if (body[q] !== 0x01) return out;
  const hLen = (body[1] << 16) | (body[2] << 8) | body[3];
  const ch = body.subarray(4, 4 + hLen);
  let r = 0;
  const clientVersion = ch.readUInt16BE(r); r += 2;
  const clientRandom = ch.subarray(r, r + 32); r += 32;
  const sidLen = ch[r++];
  const sessionId = ch.subarray(r, r + sidLen); r += sidLen;
  const csLen = ch.readUInt16BE(r); r += 2;
  const ciphers = [];
  for (let i = 0; i < csLen; i += 2) ciphers.push(ch.readUInt16BE(r + i));
  r += csLen;
  const compLen = ch[r++];
  r += compLen;

  const extensions = [];
  const extOrder = [];
  if (r + 2 <= ch.length) {
    const extLen = ch.readUInt16BE(r); r += 2;
    const extBlock = ch.subarray(r, r + extLen);
    let e = 0;
    while (e + 4 <= extBlock.length) {
      const type = extBlock.readUInt16BE(e);
      const len = extBlock.readUInt16BE(e + 2);
      const data = extBlock.subarray(e + 4, e + 4 + len);
      extensions.push({ type, len, grease: isGrease(type), data });
      extOrder.push(type);
      e += 4 + len;
    }
  }

  const groups = [], sigAlgs = [], alpn = [], versions = [], sni = [];
  let reneg = false, ems = false, etm = false;
  for (const ext of extensions) {
    if (ext.type === 0x0000) {
      let t = 2;
      while (t + 3 <= ext.data.length) {
        const nlen = ext.data.readUInt16BE(t + 1);
        if (t + 3 + nlen > ext.data.length) break;
        const name = ext.data.subarray(t + 3, t + 3 + nlen).toString('latin1');
        if (name) sni.push(name);
        t += 3 + nlen;
      }
    } else if (ext.type === 0x000a) {
      const n = ext.data.readUInt16BE(0);
      for (let i = 0; i + 2 + 2 <= ext.data.length && i < n; i += 2) groups.push(ext.data.readUInt16BE(2 + i));
    } else if (ext.type === 0x000d) {
      const n = ext.data.readUInt16BE(0);
      for (let i = 0; i + 2 + 2 <= ext.data.length && i < n; i += 2) sigAlgs.push(ext.data.readUInt16BE(2 + i));
    } else if (ext.type === 0x0010) {
      const n = ext.data.readUInt16BE(0);
      let t = 2;
      while (t + 1 <= ext.data.length && t < n + 2) {
        const l = ext.data[t];
        alpn.push(ext.data.subarray(t + 1, t + 1 + l).toString('latin1'));
        t += 1 + l;
      }
    } else if (ext.type === 0x002b) {
      const n = ext.data[0];
      for (let i = 0; i < n; i += 2) versions.push(ext.data.readUInt16BE(1 + i));
    } else if (ext.type === 0xff01) reneg = true;
    else if (ext.type === 0x0017) ems = true;
    else if (ext.type === 0x0016) etm = true;
  }
  const tls13Offered = versions.indexOf(0x0304) !== -1;
  const tlsv = tls13Offered ? '13' : (clientVersion === 0x0303 ? '12' : '0x' + hex16(clientVersion));

  const raw = {
    clientVersion: '0x' + hex16(clientVersion),
    sessionIdLen: sidLen,
    ciphers: ciphers.map(hex16),
    cipherCount: ciphers.length,
    extensions: extensions.map((x) => ({ t: '0x' + hex16(x.type), l: x.len, g: x.grease })),
    groups: groups.map(hex16),
    sigAlgs: sigAlgs.map(hex16),
    alpn,
    versions: versions.map(hex16),
    sni,
  };
  const tlsSig = crypto.createHash('sha256').update(JSON.stringify(raw)).digest('hex').slice(0, 24);

  Object.assign(out, {
    ok: true, tlsSig, tlsv, clientRandom, sessionId, ciphers, groups, sigAlgs, alpn, versions,
    sni, renegotiation: reneg, ems, etm, extOrder, extensions, raw,
  });
  return out;
}

/* ------------------------------------------------------------------ */
/* JA4-style digest (deterministic approx mapping). tlsSig is canonical.*/
/* ------------------------------------------------------------------ */
function ja4approx(ch) {
  return {
    version: ch.tlsv,
    greaseCount: (ch.ciphers || []).filter(isGrease).length + (ch.extOrder || []).filter(isGrease).length,
    ciphers: (ch.ciphers || []).map(hex16).join(','),
    extensions: (ch.extOrder || []).filter((t) => !isGrease(t)).map(hex16).join(','),
    sigFirst: (ch.sigAlgs || []).slice(0, 1).map(hex16).join(',') || '-',
    alpn: (ch.alpn || []).join(',') || '-',
    digest: 't' + (ch.tlsv === '13' ? '13' : '12') + ':' +
      (ch.ciphers || []).map(hex16).join(',') + ':' +
      (ch.extOrder || []).filter((t) => !isGrease(t)).map(hex16).join(',') + ':' +
      ((ch.sigAlgs || []).slice(0, 1).map(hex16).join(',') || '-') + ':' +
      ((ch.alpn || []).join(',') || '-'),
  };
}

function tlsDigestFromHello(ch) {
  return {
    tlsSig: ch.tlsSig,
    via: 'hello-sniffer',
    version: ch.tlsv,
    ciphers: ch.ciphers.map(hex16),
    extOrder: ch.extOrder.map(hex16),
    groups: ch.groups.map(hex16),
    sigAlgs: ch.sigAlgs.map(hex16),
    alpn: ch.alpn,
    versions: ch.versions.map(hex16),
    sni: ch.sni,
    greaseCiphers: ch.ciphers.filter(isGrease).map(hex16),
    greaseExts: ch.extOrder.filter((t) => isGrease(t)).map(hex16),
    renegotiation: ch.renegotiation,
    ems: ch.ems,
    etm: ch.etm,
    ja4approx: ja4approx(ch),
  };
}

/* ------------------------------------------------------------------ */
/* HTTP/2 frame parsing (RFC 7540) â€” SETTINGS order/values + sequence  */
/* ------------------------------------------------------------------ */
function parseH2(data) {
  const out = { preface: false, settings: [], settingsAck: false, frames: [], firstHeaders: null, windowUpdates: [] };
  const PRE = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
  const bfs = Buffer.isBuffer(data) ? data : Buffer.from(data, 'latin1');
  if (bfs.length < PRE.length || bfs.subarray(0, PRE.length).toString('latin1') !== PRE) {
    out.error = 'missing-preface';
    return out;
  }
  out.preface = true;
  let p = PRE.length;
  while (p + 9 <= bfs.length) {
    const len = (bfs[p] << 16) | (bfs[p + 1] << 8) | bfs[p + 2];
    if (p + 9 + len > bfs.length) break;
    const type = bfs[p + 3];
    const flags = bfs[p + 4];
    const stream = bfs.readUInt32BE(p + 5) & 0x7fffffff;
    const payload = bfs.subarray(p + 9, p + 9 + len);
    const names = ['DATA', 'HEADERS', 'PRIORITY', 'RST_STREAM', 'SETTINGS', 'PUSH_PROMISE', 'PING', 'GOAWAY', 'WINDOW_UPDATE', 'CONTINUATION'];
    out.frames.push({ type: names[type] || ('F' + type), stream, len, flags });
    if (type === 0x04) {
      if (flags & 0x01) out.settingsAck = true;
      else for (let i = 0; i + 6 <= payload.length; i += 6) out.settings.push({ id: payload.readUInt16BE(i), val: payload.readUInt32BE(i + 2) });
    } else if (type === 0x08 && payload.length >= 4) {
      out.windowUpdates.push(payload.readUInt32BE(0));
    } else if (type === 0x01 && !out.firstHeaders) {
      out.firstHeaders = { stream, len, prefix24: payload.subarray(0, 24).toString('hex') };
    }
    p += 9 + len;
  }
  return out;
}

function parseH1(data) {
  const s = Buffer.isBuffer(data) ? data.toString('latin1') : String(data);
  const end = s.indexOf('\r\n\r\n');
  if (end === -1) return { ok: false, rawHead: s.slice(0, 120) };
  const lines = s.slice(0, end).split('\r\n');
  const requestLine = lines.shift() || '';
  const headers = [];
  for (const ln of lines) {
    const i = ln.indexOf(':');
    if (i > 0) headers.push({ name: ln.slice(0, i).trim(), value: ln.slice(i + 1).trim() });
  }
  return { ok: true, requestLine, headers, order: headers.map((h) => h.name) };
}

/* ------------------------------------------------------------------ */
/* TLS 1.2 PRF kept for reference instruments & tests (RFC 5246 Â§5)    */
/* ------------------------------------------------------------------ */
function hmacSha256(k, d) { return crypto.createHmac('sha256', k).update(d).digest(); }
function prf12(secret, label, seed, outLen) {
  const ls = Buffer.concat([Buffer.from(label, 'binary'), seed]);
  let a = hmacSha256(secret, ls);
  const parts = [];
  let acc = 0;
  while (acc < outLen) {
    const p = hmacSha256(secret, Buffer.concat([a, ls]));
    parts.push(p);
    acc += p.length;
    a = hmacSha256(secret, a);
  }
  return Buffer.concat(parts).subarray(0, outLen);
}

/* ------------------------------------------------------------------ */
/* Self-signed CA cert (runner side, measurement only)                 */
/* ------------------------------------------------------------------ */
function findOpenssl() {
  const candidates = [
    'openssl',
    'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
    'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe',
    '/usr/bin/openssl',
    '/opt/homebrew/bin/openssl',
  ];
  for (const c of candidates) {
    try { execFileSync(c, ['version'], { stdio: 'ignore', timeout: 5000 }); return c; } catch (_) {}
  }
  return null;
}

function buildCert(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const openssl = findOpenssl();
  if (!openssl) throw new Error('tls-trap requires the openssl CLI (runner only, never shipped)');
  const cnf = path.join(dir, 'openssl.cnf');
  fs.writeFileSync(cnf, [
    '[req]', 'distinguished_name = dn', 'prompt = no', 'x509_extensions = v3_ca',
    '[dn]', 'CN = localhost',
    '[v3_ca]', 'basicConstraints = CA:TRUE', 'keyUsage = digitalSignature, keyCertSign, keyEncipherment',
    'subjectAltName = @alt', '[alt]', 'IP.1 = 127.0.0.1', 'DNS.1 = localhost', '',
  ].join('\n'), 'utf8');
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-extensions', 'v3_ca', '-config', cnf,
    '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem')],
  { stdio: 'ignore', timeout: 30000 });
  const certPem = fs.readFileSync(path.join(dir, 'cert.pem'), 'utf8');
  const certRaw = new crypto.X509Certificate(certPem).raw;
  const keyPem = fs.readFileSync(path.join(dir, 'key.pem'), 'utf8');
  const key = crypto.createPrivateKey(keyPem);
  return { certPem, certRaw, key, keyPem, dir };
}

/**
 * Start the whole measurement suite:
 *   basePort     -> raw hello-sniffer (TLS ClientHello record parse)
 *   basePort + 1 -> Node TLS server (ALPN h2, http/1.1) -> HTTP/2 capture
 *   basePort + 2 -> Node TLS server (ALPN http/1.1)     -> header-order capture
 *   basePort + 3 -> plain HTTP export server  (GET /capture, GET /ping)
 */
function startTrapSuite(basePort, opts) {
  const dir = (opts && opts.dir) || fs.mkdtempSync(path.join(os.tmpdir(), 'gbp-truth-trap-'));
  const cert = buildCert(path.join(dir, 'cert'));
  const ports = {
    sniff: basePort,
    h2: basePort + 1,
    h1: basePort + 2,
    export: (opts && opts.exportPort) || (basePort + 3),
  };
  let lastHello = null;
  let lastH2 = null;
  let lastH1 = null;

  const sniff = net.createServer((sock) => {
    let inbox = Buffer.alloc(0);
    let done = false;
    sock.on('data', (d) => {
      if (done) return;
      inbox = Buffer.concat([inbox, d]);
      let ch;
      try { ch = parseClientHello(inbox); } catch (_) { ch = { ok: false }; }
      if (ch.ok) {
        done = true;
        lastHello = Object.assign(tlsDigestFromHello(ch), { capturedAt: new Date().toISOString() });
        try { sock.write(Buffer.from([21, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])); } catch (_) {} // TLS alert (2,40)
        try { sock.end(); } catch (_) {}
      }
    });
    sock.on('error', () => {});
  });

  const h2srv = tls.createServer(
    { key: cert.keyPem, cert: cert.certPem, ALPNProtocols: ['h2', 'http/1.1'] },
    (sock) => {
      let inbox = Buffer.alloc(0);
      let done = false;
      let fed = false;
      const feed = (buf) => { try { sock.write(buf); } catch (_) {} };
      sock.on('data', (d) => {
        if (done) return;
        inbox = Buffer.concat([inbox, d]);
        const r = parseH2(inbox);
        if (process.env.TRUTH_TRAP_DEBUG) {
          process.stderr.write('[trap:h2] data=' + d.length + ' total=' + inbox.length + ' preface=' + r.preface + ' settings=' + r.settings.length + ' frames=' + r.frames.length + ' types=' + JSON.stringify(r.frames.map((f) => f.type)) + '\n');
        }
        if (r.preface && !fed) {
          fed = true;
          // Client needs our SETTINGS before it sends request HEADERS.
          // (Note: we must NOT ACK the client's own (empty) SETTINGS — that
          // trips some implementations; our own SETTINGS frame alone is enough.)
          const sPayload = Buffer.concat([
            Buffer.concat([u16(0x0003), u32(128)]),      // MAX_CONCURRENT_STREAMS
            Buffer.concat([u16(0x0004), u32(1048576)]),  // INITIAL_WINDOW_SIZE
            Buffer.concat([u16(0x0002), u32(0)]),        // ENABLE_PUSH
          ]);
          const sFrame = Buffer.concat([u24(sPayload.length), u8(0x04), u8(0x00), u32(0), sPayload]);
          feed(sFrame);
        }
        if (r.preface && r.firstHeaders) {
          done = true;
          lastH2 = Object.assign(r, { via: 'tls-session', negotiated: sock.alpnProtocol || null, capturedAt: new Date().toISOString() });
          const goaway = Buffer.concat([u24(8), u8(0x07), u8(0), u32(0), u32(r.firstHeaders.stream || 0), u32(0)]); // graceful close
          try { sock.write(goaway); } catch (_) {}
          try { sock.end(); } catch (_) {}
        }
      });
      sock.on('error', () => {});
    });

  const h1srv = tls.createServer(
    { key: cert.keyPem, cert: cert.certPem, ALPNProtocols: ['http/1.1'] },
    (sock) => {
      let inbox = Buffer.alloc(0);
      let done = false;
      sock.on('data', (d) => {
        if (done) return;
        inbox = Buffer.concat([inbox, d]);
        const r = parseH1(inbox);
        if (r.ok) {
          done = true;
          lastH1 = Object.assign(r, { via: 'tls-session', negotiated: sock.alpnProtocol || null, capturedAt: new Date().toISOString() });
          try { sock.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'); } catch (_) {}
          try { sock.end(); } catch (_) {}
        }
      });
      sock.on('error', () => {});
    });

  const exportServer = http.createServer((req, res) => {
    if (req.url === '/capture') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ tls: lastHello, http2: lastH2, http1: lastH1, capturedAt: new Date().toISOString() }));
      lastH2 = null;
      lastH1 = null;
    } else if (req.url === '/ping') { res.writeHead(200); res.end('pong'); }
    else { res.writeHead(404); res.end(); }
  });

  const started = [];
  const listenOne = (srv, port) => new Promise((res) => srv.listen(port, '127.0.0.1', res));
  return {
    ports,
    certPem: cert.certPem,
    certRaw: cert.certRaw,
    certDir: cert.dir,
    /** Install the ephemeral root so Safari completes TLS (runner macOS only). */
    trustMacOS() {
      try {
        execFileSync('sudo', ['security', 'add-trusted-cert', '-d', '-r', 'trustRoot', '-k', '/Library/Keychains/System.keychain', path.join(cert.dir, 'cert.pem')], { stdio: 'ignore', timeout: 20000 });
        return true;
      } catch (_) { return false; }
    },
    async listen() {
      for (const [name, port] of Object.entries(ports)) {
        if (name === 'export') continue;
        await new Promise((res) => started.push(name) && setTimeout(res, 0));
        if (name === 'sniff') await new Promise((r) => sniff.listen(port, '127.0.0.1', r));
        else if (name === 'h2') await new Promise((r) => h2srv.listen(port, '127.0.0.1', r));
        else if (name === 'h1') await new Promise((r) => h1srv.listen(port, '127.0.0.1', r));
      }
      await new Promise((r) => exportServer.listen(ports.export, '127.0.0.1', r));
    },
    close() {
      try { sniff.close(); } catch (_) {}
      try { h2srv.close(); } catch (_) {}
      try { h1srv.close(); } catch (_) {}
      try { exportServer.close(); } catch (_) {}
    },
  };
}

module.exports = {
  parseClientHello, parseH2, parseH1, startTrapSuite, ja4approx, prf12, isGrease,
  GREASE, hex16, findOpenssl, buildCert, u8, u16, u24, u32, rec, hs, tlsDigestFromHello,
};