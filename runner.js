'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { execSync, spawn, execFileSync } = require('child_process');
const { startTrapSuite } = require('./tls-trap.js');

const LANE = process.env.TRUTH_LANE || 'macos';
const BURST = parseInt(process.env.TRUTH_BURST || '6', 10);
const PORT = parseInt(process.env.TRUTH_PORT || '8234', 10);
const OUT_DIR = process.env.TRUTH_OUT || path.join(process.cwd(), 'samples');
const URL_BASE = 'http://127.0.0.1:' + PORT;
const TRAP_BASE = PORT + 10; // sniff=P+10, h2=P+11, h1=P+12, export=P+13

function log(msg) { process.stdout.write('[' + new Date().toISOString() + '] ' + msg + '\n'); }

let trap = null;
async function bootTrap() {
  trap = startTrapSuite(TRAP_BASE, {});
  await trap.listen();
  log('trap suite listening: sniff=' + trap.ports.sniff + ' h2=' + trap.ports.h2 + ' h1=' + trap.ports.h1 + ' export=' + trap.ports.export);
  const ok = trap.trustMacOS();
  log('cert trust (System.keychain): ' + (ok ? 'installed' : 'skipped'));
}
function closeTrap() { if (trap) try { trap.close(); } catch (_) {} }
const TRAP_HELLO_URL = 'https://127.0.0.1:' + TRAP_BASE + '/';
const TRAP_H2_URL = 'https://127.0.0.1:' + (TRAP_BASE + 1) + '/';
const TRAP_H1_URL = 'https://127.0.0.1:' + (TRAP_BASE + 2) + '/';
const isProbePath = (u) => u.split('?')[0] === '/probe';

function enrich(s) {
  if (s && s.hw) {
    s.hw.memGb = Math.round(os.totalmem() / 1048576 / 1024);
    s.hw.cores = os.cpus().length;
  }
  if (s && s.harvestedAt) s.harvestedAt = new Date().toISOString();
  return s;
}

function closeCollector(server) {
  try { server.close(); } catch (_) {}
}

function collectPosts(server, timeoutMs, need) {
  return new Promise((resolve) => {
    const samples = [];
    const probeHtml = fs.readFileSync(path.join(__dirname, 'probe.html'), 'utf8')
      .replace(/%COLLECT_URL%/g, 'http://127.0.0.1:' + PORT + '/collect');
    const timer = setTimeout(() => { closeCollector(server); resolve(samples); }, timeoutMs);
    server.on('request', (req, res) => {
      if (req.method === 'GET' && isProbePath(req.url)) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(probeHtml);
      } else if (req.method === 'POST' && req.url === '/collect') {
        let body = '';
        req.on('data', (c) => { body += c; });
        req.on('end', () => {
          try { samples.push(enrich(JSON.parse(body))); } catch (_) {}
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{"ok":true}');
          if (samples.length >= need) { clearTimeout(timer); closeCollector(server); resolve(samples); }
        });
      } else {
        res.writeHead(404);
        res.end();
      }
    });
  });
}

async function wdPost(base, pathPart, body) {
  const r = await fetch(base + pathPart, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return r.json();
}

async function runMacOS() {
  const wdPort = PORT + 1;
  log('macOS lane: safaridriver WebDriver on :' + wdPort);
  const probeHtml = fs.readFileSync(path.join(__dirname, 'probe.html'), 'utf8')
    .replace(/%COLLECT_URL%/g, '');
  const page = http.createServer((req, res) => {
    if (req.method === 'GET' && isProbePath(req.url)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(probeHtml);
    } else if (req.method === 'POST' && req.url === '/collect') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise((resolve) => page.listen(PORT, '127.0.0.1', resolve));
  log('probe page serving on 127.0.0.1:' + PORT);
  try { execSync('sudo safaridriver --enable', { stdio: 'ignore', timeout: 20000 }); } catch (e) { log('safaridriver --enable: ' + e.message); }
  let srv;
  try {
    srv = spawn('safaridriver', ['-p', String(wdPort)], { stdio: 'ignore' });
    srv.on('error', (e) => log('safaridriver process error: ' + e.message));
  } catch (e) { log('spawn safaridriver: ' + e.message); return []; }
  const base = 'http://127.0.0.1:' + wdPort;
  let sid = null;
  for (let i = 0; i < 30 && !sid; i++) {
    try {
      const j = await wdPost(base, '/session', { capabilities: { alwaysMatch: {}, firstMatch: [{}] } });
      if (j && j.value && j.value.sessionId) sid = j.value.sessionId;
    } catch (_) {}
    if (!sid) await new Promise((r) => setTimeout(r, 1000));
  }
  if (!sid) { log('webdriver: no session'); if (srv) srv.kill(); return []; }
  log('webdriver session ' + sid.toString().slice(0, 8));
  const samples = [];
  for (let i = 0; i < BURST; i++) {
    try {
      // Prime the transport measurements with real Safari TLS/HTTP sessions.
      for (const tu of [TRAP_HELLO_URL, TRAP_H2_URL, TRAP_H1_URL]) {
        try {
          await wdPost(base, '/session/' + sid + '/url', { url: tu });
          log('trap nav ok: ' + tu.slice(0, 24) + ' (sample ' + (i + 1) + ')');
        } catch (e) { log('trap nav fail: ' + tu.slice(0, 24) + ' ' + e.message); }
        await new Promise((r) => setTimeout(r, 1200));
      }
      await wdPost(base, '/session/' + sid + '/url', { url: URL_BASE + '/probe?exp=' + trap.ports.export });
      await new Promise((r) => setTimeout(r, 3500));
      const ex = await wdPost(base, '/session/' + sid + '/execute/sync', { script: 'return window.__TRUTH_SAMPLE__ || null;', args: [] });
      if (ex && ex.value && typeof ex.value === 'object') { samples.push(enrich(ex.value)); log('webdriver probe ' + (i + 1) + '/' + BURST + ' sample' + (ex.value.transport && ex.value.transport.tls ? ' [transport:tls]' : ' [transport:none]')); }
      else log('webdriver probe ' + (i + 1) + '/' + BURST + ' empty');
    } catch (e) { log('webdriver probe ' + (i + 1) + '/' + BURST + ' error: ' + e.message); }
  }
  try { await fetch(base + '/session/' + sid, { method: 'DELETE' }); } catch (_) {}
  if (srv) srv.kill();
  try { page.close(); } catch (_) {}
  return samples;
}

function firstSimulator() {
  const out = execSync('xcrun simctl list devices available', { encoding: 'utf8', timeout: 20000 });
  for (const line of out.split('\n')) {
    const m = line.match(/^\s*(iPhone [^(]+) \(([0-9A-F-]{36})\)/);
    if (m && !/unavailable/.test(line)) return m[1].trim();
  }
  return 'iPhone 16';
}

async function runIOS() {
  log('iOS lane: simulator + Mobile Safari');
  const server = http.createServer();
  return new Promise((resolve) => {
    server.listen(PORT, '127.0.0.1', async () => {
      log('collector listening on 127.0.0.1:' + PORT);
      const samplesPromise = collectPosts(server, 300000, BURST);
      const device = firstSimulator();
      log('simulator device: ' + device);
      try {
        execSync('xcrun simctl boot "' + device + '" 2>/dev/null || true', { stdio: 'ignore' });
        log('simulator boot issued, waiting for full boot...');
        execFileSync('xcrun', ['simctl', 'bootstatus', device, '-b'], { stdio: 'ignore', timeout: 240000 });
        log('simulator fully booted');
      } catch (e) { log('sim boot: ' + e.message); }
      for (let i = 0; i < BURST; i++) {
        try {
          for (const tu of [TRAP_HELLO_URL, TRAP_H2_URL, TRAP_H1_URL]) {
            try { execSync('xcrun simctl openurl booted "' + tu + '"', { stdio: 'ignore', timeout: 15000 }); } catch (_) {}
            await new Promise((r) => setTimeout(r, 1200));
          }
          execSync('xcrun simctl openurl booted "' + URL_BASE + '/probe?exp=' + trap.ports.export + '"', { stdio: 'ignore', timeout: 20000 });
          log('dispatched probe ' + (i + 1) + '/' + BURST);
        } catch (e) { log('dispatch error: ' + e.message); }
        await new Promise((r) => setTimeout(r, 6000));
      }
      await new Promise((r) => setTimeout(r, 10000));
      const samples = await samplesPromise;
      resolve(samples);
    });
  });
}

async function main() {
  const runId = process.env.TRUTH_RUN || ('t' + Date.now() + '-' + LANE);
  log('truth probe runner — lane=' + LANE + ' burst=' + BURST + ' run=' + runId);
  await bootTrap();
  let samples = [];
  try {
    if (LANE === 'macos') samples = await runMacOS();
    else if (LANE === 'ios') samples = await runIOS();
    else { log('unknown lane: ' + LANE); process.exit(1); }
  } finally {
    closeTrap();
  }

  fs.mkdirSync(OUT_DIR, { recursive: true });
  const outFile = path.join(OUT_DIR, runId + '.json');
  fs.writeFileSync(outFile, JSON.stringify(samples, null, 2));
  log('wrote ' + samples.length + ' samples to ' + outFile);
  console.log(JSON.stringify({ lane: LANE, runId, samples: samples.length, file: outFile }));
}

main().catch((e) => { log('fatal: ' + e); process.exit(1); });