'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { execSync } = require('child_process');

const LANE = process.env.TRUTH_LANE || 'macos';
const BURST = parseInt(process.env.TRUTH_BURST || '6', 10);
const PORT = parseInt(process.env.TRUTH_PORT || '8234', 10);
const OUT_DIR = process.env.TRUTH_OUT || path.join(process.cwd(), 'samples');

function log(msg) { process.stdout.write('[' + new Date().toISOString() + '] ' + msg + '\n'); }

function enrich(s) {
  if (s && s.hw) {
    s.hw.memGb = Math.round(os.totalmem() / 1048576 / 1024);
    s.hw.cores = os.cpus().length;
  }
  if (s && s.harvestedAt) s.harvestedAt = new Date().toISOString();
  return s;
}

function waitForPost(server, timeoutMs) {
  return new Promise((resolve, reject) => {
    const samples = [];
    const probeHtml = fs.readFileSync(path.join(__dirname, 'probe.html'), 'utf8');
    const timer = setTimeout(() => {
      server.close();
      resolve(samples);
    }, timeoutMs);
    server.on('request', (req, res) => {
      if (req.method === 'GET' && req.url === '/probe') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(probeHtml);
      } else if (req.method === 'POST' && req.url === '/collect') {
        let body = '';
        req.on('data', (c) => { body += c; });
        req.on('end', () => {
          try { samples.push(enrich(JSON.parse(body))); } catch (_) {}
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{"ok":true}');
          if (samples.length >= BURST) { clearTimeout(timer); server.close(); resolve(samples); }
        });
      } else {
        res.writeHead(404);
        res.end();
      }
    });
  });
}

function runMacOS() {
  log('macOS lane: launching Safari via open -a');
  const server = http.createServer();
  return new Promise((resolve) => {
    server.listen(PORT, '127.0.0.1', async () => {
      log('collector listening on 127.0.0.1:' + PORT);
      const samplesPromise = waitForPost(server, 120000);
      for (let i = 0; i < BURST; i++) {
        try {
          const url = 'http://127.0.0.1:' + PORT + '/probe';
          execSync('open -a Safari "' + url + '"', { stdio: 'ignore', timeout: 10000 });
          log('dispatched probe ' + (i + 1) + '/' + BURST);
        } catch (e) { log('dispatch error: ' + e.message); }
        await new Promise((r) => setTimeout(r, 3000));
      }
      await new Promise((r) => setTimeout(r, 5000));
      try { execSync('killall Safari 2>/dev/null || true', { stdio: 'ignore' }); } catch (_) {}
      const samples = await samplesPromise;
      resolve(samples);
    });
  });
}

function firstSimulator() {
  try {
    const out = execSync('xcrun simctl list devices available', { encoding: 'utf8', timeout: 15000 });
    for (const line of out.split('\n')) {
      const m = line.match(/^\s*(iPhone [^(]+) \(([0-9A-F-]{36})\)/);
      if (m && !/unavailable/.test(line)) return m[1].trim();
    }
  } catch (_) {}
  return 'iPhone 16';
}

function runIOS() {
  log('iOS lane: launching simulator');
  const server = http.createServer();
  return new Promise((resolve) => {
    server.listen(PORT, '127.0.0.1', async () => {
      log('collector listening on 127.0.0.1:' + PORT);
      const samplesPromise = waitForPost(server, 240000);
      const device = firstSimulator();
      log('simulator device: ' + device);
      try {
        execSync('xcrun simctl boot "' + device + '" 2>/dev/null || true', { stdio: 'ignore' });
        log('simulator booted');
      } catch (e) { log('sim boot: ' + e.message); }
      for (let i = 0; i < BURST; i++) {
        try {
          execSync('xcrun simctl openurl booted "http://127.0.0.1:' + PORT + '/probe"', { stdio: 'ignore', timeout: 10000 });
          log('dispatched probe ' + (i + 1) + '/' + BURST);
        } catch (e) { log('dispatch error: ' + e.message); }
        await new Promise((r) => setTimeout(r, 5000));
      }
      await new Promise((r) => setTimeout(r, 8000));
      const samples = await samplesPromise;
      resolve(samples);
    });
  });
}

async function main() {
  log('truth probe runner — lane=' + LANE + ' burst=' + BURST);
  let samples = [];
  if (LANE === 'macos') samples = await runMacOS();
  else if (LANE === 'ios') samples = await runIOS();
  else { log('unknown lane: ' + LANE); process.exit(1); }

  fs.mkdirSync(OUT_DIR, { recursive: true });
  const runId = process.env.TRUTH_RUN || ('t' + Date.now() + '-' + LANE);
  const outFile = path.join(OUT_DIR, runId + '.json');
  fs.writeFileSync(outFile, JSON.stringify(samples, null, 2));
  log('wrote ' + samples.length + ' samples to ' + outFile);
  console.log(JSON.stringify({ lane: LANE, runId, samples: samples.length, file: outFile }));
}

main().catch((e) => { log('fatal: ' + e); process.exit(1); });