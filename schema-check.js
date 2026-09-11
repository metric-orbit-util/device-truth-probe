'use strict';
const os = require('os');
const { assertSample } = require('../desktop/engines/corpus/truth.js');

function enrich(s) {
  s.hw.memGb = Math.round(os.totalmem() / 1048576 / 1024);
  s.hw.cores = os.cpus().length;
  s.harvestedAt = new Date().toISOString();
  return s;
}

const macos = enrich({
  uuid: 'probe-macos-0001',
  lane: 'macos',
  model: 'MacBook-Pro',
  os: 'macOS 15.4',
  browser: 'Safari',
  ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15',
  platform: 'MacIntel',
  screen: { w: 2560, h: 1440, dpr: 2 },
  viewport: { w: 1512, h: 982 },
  hw: { cores: 0, memGb: 0, touch: false },
  webgl: { renderer: 'Apple M1', vendor: 'Apple' },
  fonts: ['Helvetica', 'Arial', 'Geneva', 'Times New Roman', 'Menlo', 'Courier'],
  timeline: { canvas: 2400, webgl: 1800 },
  webkit: { applePay: true, standalone: false, orientation: 'landscape-primary' },
  harvestedAt: ''
});

const ios = enrich({
  uuid: 'probe-ios-0002',
  lane: 'ios',
  model: 'iPhone',
  os: 'iOS 18.5',
  browser: 'Safari',
  ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1',
  platform: 'iPhone',
  screen: { w: 393, h: 852, dpr: 3 },
  viewport: { w: 393, h: 759 },
  hw: { cores: 0, memGb: 0, touch: true },
  webgl: { renderer: 'Apple Software Renderer', vendor: 'Apple' },
  fonts: ['Helvetica', 'Helvetica Neue', 'Arial', 'Times New Roman', 'American Typewriter', 'Courier New'],
  timeline: { canvas: 2100, webgl: 1500 },
  webkit: { applePay: true, standalone: false, orientation: 'portrait-primary' },
  harvestedAt: ''
});

for (const [name, s] of [['macos', macos], ['ios', ios]]) {
  const r = assertSample(s);
  console.log(name + ': ' + (r.ok ? 'PASS' : 'REJECT ' + JSON.stringify(r.reasons)));
}