#!/usr/bin/env node
// Local preview of the website as Vercel serves it: _site/ plus the Jev relay at /api/jev, with the
// response headers from vercel.json. The demo key comes from TYPESAFE_API_KEY in the environment or
// .env; "My own TypeSafe key" needs neither.
//
//   node scripts/build_site.js && node scripts/serve_site.js [--port 8000]
'use strict';
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const {createHandler} = require('../api/_relay.js');

const ROOT = path.resolve(__dirname, '..');
const SITE = path.join(ROOT, '_site');
const TYPES = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8'};
const headers = JSON.parse(fs.readFileSync(path.join(ROOT, 'vercel.json'), 'utf8')).headers[0].headers;

function envFileKey() {
  try {
    const line = fs.readFileSync(path.join(ROOT, '.env'), 'utf8').split(/\r?\n/).find(l => /^\s*(export\s+)?TYPESAFE_API_KEY\s*=/.test(l));
    const value = line ? line.split('=').slice(1).join('=').trim().replace(/^(['"])(.*)\1$/, '$2').split(/\s+#/)[0] : '';
    return value || undefined;
  } catch { return undefined; }
}

const portIndex = process.argv.indexOf('--port');
const port = portIndex >= 0 ? Number(process.argv[portIndex + 1]) : 8000;
if (!fs.existsSync(path.join(SITE, 'index.html'))) { process.stderr.write('Run node scripts/build_site.js first.\n'); process.exit(1); }
const relay = createHandler({env: {TYPESAFE_API_KEY: process.env.TYPESAFE_API_KEY || envFileKey()}});

http.createServer((req, res) => {
  for (const {key, value} of headers) res.setHeader(key, value);
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/api/jev') return relay(req, res);
  let file;
  try { file = path.normalize(path.join(SITE, url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname))); } catch { file = ''; }
  if (!file.startsWith(SITE + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.statusCode = 404; return res.end('Not found'); }
  res.setHeader('Content-Type', TYPES[path.extname(file)] || 'application/octet-stream');
  fs.createReadStream(file).pipe(res);
}).listen(port, '127.0.0.1', () => process.stdout.write(`Jevline website preview at http://127.0.0.1:${port}/ (Ctrl+C to stop)\n`));
