#!/usr/bin/env node
// Assemble the Jevline website into _site/. Vercel serves it together with the Jev relay in api/.
//
//   node scripts/build_site.js            # writes _site/
//   node scripts/serve_site.js            # local preview with the relay: http://127.0.0.1:8000
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_REPO = 'https://github.com/tsale/jevline';

// The repository the site is built from (Vercel, GitHub Actions, or the local git remote).
function repositoryUrl() {
  const env = process.env;
  if (env.VERCEL_GIT_REPO_OWNER && env.VERCEL_GIT_REPO_SLUG && (env.VERCEL_GIT_PROVIDER || 'github') === 'github') {
    return `https://github.com/${env.VERCEL_GIT_REPO_OWNER}/${env.VERCEL_GIT_REPO_SLUG}`;
  }
  if (env.GITHUB_REPOSITORY) return `${env.GITHUB_SERVER_URL || 'https://github.com'}/${env.GITHUB_REPOSITORY}`;
  try {
    const remote = execFileSync('git', ['remote', 'get-url', 'origin'], {cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']}).trim();
    // Never publish credentials embedded in a remote URL.
    return remote.replace(/^git@([^:]+):/, 'https://$1/').replace(/^https:\/\/[^@/]+@/, 'https://').replace(/\.git$/, '');
  } catch {
    return DEFAULT_REPO;
  }
}

const escapeHtml = text => text.replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[c]);

function build(out, repoUrl) {
  fs.rmSync(out, {recursive: true, force: true});
  fs.mkdirSync(path.join(out, 'examples'), {recursive: true});
  const page = fs.readFileSync(path.join(ROOT, 'site', 'index.html'), 'utf8');
  fs.writeFileSync(path.join(out, 'index.html'), page.replaceAll('{{REPO_URL}}', escapeHtml(repoUrl)));
  for (const name of ['app.js', 'engine.js', 'styles.css']) fs.copyFileSync(path.join(ROOT, 'ui', name), path.join(out, name));
  // Loaded as a script, so the page's connection policy needs nothing extra for it.
  const example = JSON.parse(fs.readFileSync(path.join(ROOT, 'examples', 'malicious_events.json'), 'utf8'));
  fs.writeFileSync(path.join(out, 'examples', 'malicious_events.js'), `window.CASEBENCH_EXAMPLE = ${JSON.stringify(example)};\n`);
  return ['index.html', 'app.js', 'engine.js', 'styles.css', 'examples/malicious_events.js'];
}

function main(argv) {
  const option = name => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv.includes('-h') || argv.includes('--help')) {
    process.stdout.write('Usage: node scripts/build_site.js [--out DIR] [--repo-url https://...]\n');
    return;
  }
  const out = path.resolve(option('--out') || path.join(ROOT, '_site'));
  const repoUrl = option('--repo-url') || repositoryUrl();
  if (!/^https:\/\/[^\s"'<>]+$/.test(repoUrl)) throw new Error(`--repo-url must be an https URL, got ${JSON.stringify(repoUrl)}`);
  const files = build(out, repoUrl);
  process.stdout.write(`Built ${files.length} files into ${out} (source link: ${repoUrl})\n`);
}

if (require.main === module) {
  try { main(process.argv.slice(2)); } catch (error) { process.stderr.write(`build_site: ${error.message}\n`); process.exit(1); }
}
module.exports = {build, repositoryUrl};
