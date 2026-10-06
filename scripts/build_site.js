#!/usr/bin/env node
// Assemble the Jevline website into _site/. Vercel serves it together with the Jev relay in api/.
// The engine runs in the visitor's browser: its TypeScript (engine/src) is published as JavaScript
// modules by erasing the type annotations, so the site needs no compiler and no dependencies.
//
//   node scripts/build_site.js            # writes _site/
//   node scripts/serve_site.js            # local preview with the relay: http://127.0.0.1:8000
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {stripTypeScriptTypes} = require('node:module');

const ROOT = path.resolve(__dirname, '..');
const ENGINE = path.join(ROOT, 'engine', 'src');
// The page's own scripts, and the engine thread it starts (with every engine module that one imports).
const UI_FILES = ['app.js', 'view.js', 'styles.css'];
const ENGINE_ENTRY = 'web-worker.ts';
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

// "owner/repo" for a github.com URL, or null.
function repositorySlug(repoUrl) {
  const match = /^https:\/\/github\.com\/([\w.-]+\/[\w.-]+)\/?$/.exec(repoUrl);
  return match ? match[1] : null;
}

// The repository's star count, read once at build time so the page itself never contacts GitHub.
// Any failure (offline, rate limit, not a GitHub repo) just leaves the count bubble out.
async function starCount(repoUrl) {
  const slug = repositorySlug(repoUrl);
  if (!slug) return null;
  try {
    const response = await fetch(`https://api.github.com/repos/${slug}`, {
      headers: {accept: 'application/vnd.github+json', 'user-agent': 'jevline-build'},
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) return null;
    const count = (await response.json()).stargazers_count;
    return Number.isInteger(count) && count >= 0 ? count : null;
  } catch {
    return null;
  }
}

function starCountHtml(repoUrl, count) {
  if (count === null || count === undefined) return '';
  const label = `${count.toLocaleString('en-US')} ${count === 1 ? 'user has' : 'users have'} starred this repository`;
  return `<a class="github-star-count" href="${escapeHtml(repoUrl)}/stargazers" target="_blank" rel="noopener noreferrer" aria-label="${label}">${count.toLocaleString('en-US')}</a>`;
}

/**
 * The engine modules the browser needs, as JavaScript: each TypeScript file reachable from the entry, with
 * its types erased (the engine uses erasable syntax only) and its './x.ts' imports pointing at './x.js'.
 * A module that imports from Node would not run in a browser, so it fails the build.
 */
function engineModules(entry = ENGINE_ENTRY) {
  if (typeof stripTypeScriptTypes !== 'function') throw new Error(`Node.js ${process.version} cannot strip TypeScript types; use Node.js 22.18 or newer`);
  // Node marks type stripping experimental and says so on stderr; that one notice is expected here.
  const emitWarning = process.emitWarning;
  process.emitWarning = (warning, ...rest) => {
    if (!/stripTypeScriptTypes/.test(String(warning))) emitWarning.call(process, warning, ...rest);
  };
  try { return collectModules(entry); } finally { process.emitWarning = emitWarning; }
}

function collectModules(entry) {
  const modules = new Map(), queue = [entry];
  while (queue.length) {
    const file = queue.pop();
    if (modules.has(file)) continue;
    const source = fs.readFileSync(path.join(ENGINE, file), 'utf8');
    const js = stripTypeScriptTypes(source, {mode: 'strip'})
      .replace(/(\b(?:import|export)\b[^'";]*?\bfrom\s*|\bimport\s*\(\s*)'(\.\/[^']+)\.ts'/g, (_, head, spec) => {
        queue.push(`${spec.slice(2)}.ts`);
        return `${head}'${spec}.js'`;
      });
    const node = /\bfrom\s*'node:|\bimport\s*\(\s*'node:/.exec(js);
    if (node) throw new Error(`engine/src/${file} imports a Node module, so it cannot run in the browser`);
    modules.set(file, js);
  }
  return modules;
}

function build(out, repoUrl, stars = null) {
  fs.rmSync(out, {recursive: true, force: true});
  fs.mkdirSync(path.join(out, 'examples'), {recursive: true});
  fs.mkdirSync(path.join(out, 'engine'), {recursive: true});
  const page = fs.readFileSync(path.join(ROOT, 'site', 'index.html'), 'utf8');
  const filled = page
    .replaceAll('{{STAR_COUNT}}', starCountHtml(repoUrl, stars))
    .replaceAll('{{REPO_NAME}}', escapeHtml(repositorySlug(repoUrl) || repoUrl))
    .replaceAll('{{REPO_URL}}', escapeHtml(repoUrl));
  fs.writeFileSync(path.join(out, 'index.html'), filled);
  const files = ['index.html'];
  for (const name of UI_FILES) { fs.copyFileSync(path.join(ROOT, 'ui', name), path.join(out, name)); files.push(name); }
  for (const [file, js] of engineModules()) {
    const name = `engine/${file.replace(/\.ts$/, '.js')}`;
    fs.writeFileSync(path.join(out, name), js);
    files.push(name);
  }
  fs.copyFileSync(path.join(ROOT, 'examples', 'malicious_events.json'), path.join(out, 'examples', 'malicious_events.json'));
  files.push('examples/malicious_events.json');
  return files;
}

async function main(argv) {
  const option = name => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv.includes('-h') || argv.includes('--help')) {
    process.stdout.write('Usage: node scripts/build_site.js [--out DIR] [--repo-url https://...] [--stars N | --no-stars]\n');
    return;
  }
  const out = path.resolve(option('--out') || path.join(ROOT, '_site'));
  const repoUrl = option('--repo-url') || repositoryUrl();
  if (!/^https:\/\/[^\s"'<>]+$/.test(repoUrl)) throw new Error(`--repo-url must be an https URL, got ${JSON.stringify(repoUrl)}`);
  let stars = null;
  if (option('--stars') !== undefined) {
    stars = Number(option('--stars'));
    if (!Number.isInteger(stars) || stars < 0) throw new Error(`--stars must be a whole number, got ${JSON.stringify(option('--stars'))}`);
  } else if (!argv.includes('--no-stars')) {
    stars = await starCount(repoUrl);
  }
  const files = build(out, repoUrl, stars);
  process.stdout.write(`Built ${files.length} files into ${out} (source link: ${repoUrl}; stars: ${stars ?? 'not shown'})\n`);
}

if (require.main === module) {
  main(process.argv.slice(2)).catch(error => { process.stderr.write(`build_site: ${error.message}\n`); process.exit(1); });
}
module.exports = {build, engineModules, repositoryUrl, repositorySlug, starCountHtml};
