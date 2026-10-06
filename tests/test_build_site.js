// Run with: node tests/test_build_site.js (from the repository root). Offline: no star count is fetched.
// Builds the site, checks the page and the published files, and runs the published engine modules.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {build, repositorySlug, starCountHtml} = require('../scripts/build_site.js');

const out = fs.mkdtempSync(path.join(os.tmpdir(), 'jevline-site-'));
const page = () => fs.readFileSync(path.join(out, 'index.html'), 'utf8');

assert.equal(repositorySlug('https://github.com/tsale/jevline'), 'tsale/jevline');
assert.equal(repositorySlug('https://gitlab.com/tsale/jevline'), null);

// With a count: the star button and a count bubble that links to the stargazers.
build(out, 'https://github.com/tsale/jevline', 1234);
let html = page();
assert.doesNotMatch(html, /\{\{[A-Z_]+\}\}/, 'every placeholder is filled');
for (const name of ['app.js', 'view.js', 'styles.css']) {
  assert.equal(fs.readFileSync(path.join(out, name), 'utf8'), fs.readFileSync(path.join(__dirname, '..', 'ui', name), 'utf8'), `${name} is published`);
  if (name.endsWith('.js')) assert.match(html, new RegExp(`<script src="${name}" defer></script>`), `${name} is loaded by the page`);
}
// The engine thread and every module it imports, as JavaScript that imports only each other.
const engineFiles = fs.readdirSync(path.join(out, 'engine')).sort();
assert.ok(engineFiles.includes('web-worker.js') && engineFiles.includes('pipeline.js') && engineFiles.includes('investigate.js'));
assert.ok(!engineFiles.some(f => ['analyze.js', 'files.js', 'worker.js', 'cli.js', 'standin.js'].includes(f)), 'Node-only modules are not published');
for (const file of engineFiles) {
  const js = fs.readFileSync(path.join(out, 'engine', file), 'utf8');
  for (const [, spec] of js.matchAll(/^(?:import|export)\b[^;]*?\bfrom\s*'([^']+)'/gm)) assert.ok(/^\.\/[\w-]+\.js$/.test(spec) && engineFiles.includes(spec.slice(2)), `${file} imports ${spec}`);
  assert.doesNotMatch(js, /:\s*(string|number|boolean)\b[^'"\n]*[,)=;]/, `${file} has no type annotations left`);
}
assert.ok(fs.existsSync(path.join(out, 'examples', 'malicious_events.json')));
assert.match(html, /<a class="github-star-button" href="https:\/\/github.com\/tsale\/jevline" [^>]*aria-label="Star tsale\/jevline on GitHub">/);
assert.match(html, /<a class="github-star-count" href="https:\/\/github.com\/tsale\/jevline\/stargazers" [^>]*>1,234<\/a>/);
// The button is plain markup: the page still loads nothing from GitHub.
assert.doesNotMatch(html, /buttons\.github\.io|api\.github\.com/);

// Without a count (offline build, rate limit): the button alone.
build(out, 'https://github.com/tsale/jevline', null);
html = page();
assert.match(html, /class="github-star-button"/);
assert.doesNotMatch(html, /github-star-count/);
assert.equal(starCountHtml('https://github.com/a/b', 1).includes('1 user has starred'), true);

// The published modules run, and read the bundled example exactly as the TypeScript source does.
(async () => {
  const modules = fs.mkdtempSync(path.join(os.tmpdir(), 'jevline-engine-'));
  fs.cpSync(path.join(out, 'engine'), modules, {recursive: true});
  fs.writeFileSync(path.join(modules, 'package.json'), '{"type": "module"}');
  const example = path.join(__dirname, '..', 'examples', 'malicious_events.json');
  const file = new File([fs.readFileSync(example)], 'malicious_events.json');
  const built = await import(path.join(modules, 'browser.js'));
  const source = await import(path.join(__dirname, '..', 'engine', 'src', 'browser.ts'));
  const [a, b] = [await built.loadFiles([file]), await source.loadFiles([file])];
  assert.deepEqual(JSON.parse(JSON.stringify(a.events)), JSON.parse(JSON.stringify(b.events)));
  assert.equal(a.events.length, 65);
  fs.rmSync(modules, {recursive: true, force: true});
  fs.rmSync(out, {recursive: true, force: true});
  console.log(`build_site tests passed: page, ${engineFiles.length} engine modules that run as published`);
})().catch(error => { process.stderr.write(String(error.stack || error) + '\n'); process.exit(1); });
