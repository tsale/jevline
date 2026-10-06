// Run with: node tests/test_build_site.js (from the repository root). Offline: no star count is fetched.
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

fs.rmSync(out, {recursive: true, force: true});
console.log('build_site tests passed');
