// Vercel function GET /api/stars: the repository's current star count, read from GitHub here and cached
// for an hour, so the page shows a live count without the visitor's browser ever contacting GitHub.
'use strict';
const {repositorySlug, repositoryUrl} = require('../scripts/build_site.js');

let cached = null;  // {count, at}
const TTL_MS = 60 * 60 * 1000;

module.exports = async function handler(req, res) {
  const send = (status, value, maxAge) => {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', maxAge ? `public, s-maxage=${maxAge}, stale-while-revalidate=${maxAge}` : 'no-store');
    res.end(JSON.stringify(value));
  };
  if (req.method !== 'GET') return send(405, {error: 'Use GET.'});
  if (cached && Date.now() - cached.at < TTL_MS) return send(200, {count: cached.count}, 3600);
  const slug = repositorySlug(repositoryUrl());
  if (!slug) return send(404, {error: 'Not a GitHub repository.'});
  try {
    const response = await fetch(`https://api.github.com/repos/${slug}`, {headers: {accept: 'application/vnd.github+json', 'user-agent': 'jevline-site'},
      signal: AbortSignal.timeout(5000)});
    const count = response.ok ? (await response.json()).stargazers_count : null;
    if (!Number.isInteger(count) || count < 0) return send(502, {error: 'GitHub did not return a star count.'});
    cached = {count, at: Date.now()};
    return send(200, {count}, 3600);
  } catch {
    return send(502, {error: 'GitHub could not be reached.'});
  }
};
