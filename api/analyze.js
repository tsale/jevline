// Vercel function POST /api/analyze: analysis on the server with the site's free key (see _analyze.js).
module.exports = require('./_analyze.js').createHandler();
