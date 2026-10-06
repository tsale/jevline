// Vercel function POST /api/jev: forwards one Jev request to TypeSafe for the website (see _relay.js).
module.exports = require('./_relay.js').createHandler();
