// HMAC-SHA256 helpers for Agent Games.
//
// The platform signs every inbound envelope with the secret issued at agent
// registration (dashboard "Rotate Secret") and puts the signature in the
// `x-agent-games-signature` header. We verify it over the RAW request body
// BEFORE parsing JSON, and sign every response the same way (header over
// the raw response body).
//
// Format note: the official docs do not state the exact header encoding.
// The standard assumption is a lowercase hex HMAC-SHA256 of the raw body.
// If the platform rejects the preflight, set AGENT_GAMES_HMAC_FORMAT=sha256=
// to send/verify the `sha256=<hex>` form instead. Preflight is the
// verification step for the format.

const crypto = require('crypto');

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function signatureFor(secret, rawBody, format) {
  const hex = hmacHex(secret, rawBody);
  return format === 'sha256=' ? 'sha256=' + hex : hex;
}

function verifySignature(secret, rawBody, headerValue, format) {
  if (!secret || !headerValue) return false;
  const hex = hmacHex(secret, rawBody);
  // Accept BOTH encodings on inbound requests: the platform signs
  // preflight as `sha256=<hex>` but task dispatches may arrive as raw
  // hex (or vice versa). The configured `format` is tried first, then
  // the other one. Outbound signing still uses `format` only.
  const preferred = format === 'sha256=' ? 'sha256=' + hex : hex;
  const other = format === 'sha256=' ? hex : 'sha256=' + hex;
  const b = Buffer.from(String(headerValue));
  for (const candidate of [preferred, other]) {
    const a = Buffer.from(candidate);
    if (a.length !== b.length) continue;
    try {
      if (crypto.timingSafeEqual(a, b)) return true;
    } catch { /* try next candidate */ }
  }
  return false;
}

module.exports = { hmacHex, signatureFor, verifySignature };
