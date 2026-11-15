// HMAC-SHA256 helpers for Agent Games.
//
// The platform signs every inbound envelope with the secret issued at agent
// registration (dashboard "Rotate Secret") and puts the signature in the
// `x-agent-games-signature` header. We verify it over the RAW request body
// BEFORE parsing JSON, and sign every response the same way (header over
// the raw response body).
//
// Format note: the official docs do not state the exact header encoding,
// so the encoding is configurable and inbound verification accepts ALL
// known encodings. Outbound signing uses AGENT_GAMES_HMAC_FORMAT:
//   "hex" (default)   -> <lowercase hex>
//   "sha256="         -> sha256=<lowercase hex>
//   "base64"          -> <base64>
//   "sha256=base64"   -> sha256=<base64>
// Preflight is the verification step for the format: try them in order
// (hex, sha256=, base64, sha256=base64) until preflight passes.

const crypto = require('crypto');

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function hmacBase64(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
}

function signatureFor(secret, rawBody, format) {
  const hex = hmacHex(secret, rawBody);
  switch (format) {
    case 'sha256=': return 'sha256=' + hex;
    case 'base64': return hmacBase64(secret, rawBody);
    case 'sha256=base64': return 'sha256=' + hmacBase64(secret, rawBody);
    default: return hex;
  }
}

function verifySignature(secret, rawBody, headerValue, format) {
  if (!secret || !headerValue) return false;
  const hex = hmacHex(secret, rawBody);
  const b64 = hmacBase64(secret, rawBody);
  // Configured format first, then every other known encoding, so a
  // platform that signs requests and verifies responses in different
  // encodings still works.
  const all = [
    signatureFor(secret, rawBody, format),
    hex,
    'sha256=' + hex,
    b64,
    'sha256=' + b64,
  ];
  const ordered = [...new Set(all)];
  const b = Buffer.from(String(headerValue));
  for (const candidate of ordered) {
    const a = Buffer.from(candidate);
    if (a.length !== b.length) continue;
    try {
      if (crypto.timingSafeEqual(a, b)) return true;
    } catch { /* try next candidate */ }
  }
  return false;
}

module.exports = { hmacHex, hmacBase64, signatureFor, verifySignature };
