// Field arithmetic for the BN128 (alt_bn128) prime field, plus keccak256.
// The Agent Games circuits (Groth16/BN128, Circom 2.x) work over this field.
// FIELD_PRIME is the BN128 prime; keccak_256 comes from js-sha3 (Node's
// built-in crypto has SHA3-256, which is NOT the same as Keccak-256).

const { keccak_256 } = require('js-sha3');

const FIELD_PRIME = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
);

// Convert a hex string (0x..), decimal string, number, or BigInt to a field
// element (BigInt, reduced mod p).
function toField(x) {
  let b;
  if (typeof x === 'bigint') b = x;
  else if (typeof x === 'number') b = BigInt(x);
  else if (typeof x === 'string' && x.startsWith('0x')) b = BigInt(x);
  else b = BigInt(x);
  const r = b % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}

// Hex-first conversion: a bare hex string (e.g. from `openssl rand -hex 16`)
// is not a valid decimal, so plain BigInt() would throw on a-f digits.
function toFieldHex(x) {
  if (typeof x === 'string' && !x.startsWith('0x') && /^[0-9a-fA-F]+$/.test(x)) {
    return toField(BigInt('0x' + x));
  }
  return toField(x);
}

// Normalize a value to a 0x-prefixed hex string (snarkjs inputs accept
// 0x-hex or decimal strings).
function toHexString(x) {
  const s = String(x || '');
  if (s.startsWith('0x')) return s;
  if (/^[0-9a-fA-F]+$/.test(s)) return '0x' + s;
  return s;
}

// Field element -> 32-byte big-endian Buffer (for ABI packing / keccak input).
function to32Bytes(x) {
  const b = toField(x);
  return Buffer.from(b.toString(16).padStart(64, '0'), 'hex');
}

function keccak256Hex(buffers) {
  return '0x' + keccak_256(Buffer.concat(buffers));
}

function keccak256ModP(buffers) {
  return toField(BigInt(keccak256Hex(buffers)));
}

module.exports = {
  FIELD_PRIME,
  toField,
  toFieldHex,
  toHexString,
  to32Bytes,
  keccak256Hex,
  keccak256ModP,
};
