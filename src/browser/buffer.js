const enc = new TextEncoder();
const dec = new TextDecoder();

function toBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

function fromBase64(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export class Buffer extends Uint8Array {
  static from(input, encoding = 'utf8') {
    if (input instanceof Uint8Array || Array.isArray(input)) return new Buffer(input);
    const s = String(input);
    if (encoding === 'base64' || encoding === 'base64url') return new Buffer(fromBase64(s));
    if (encoding === 'hex') return new Buffer((s.match(/../g) ?? []).map((h) => parseInt(h, 16)));
    return new Buffer(enc.encode(s));
  }

  toString(encoding = 'utf8') {
    if (encoding === 'hex') return [...this].map((b) => b.toString(16).padStart(2, '0')).join('');
    if (encoding === 'base64') return toBase64(this);
    if (encoding === 'base64url') return toBase64(this).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return dec.decode(this);
  }
}
