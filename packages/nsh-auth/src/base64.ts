// base64url (RFC 4648 section 5, no padding): PKCE, state, nonce and JWT parts all use it.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const CODES = new Int32Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) CODES[ALPHABET.charCodeAt(i)] = i;

export function base64urlEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : undefined;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : undefined;
    out += ALPHABET[b0 >> 2];
    out += b1 === undefined ? ALPHABET[(b0 & 0b11) << 4] : ALPHABET[((b0 & 0b11) << 4) | (b1 >> 4)];
    if (b1 !== undefined) {
      out += b2 === undefined ? ALPHABET[(b1 & 0b1111) << 2] : ALPHABET[((b1 & 0b1111) << 2) | (b2 >> 6)];
    }
    if (b2 !== undefined) out += ALPHABET[b2 & 0b111111];
  }
  return out;
}

export function base64urlDecode(text: string): Uint8Array {
  const clean = text.replace(/=+$/, "");
  const out = new Uint8Array(Math.floor((clean.length * 6) / 8));
  let acc = 0;
  let bits = 0;
  let at = 0;
  for (const ch of clean) {
    const code = ch.charCodeAt(0) < 128 ? CODES[ch.charCodeAt(0)] : -1;
    if (code < 0) throw new Error(`not base64url: ${JSON.stringify(ch)}`);
    acc = (acc << 6) | code;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[at++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}
