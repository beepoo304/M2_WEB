// M² Web — channel logic (port from M² Android: ChannelCrypto + ChannelRepository).
// MeshCore channels use AES-128-ECB with a 2-byte HMAC-SHA256 check, exactly as
// M² ChannelCrypto.decryptMessage does; there is no other cipher mode.

(function (root) {
  'use strict';

  // ---------- AES-128-ECB decrypt ----------
  const SBOX = new Uint8Array(256);
  const INV_SBOX = new Uint8Array(256);
  (function buildTables() {
    const mul = (a, b) => {
      let p = 0;
      for (let i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        const hi = a & 0x80;
        a = (a << 1) & 0xff;
        if (hi) a ^= 0x1b;
        b >>= 1;
      }
      return p;
    };
    const rotl = (v, n) => ((v << n) | (v >>> (8 - n))) & 0xff;
    const inverse = new Uint8Array(256);
    for (let a = 1; a < 256; a++) {
      for (let b = 1; b < 256; b++) {
        if (mul(a, b) === 1) { inverse[a] = b; break; }
      }
    }
    for (let i = 0; i < 256; i++) {
      const value = inverse[i];
      SBOX[i] = value ^ rotl(value, 1) ^ rotl(value, 2) ^ rotl(value, 3) ^ rotl(value, 4) ^ 0x63;
      INV_SBOX[SBOX[i]] = i;
    }
  })();

  const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

  function expandKey(key16) {
    const words = [];
    for (let i = 0; i < 4; i++) words.push([key16[4 * i], key16[4 * i + 1], key16[4 * i + 2], key16[4 * i + 3]]);
    for (let i = 4; i < 44; i++) {
      let temp = words[i - 1].slice();
      if (i % 4 === 0) {
        temp = [temp[1], temp[2], temp[3], temp[0]].map((v, j) => SBOX[v] ^ (j === 0 ? RCON[i / 4] : 0));
      }
      words.push(words[i - 4].map((v, j) => v ^ temp[j]));
    }
    return words;
  }

  function aesDecryptBlock(words, block) {
    const state = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) state[r][c] = block[c * 4 + r];
    const addRoundKey = round => {
      for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) state[r][c] ^= words[round * 4 + c][r];
    };
    const invShiftRows = () => {
      for (let r = 1; r < 4; r++) {
        const row = state[r];
        state[r] = row.slice(4 - r).concat(row.slice(0, 4 - r));
      }
    };
    const invSubBytes = () => {
      for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) state[r][c] = INV_SBOX[state[r][c]];
    };
    const mul2 = a => ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;
    const mul4 = a => mul2(mul2(a));
    const mul8 = a => mul2(mul4(a));
    const mul9 = a => mul8(a) ^ a;
    const mul11 = a => mul8(a) ^ mul2(a) ^ a;
    const mul13 = a => mul8(a) ^ mul4(a) ^ a;
    const mul14 = a => mul8(a) ^ mul4(a) ^ mul2(a);
    const invMixColumns = () => {
      for (let c = 0; c < 4; c++) {
        const a = state[0][c], b = state[1][c], d = state[2][c], e = state[3][c];
        state[0][c] = mul14(a) ^ mul11(b) ^ mul13(d) ^ mul9(e);
        state[1][c] = mul9(a) ^ mul14(b) ^ mul11(d) ^ mul13(e);
        state[2][c] = mul13(a) ^ mul9(b) ^ mul14(d) ^ mul11(e);
        state[3][c] = mul11(a) ^ mul13(b) ^ mul9(d) ^ mul14(e);
      }
    };
    addRoundKey(10);
    for (let round = 9; round >= 1; round--) {
      invShiftRows();
      invSubBytes();
      addRoundKey(round);
      invMixColumns();
    }
    invShiftRows();
    invSubBytes();
    addRoundKey(0);
    const out = new Uint8Array(16);
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) out[c * 4 + r] = state[r][c];
    return out;
  }

  function aesEcbDecrypt(key16, data) {
    if (!data || data.length === 0 || data.length % 16 !== 0) return null;
    const words = expandKey(key16), out = new Uint8Array(data.length);
    for (let offset = 0; offset < data.length; offset += 16) {
      const block = data.subarray ? data.subarray(offset, offset + 16) : data.slice(offset, offset + 16);
      aesDecryptBlock(words, block).forEach((v, i) => out[offset + i] = v);
    }
    return out;
  }

  // ---------- Helpers ----------
  function decodeHex(value) {
    const text = String(value || '').trim();
    if (text.length < 2 || text.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(text)) return null;
    const out = new Uint8Array(text.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
    return out;
  }

  function encodeHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  const encoder = () => new (root.TextEncoder || globalThis.TextEncoder)();

  async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  }

  async function hmacSha256(key, data) {
    const imported = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', imported, data));
  }

  // ---------- Channel secret utilities ----------
  async function deriveSecret(name) {
    const digest = await sha256(encoder().encode(String(name)));
    return encodeHex(digest.slice(0, 16));
  }

  async function channelHash(secretHex) {
    const secret = typeof secretHex === 'string' ? decodeHex(secretHex) : secretHex;
    if (!secret) return null;
    const digest = await sha256(secret);
    return digest[0].toString(16).padStart(2, '0').toUpperCase();
  }

  // ---------- MAC validation ----------
  async function validMac(secretHex, expectedMacHex, encryptedHex) {
    const secret = decodeHex(secretHex), expected = decodeHex(expectedMacHex), encrypted = decodeHex(encryptedHex);
    if (!secret || !expected || !encrypted || expected.length < 2) return false;
    const key = new Uint8Array(32);
    key.set(secret.subarray(0, Math.min(secret.length, 32)));
    const mac = await hmacSha256(key, encrypted);
    return mac[0] === expected[0] && mac[1] === expected[1];
  }

  // ---------- Decrypt channel messages (M² ChannelCrypto: AES-128-ECB) ----------
  function decodePlainMessage(plain) {
    if (!plain || plain.length < 6) return null;
    const view = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
    const epoch = view.getUint32(0, true);
    let end = 5;
    while (end < plain.length && plain[end] !== 0) end++;
    // Kotlin String(bytes, UTF_8) replaces invalid sequences instead of failing.
    const body = new TextDecoder('utf-8').decode(plain.subarray(5, end));
    const split = body.indexOf(': ');
    return {
      sender: split > 0 ? body.slice(0, split) : 'Anonymous',
      text: split > 0 ? body.slice(split + 2) : body,
      timestamp: new Date(epoch * 1000).toISOString()
    };
  }

  async function decryptMessage(secretHex, encryptedHex) {
    const secret = decodeHex(secretHex), encrypted = decodeHex(encryptedHex);
    if (!secret || !encrypted || secret.length < 16) return null;

    try {
      return decodePlainMessage(aesEcbDecrypt(secret.slice(0, 16), encrypted));
    } catch {
      return null;
    }
  }

  // ---------- Channel parsing ----------
  const HEX_SECRET_RE = /^(?:[0-9a-f]{32}|[0-9a-f]{64})$/i;
  async function parseChannel(value) {
    const input = String(value || '').trim();
    if (!input) return null;
    if (/^public$/i.test(input)) return { name: 'Public', hash: 'Public', secret: '', isPrivate: false };
    if (/^meshcore:\/\/channel\/add/i.test(input)) {
      try {
        const url = new URL(input);
        const secretText = (url.searchParams.get('secret') || '').trim();
        if (!HEX_SECRET_RE.test(secretText)) return null;
        const name = (url.searchParams.get('name') || '').trim() || 'Private channel';
        return { name, hash: await channelHash(secretText.toLowerCase()), secret: secretText.toLowerCase(), isPrivate: true };
      } catch { return null; }
    }
    if (input.startsWith('#') && input.length > 1) {
      const secret = await deriveSecret(input);
      return { name: input, hash: await channelHash(secret), secret, isPrivate: false };
    }
    if (HEX_SECRET_RE.test(input)) {
      return { name: 'Private channel', hash: await channelHash(input.toLowerCase()), secret: input.toLowerCase(), isPrivate: true };
    }
    return null;
  }

  // ---------- Message handling ----------
  const messageEpoch = message => {
    const v = Date.parse(message.timestamp);
    return Number.isFinite(v) ? v : 0;
  };

  function sortMessages(values) {
    return [...values]
      .filter(Boolean)
      .filter((msg, i, all) => all.findIndex(m => m.id === msg.id) === i)
      .sort((a, b) => messageEpoch(b) - messageEpoch(a));
  }

  function mergeMessages(cached, incoming, clearedAt = 0) {
    const fresh = (Array.isArray(incoming) ? incoming : []).filter(msg => messageEpoch(msg) > clearedAt);
    if (!fresh.length) return sortMessages(cached);
    return sortMessages(fresh.concat(cached)).slice(0, 250);
  }

  function unreadCount(messages, lastReadAtMs) {
    return (Array.isArray(messages) ? messages : []).filter(msg => messageEpoch(msg) > (Number(lastReadAtMs) || 0)).length;
  }

  const api = {
    HEX_SECRET_RE,
    decodeHex,
    encodeHex,
    sha256,
    hmacSha256,
    deriveSecret,
    channelHash,
    validMac,
    decryptMessage,
    parseChannel,
    sortMessages,
    mergeMessages,
    unreadCount,
    messageEpoch,
    _aesEcbDecrypt: aesEcbDecrypt,
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.M2Channels = api;
})(typeof window !== 'undefined' ? window : globalThis);