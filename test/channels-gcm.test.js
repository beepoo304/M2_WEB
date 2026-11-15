const assert = require('assert');
const M2Channels = require('../channels-core');

// Helper to encrypt a message using AES‑GCM (zero IV) matching the new implementation.
async function encryptMessage(secretHex, payload) {
  const secret = Buffer.from(secretHex, 'hex');
  const keyData = secret.slice(0, 16);
  const iv = new Uint8Array(12); // zero IV
  let payloadBytes;
  if (payload instanceof Uint8Array) {
    payloadBytes = payload;
  } else {
    const encoder = new TextEncoder();
    payloadBytes = encoder.encode(String(payload));
  }
  const key = await crypto.subtle.importKey('raw', keyData, { name: 'AES-GCM' }, false, ['encrypt']);
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, payloadBytes);
  return Buffer.from(new Uint8Array(cipherBuf)).toString('hex');
}

(async () => {
  const secretHex = '00112233445566778899aabbccddeeff';
  const epoch = Math.floor(Date.now() / 1000);
  const message = 'Alice: Hello world';
  const encoder = new TextEncoder();
  const body = encoder.encode(message);
  const buf = new Uint8Array(5 + body.length + 1);
  const view = new DataView(buf.buffer);
  view.setUint32(0, epoch, true); // little‑endian epoch
  buf.set(body, 5);
  // null terminator already zero
  const encryptedHex = await encryptMessage(secretHex, buf);
  const result = await M2Channels.decryptMessage(secretHex, encryptedHex);
  assert.strictEqual(result.sender, 'Alice');
  assert.strictEqual(result.text, 'Hello world');
  const decodedEpoch = Math.floor(new Date(result.timestamp).getTime() / 1000);
  assert.ok(Math.abs(decodedEpoch - epoch) <= 1);
  console.log('AES‑GCM decryption test passed');
})();
