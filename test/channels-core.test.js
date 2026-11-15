const { test } = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const M2Channels = require('../channels-core.js');

// Port testu z M² Android: ChannelCryptoTest.kt
test('channel uses protocol hash (#test -> D9)', async () => {
  const secret = await M2Channels.deriveSecret('#test');
  assert.equal(secret.length, 32);
  assert.equal(await M2Channels.channelHash(secret), 'D9');
});

test('invalid hex is rejected', () => {
  assert.equal(M2Channels.decodeHex('abc'), null);
  assert.equal(M2Channels.decodeHex('zz'), null);
});

test('private channel MAC and payload are decoded', async () => {
  const secretHex = '8b3387e9c5cdea6ac9e5edbaa115cd72' + '7b47419961fa3d436e5a887739100d42';
  const secret = Buffer.from(secretHex, 'hex');
  const plain = Buffer.concat([
    Buffer.from([0x00, 0xf1, 0x53, 0x65, 0x00]),
    Buffer.from('Alice: private message', 'utf8')
  ]);
  const padded = Buffer.alloc(Math.ceil(plain.length / 16) * 16);
  plain.copy(padded);
  const cipher = nodeCrypto.createCipheriv('aes-128-ecb', secret.subarray(0, 16), null);
  cipher.setAutoPadding(false);
  const encrypted = Buffer.concat([cipher.update(padded), cipher.final()]);
  const hmacKey = Buffer.alloc(32);
  secret.copy(hmacKey, 0, 0, Math.min(secret.length, 32));
  const mac = nodeCrypto.createHmac('sha256', hmacKey).update(encrypted).digest().subarray(0, 2);

  assert.equal(await M2Channels.validMac(secretHex, mac.toString('hex'), encrypted.toString('hex')), true);
  const decoded = await M2Channels.decryptMessage(secretHex, encrypted.toString('hex'));
  assert.ok(decoded);
  assert.equal(decoded.sender, 'Alice');
  assert.equal(decoded.text, 'private message');
  assert.equal(Math.round(new Date(decoded.timestamp).getTime() / 1000), 1700000000);
});

test('wrong MAC is rejected', async () => {
  const secretHex = '8b3387e9c5cdea6ac9e5edbaa115cd727b47419961fa3d436e5a887739100d42';
  assert.equal(await M2Channels.validMac(secretHex, '0000', '00112233445566778899aabbccddeeff'), false);
});

test('parseChannel accepts public, named and private keys', async () => {
  assert.deepEqual(await M2Channels.parseChannel('PUBLIC'), { name: 'public', hash: 'public', secret: '', isPrivate: false });
  const named = await M2Channels.parseChannel('#test');
  assert.equal(named.name, '#test');
  assert.equal(named.hash, 'D9');
  assert.equal(named.isPrivate, false);
  const priv = await M2Channels.parseChannel('8B3387E9C5CDEA6AC9E5EDBAA115CD72');
  assert.equal(priv.name, 'Private channel');
  assert.equal(priv.isPrivate, true);
  assert.equal(priv.secret, '8b3387e9c5cdea6ac9e5edbaa115cd72');
  const qr = await M2Channels.parseChannel('meshcore://channel/add?name=Team&secret=8b3387e9c5cdea6ac9e5edbaa115cd72');
  assert.deepEqual([qr.name, qr.isPrivate], ['Team', true]);
  assert.equal(await M2Channels.parseChannel('not-a-channel'), null);
});

test('messages are merged, deduplicated and capped', () => {
  const base = [{ id: 'a', timestamp: '2026-01-01T10:00:00Z' }, { id: 'b', timestamp: '2026-01-01T09:00:00Z' }];
  const merged = M2Channels.mergeMessages(base, [{ id: 'b', timestamp: '2026-01-01T09:00:00Z' }, { id: 'c', timestamp: '2026-01-01T11:00:00Z' }]);
  assert.deepEqual(merged.map(m => m.id), ['c', 'a', 'b']);
  assert.equal(M2Channels.unreadCount(merged, Date.parse('2026-01-01T09:30:00Z')), 2);
});

test('named channel messages use Android-compatible AES-ECB with a 16-byte secret', async () => {
  const secretHex = await M2Channels.deriveSecret('#test');
  const secret = Buffer.from(secretHex, 'hex');
  const epoch = 1700000000;
  const plain = Buffer.concat([
    Buffer.from([epoch & 255, (epoch >>> 8) & 255, (epoch >>> 16) & 255, (epoch >>> 24) & 255, 0]),
    Buffer.from('Alice: #test message', 'utf8')
  ]);
  const padded = Buffer.alloc(Math.ceil(plain.length / 16) * 16);
  plain.copy(padded);
  const cipher = nodeCrypto.createCipheriv('aes-128-ecb', secret, null);
  cipher.setAutoPadding(false);
  const encrypted = Buffer.concat([cipher.update(padded), cipher.final()]);
  const decoded = await M2Channels.decryptMessage(secretHex, encrypted.toString('hex'));

  assert.ok(decoded);
  assert.equal(decoded.sender, 'Alice');
  assert.equal(decoded.text, '#test message');
  assert.equal(Math.round(new Date(decoded.timestamp).getTime() / 1000), epoch);
});
