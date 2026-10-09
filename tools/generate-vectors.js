const c = require('crypto');
const payload = '{"event":"invoice.paid","id":"evt_123"}';
const stripeSecret = 'whsec_test_secret_key_for_vectors_only_1234567890';
const ts = '1700000000';
const stripeSig = c.createHmac('sha256', stripeSecret).update(ts + '.' + payload).digest('hex');
const ghPayload = '{"action":"opened"}';
const ghSecret = 'ghs_test_secret';
const ghSig = c.createHmac('sha256', ghSecret).update(ghPayload).digest('hex');

const vectors = {
  version: 1,
  description: 'Shared cross-language test vectors for webhook-signer. Every implementation must pass all of these.',
  hmac_sha256: [
    {
      name: 'rfc4231_case1',
      key_hex: '0b'.repeat(20),
      payload: 'Hi There',
      payload_encoding: 'utf8',
      signature_hex: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
    },
    {
      name: 'rfc4231_case2',
      key: 'Jefe',
      payload: 'what do ya want for nothing?',
      payload_encoding: 'utf8',
      signature_hex: '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'
    },
    {
      name: 'empty_payload',
      key: 'secret-key',
      payload: '',
      payload_encoding: 'utf8',
      signature_hex: c.createHmac('sha256', 'secret-key').update('').digest('hex')
    },
    {
      name: 'binary_payload',
      key_hex: '000102030405060708090a0b0c0d0e0f',
      payload_hex: 'deadbeefcafe00ff',
      payload_encoding: 'hex',
      signature_hex: c.createHmac('sha256', Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex')).update(Buffer.from('deadbeefcafe00ff', 'hex')).digest('hex')
    }
  ],
  ed25519: [
    {
      name: 'rfc8032_vector1_empty_message',
      secret_key_hex: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      public_key_hex: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
      payload_hex: '',
      payload_encoding: 'hex',
      signature_hex: 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe246551414348e7a100b'.replace('348e7a', '38e7a')
    },
    {
      name: 'rfc8032_vector2_one_byte',
      secret_key_hex: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
      public_key_hex: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
      payload_hex: '72',
      payload_encoding: 'hex',
      signature_hex: '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'
    },
    {
      name: 'rfc8032_vector3_json_payload',
      secret_key_hex: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
      public_key_hex: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
      payload: '{"event":"push","ref":"refs/heads/main"}',
      payload_encoding: 'utf8',
      signature_hex: null
    }
  ],
  header_stripe_style: [
    {
      name: 'valid_recent',
      secret: stripeSecret,
      payload: payload,
      timestamp: ts,
      header: 't=' + ts + ',v1=' + stripeSig,
      signature_hex: stripeSig,
      now: 1700000100,
      tolerance_seconds: 300,
      expect_valid: true
    },
    {
      name: 'expired_timestamp',
      secret: stripeSecret,
      payload: payload,
      timestamp: ts,
      header: 't=' + ts + ',v1=' + stripeSig,
      signature_hex: stripeSig,
      now: 1700009999,
      tolerance_seconds: 300,
      expect_valid: false
    },
    {
      name: 'tampered_payload',
      secret: stripeSecret,
      payload: '{"event":"invoice.paid","id":"evt_999"}',
      timestamp: ts,
      header: 't=' + ts + ',v1=' + stripeSig,
      signature_hex: stripeSig,
      now: 1700000100,
      tolerance_seconds: 300,
      expect_valid: false
    },
    {
      name: 'wrong_secret',
      secret: 'whsec_wrong_secret_value_abcdefghij_0123456789ab',
      payload: payload,
      timestamp: ts,
      header: 't=' + ts + ',v1=' + stripeSig,
      signature_hex: stripeSig,
      now: 1700000100,
      tolerance_seconds: 300,
      expect_valid: false
    }
  ],
  header_github_style: [
    {
      name: 'valid_sha256',
      secret: ghSecret,
      payload: ghPayload,
      header: 'sha256=' + ghSig,
      signature_hex: ghSig,
      expect_valid: true
    },
    {
      name: 'tampered',
      secret: ghSecret,
      payload: '{"action":"closed"}',
      header: 'sha256=' + ghSig,
      signature_hex: ghSig,
      expect_valid: false
    }
  ],
  check_secret: [
    { secret: 'short', expect_ok: false, expect_issue: 'too_short' },
    { secret: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', expect_ok: false, expect_issue: 'low_entropy' },
    { secret: 'whsec_test_secret_key_for_vectors_only_1234567890', expect_ok: true, expect_issue: null }
  ]
};

// Compute RFC 8032 vector 3 signature deterministically with Node crypto (ed25519).
const sk3 = Buffer.from(vectors.ed25519[2].secret_key_hex, 'hex');
const priv = c.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), sk3]), format: 'der', type: 'pkcs8' });
const sig3 = c.sign(null, Buffer.from(vectors.ed25519[2].payload, 'utf8'), priv);
vectors.ed25519[2].signature_hex = sig3.toString('hex');

// Self-verify all vectors before writing.
for (const v of vectors.ed25519) {
  const pub = c.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(v.public_key_hex, 'hex')]), format: 'der', type: 'spki' });
  const msg = v.payload_encoding === 'hex' ? Buffer.from(v.payload_hex, 'hex') : Buffer.from(v.payload, 'utf8');
  const ok = c.verify(null, msg, pub, Buffer.from(v.signature_hex, 'hex'));
  if (!ok) throw new Error('ed25519 vector failed self-check: ' + v.name);
}
console.log('all ed25519 vectors self-verified');
require('fs').writeFileSync(__dirname + '/vectors/vectors.json', JSON.stringify(vectors, null, 2) + '\n');
console.log('vectors.json written');
