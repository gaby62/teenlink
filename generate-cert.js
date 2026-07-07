const { generateKeyPairSync, createSign, createHash, randomBytes } = require('crypto');
const fs = require('fs');
const path = require('path');

const CERT_DIR = path.join(__dirname);
const CERT_FILE = path.join(CERT_DIR, 'cert.pem');
const KEY_FILE = path.join(CERT_DIR, 'key.pem');

function generateSelfSignedCert() {
  if (fs.existsSync(CERT_FILE) && fs.existsSync(KEY_FILE)) {
    console.log('Certificats déjà existants, réutilisation...');
    return { cert: fs.readFileSync(CERT_FILE, 'utf8'), key: fs.readFileSync(KEY_FILE, 'utf8') };
  }

  console.log('Génération du certificat auto-signé...');

  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });

  const serialNumber = randomBytes(16);
  const now = new Date();
  const notBefore = new Date(now);
  const notAfter = new Date(now);
  notAfter.setFullYear(notAfter.getFullYear() + 1);

  const tbs = buildTBSCertificate(publicKey, serialNumber, notBefore, notAfter);

  const hash = createHash('sha256').update(tbs).digest();
  const sign = createSign('RSA-SHA256');
  sign.update(tbs);
  const signature = sign.sign({ key: privateKey, format: 'der', type: 'pkcs8' });

  const cert = buildCertificate(tbs, signature);

  const certPem = '-----BEGIN CERTIFICATE-----\n' + cert.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----';
  const keyPem = '-----BEGIN PRIVATE KEY-----\n' + privateKey.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END PRIVATE KEY-----';

  fs.writeFileSync(CERT_FILE, certPem);
  fs.writeFileSync(KEY_FILE, keyPem);

  console.log('Certificats générés !');
  return { cert: certPem, key: keyPem };
}

function buildTBSCertificate(publicKeyDer, serialNumber, notBefore, notAfter) {
  const seq = [];
  seq.push(encodeSequence([
    encodeInteger(0x02), // version v3
    encodeInteger(serialNumber),
    encodeAlgorithmIdentifier(),
    encodeRawString('RencontreAdos'),
    encodeValidity(notBefore, notAfter),
    encodeRawString('RencontreAdos'),
    encodePublicKeyInfo(publicKeyDer),
    encodeExtensions()
  ]));
  return Buffer.concat(seq);
}

function buildCertificate(tbs, signature) {
  return encodeSequence([
    tbs,
    encodeAlgorithmIdentifier(),
    encodeBitString(signature)
  ]);
}

function encodeLength(len) {
  if (len < 128) return Buffer.from([len]);
  if (len < 256) return Buffer.from([0x81, len]);
  return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function encodeSequence(items) {
  const parts = Buffer.concat(items);
  return Buffer.concat([Buffer.from([0x30]), encodeLength(parts.length), parts]);
}

function encodeInteger(value) {
  if (Buffer.isBuffer(value)) {
    if (value[0] & 0x80) value = Buffer.concat([Buffer.from([0x00]), value]);
    return Buffer.concat([Buffer.from([0x02]), encodeLength(value.length), value]);
  }
  const hex = value.toString(16);
  const buf = Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex');
  if (buf[0] & 0x80) return Buffer.concat([Buffer.from([0x02, buf.length + 1, 0x00]), buf]);
  return Buffer.concat([Buffer.from([0x02, buf.length]), buf]);
}

function encodeBitString(data) {
  return Buffer.concat([Buffer.from([0x03]), encodeLength(data.length + 1), Buffer.from([0x00]), data]);
}

function encodeRawString(str) {
  const buf = Buffer.from(str, 'utf8');
  return Buffer.concat([Buffer.from([0x0c]), encodeLength(buf.length), buf]);
}

function encodeOid(oid) {
  const parts = oid.split('.').map(Number);
  const first = parts[0] * 40 + parts[1];
  const body = [first];
  for (let i = 2; i < parts.length; i++) {
    let val = parts[i];
    const chunks = [];
    chunks.unshift(val & 0x7f);
    val >>= 7;
    while (val > 0) { chunks.unshift((val & 0x7f) | 0x80); val >>= 7; }
    body.push(...chunks);
  }
  const buf = Buffer.from(body);
  return Buffer.concat([Buffer.from([0x06]), encodeLength(buf.length), buf]);
}

function encodeAlgorithmIdentifier() {
  return encodeSequence([
    encodeOid('1.2.840.113549.1.1.11'), // sha256WithRSAEncryption
    encodeSequence([])
  ]);
}

function encodeValidity(notBefore, notAfter) {
  return encodeSequence([
    encodeUTCTime(notBefore),
    encodeUTCTime(notAfter)
  ]);
}

function encodeUTCTime(date) {
  const y = date.getUTCFullYear() % 100;
  const str = [y, date.getUTCMonth() + 1, date.getUTCDate(), date.getUTCHours(), date.getUTCMinutes(), date.getUTCSeconds()]
    .map(n => n.toString().padStart(2, '0')).join('') + 'Z';
  const buf = Buffer.from(str, 'ascii');
  return Buffer.concat([Buffer.from([0x17]), encodeLength(buf.length), buf]);
}

function encodePublicKeyInfo(der) {
  return encodeSequence([
    encodeAlgorithmIdentifier(),
    encodeBitString(der)
  ]);
}

function encodeExtensions() {
  return encodeSequence([]); // empty extensions
}

module.exports = { generateSelfSignedCert };
