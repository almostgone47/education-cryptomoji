'use strict';

const secp256k1 = require('secp256k1-pure');
const sha256 = require('sha256');
const { randomBytes, createHash } = require('crypto');

/**
 * A function which generates a new random Secp256k1 private key, returning
 * it as a 64 character hexadecimal string.
 *
 * Example:
 *   const privateKey = createPrivateKey();
 *   console.log(privateKey);
 *   // 'e291df3eede7f0c520fddbe5e9e53434ff7ef3c0894ed9d9cbcb6596f1cfe87e'
 */
const createPrivateKey = () => {
  const privKey = randomBytes(32);

  if (secp256k1.privateKeyVerify(privKey)) {
    return privKey.toString('hex');
  }
};
/**
 * A function which takes a hexadecimal private key and returns its public pair
 * as a 66 character hexadecimal string.
 *
 * Example:
 *   const publicKey = getPublicKey(privateKey);
 *   console.log(publicKey);
 *   // '0202694593ddc71061e622222ed400f5373cfa7ea607ce106cca3f039b0f9a0123'
 *
 * Hint:
 *   Remember that the secp256k1-node library expects raw bytes (i.e Buffers),
 *   not hex strings! You'll have to convert the private key.
 */
const getPublicKey = privateKey => {
  const privKeyBuffer = Buffer.from(privateKey.toString('hex'), 'hex');

  const pubKey = secp256k1.publicKeyCreate(privKeyBuffer);
  return pubKey.toString('hex');
};
/**
 * A function which takes a hex private key and a string message, returning
 * a 128 character hexadecimal signature.
 *
 * Example:
 *   const signature = sign(privateKey, 'Hello World!');
 *   console.log(signature);
 *   // '4ae1f0b20382ad628804a5a66e09cc6bdf2c83fa64f8017e98d84cc75a1a71b52...'
 *
 * Hint:
 *   Remember that you need to sign a SHA-256 hash of the message,
 *   not the message itself!
 */
const sign = (privateKey, message) => {
  const msg = Buffer.from(sha256(message), 'hex');
  const privKey = Buffer.from(privateKey, 'hex');

  const sigObj = secp256k1.sign(msg, privKey);
  return sigObj.signature.toString('hex');
};
/**
 * A function which takes a hex public key, a string message, and a hex
 * signature, and returns either true or false.
 *
 * Example:
 *   console.log( verify(publicKey, 'Hello World!', signature) );
 *   // true
 *   console.log( verify(publicKey, 'Hello World?', signature) );
 *   // false
 */
const verify = (publicKey, message, signature) => {
  // convert hex public key to buffer
  const pubKey = Buffer.from(publicKey, 'hex');
  // convert string message to buffer
  const msg = Buffer.from(sha256(message), 'hex');
  // convert hex signiture
  const signed = Buffer.from(signature, 'hex');
  console.log(msg, signed, pubKey);
  secp256k1.verify(msg, signed, pubKey);
};

module.exports = {
  createPrivateKey,
  getPublicKey,
  sign,
  verify,
};
