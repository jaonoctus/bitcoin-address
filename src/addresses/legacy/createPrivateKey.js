const { Crypto } = require('cryptojs')

/**
 * Private ECDSA key
 *
 * https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
 * https://en.bitcoin.it/wiki/Secp256k1
 * https://en.bitcoin.it/wiki/Private_key
 */

const createPrivateKey = () => {
  // random 32 bytes
  const privateKeyBytes = Crypto.util.randomBytes(32)

  const privateKey = Crypto.util.bytesToHex(privateKeyBytes)

  return {
    privateKey,
  }
}

exports.createPrivateKey = createPrivateKey
