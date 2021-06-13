const { Crypto } = require('cryptojs')
const EllipticCurve = require('eccrypto')

/**
 * A number that corresponds to a private key,
 * but does not need to be kept secret.
 *
 * A public key can be calculated from a private key, but not vice versa.
 * A public key can be used to determine if a signature is genuine
 * without requiring the private key to be divulged.
 *
 * In Bitcoin, public keys are either compressed or uncompressed.
 *
 * Compressed public keys are 33 bytes,
 * consisting of a prefix either 0x02 or 0x03,
 * and a 256-bit integer called x.
 *
 * The older uncompressed keys are 65 bytes,
 * consisting of constant prefix (0x04),
 * followed by two 256-bit integers called x and y (2 * 32 bytes).
 *
 * The prefix of a compressed key
 * allows for the y value to be derived from the x value.
 */
const createPublicKey = (privateKey = '') => {
  const privateKeyBytes = Crypto.util.hexToBytes(privateKey)

  const privateKeyBuffer = Buffer.from(privateKeyBytes)

  const publicKeyBuffer = EllipticCurve.getPublic(privateKeyBuffer)

  // 1 byte prefix + 32 bytes x + 32 bytes y
  const publicKey = Crypto.util.bytesToHex(publicKeyBuffer)

  const prefix = publicKey.slice(0, 2)

  const x = publicKey.slice(2, 2 + 2 * 32)

  const y = publicKey.slice(2 + 2 * 32, 2 + 4 * 32)

  return {
    publicKey,
    prefix,
    x,
    y,
  }
}

exports.createPublicKey = createPublicKey
