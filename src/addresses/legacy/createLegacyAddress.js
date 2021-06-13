const { Crypto: { SHA256: sha256, util: { hexToBytes, bytesToHex } } } = require('cryptojs')
const { crypto: { ripemd160 } } = require('bitcoinjs-lib')
const base58 = require('bs58')
const { createPrivateKey } = require('./createPrivateKey')
const { createPublicKey } = require('./createPublicKey')

/**
 * https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
 */
const createLegacyAddress = (privateKey = null) => {
  // 0. Having a private ECDSA key
  if (privateKey === null) {
    const { privateKey: _privateKey } = createPrivateKey()

    privateKey = _privateKey
  }

  // 1. Take the corresponding public key generated with it, 33 bytes:
  // (1 byte 0x02 (y-coord is even), and 32 bytes corresponding to X coordinate)
  const { publicKey } = createPublicKey(privateKey)

  // 2. Perform SHA-256 hashing on the public key
  const publicKeyBytes = hexToBytes(publicKey)

  const publicKeySHA256Hash = sha256(publicKeyBytes)

  // 3. Perform RIPEMD-160 hashing on the result of SHA-256
  const publicKeySHA256Bytes = hexToBytes(publicKeySHA256Hash)

  const publicKeySHA256HashRIPEMD60BytesBuffer = ripemd160(Buffer.from(publicKeySHA256Bytes))

  const publicKeySHA256HashRIPEMD60Hash = bytesToHex(publicKeySHA256HashRIPEMD60BytesBuffer)

  // 4. Add version byte in front of RIPEMD-160 hash
  // https://en.bitcoin.it/wiki/List_of_address_prefixes
  const version = 0x00 // mainnet

  const publicKeySHA256HashRIPEMD60Bytes = hexToBytes(publicKeySHA256HashRIPEMD60Hash)

  const versionAndpublicKeySHA256HashRIPEMD60Bytes = [version, ...publicKeySHA256HashRIPEMD60Bytes]

  const versionAndpublicKeySHA256HashRIPEMD60Hash = bytesToHex(versionAndpublicKeySHA256HashRIPEMD60Bytes)

  // 5. Perform SHA-256 hash on the extended RIPEMD-160 result
  const versionAndpublicKeySHA256HashRIPEMD60HashSHA256Hash = sha256(versionAndpublicKeySHA256HashRIPEMD60Bytes)

  // 6. Perform SHA-256 hash on the result of the previous SHA-256 hash
  const versionAndpublicKeySHA256HashRIPEMD60HashSHA256HashSHA256Hash = sha256(hexToBytes(versionAndpublicKeySHA256HashRIPEMD60HashSHA256Hash))

  // 7. Take the first 4 bytes of the second SHA-256 hash.
  const checksum = versionAndpublicKeySHA256HashRIPEMD60HashSHA256HashSHA256Hash.substr(0, 8)

  // 8. Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.
  const unencodedAddress = `${versionAndpublicKeySHA256HashRIPEMD60Hash}${checksum}`

  // 9. Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format
  const address = base58.encode(Buffer.from(hexToBytes(unencodedAddress)))

  return {
    privateKey,
    publicKey,
    publicKeySHA256Hash,
    publicKeySHA256HashRIPEMD60Hash,
    versionAndpublicKeySHA256HashRIPEMD60Hash,
    versionAndpublicKeySHA256HashRIPEMD60HashSHA256Hash,
    versionAndpublicKeySHA256HashRIPEMD60HashSHA256HashSHA256Hash,
    checksum,
    unencodedAddress,
    address
  }
}

exports.createLegacyAddress = createLegacyAddress
