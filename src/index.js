// const { createLegacyAddress } = require('./addresses/legacy/createLegacyAddress')
const { createBech32Address } = require('./addresses/bech32/createBech32Address')

const app = () => {
  /**
   * PRIVATE_KEY_HEX: 364F5072F97A57271149E95EAB0A79BD58ECFA31033AF72E8B90F5CCFB8CC51C
   * ADDRESS: 13Nd5KAhGuVpp69XufmvCDBshR6fTRt6c1
   */
  // const legacy = createLegacyAddress()

  const bech32 = createBech32Address()

  console.log({ bech32 })
}

app()
