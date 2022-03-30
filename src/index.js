const { Oblivious } = require('@nthparty/oblivious')

const { subtle } = require('crypto').webcrypto
const { Common, Mask } = require('./Common')
const { Client } = require('./Client')
const { Server } = require('./Server')

// const sodium = require('libsodium-wrappers-sumo')
const _sodium = require('libsodium-wrappers-sumo')
const { mainModule } = require('process')
let sodium = null

_sodium.ready.then(() => {
    sodium = _sodium
    main()
})


const password = 'password'

const server = new Server('serverId')
const client = new Client('clientId')

const main = async () => {
    const hash = await Common.hash('123')
    const base64Hash = Common.base64Encode(hash)
    console.log(`hash: ${base64Hash}`)

    const mask = new Mask()
    const maskedHash = mask.mask(hash)

    const base64Mask = Common.base64Encode(maskedHash)
    console.log(`masked hash: ${base64Mask}`)

    const unmaskedHash = mask.unmask(maskedHash)
    const base64UnmaskedHash = Common.base64Encode(unmaskedHash)
    console.log(`hash: ${base64UnmaskedHash}`)
}

// console.log(client)

/*
Oblivious.ready.then(function () {
    const p = Oblivious.Point.random();
    console.log(p);  // Point(32) [Uint8Array] [ ... ]
});
/* */
