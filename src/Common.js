const { Oblivious } = require('@nthparty/oblivious')
const _sodium = require('libsodium-wrappers-sumo')


class Mask {
    constructor (byteString) {
        let inboundByteString = null
        if (byteString !== undefined & byteString !== null) {
            inboundByteString = byteString
        }
        const scalar = new Oblivious.Scalar(inboundByteString)
        this.scalar = scalar
    }

    mask (value) {
        const maskedValue = Oblivious.Sodium.mul(this.scalar, value)
        return maskedValue
    }

    unmask (value) {
        const maskedValue = Oblivious.Sodium.mul(this.scalar.invert(), value)
        return maskedValue
    }

    createKeyPair () {
        Oblivious.crypto_kx_keypair()
    }

}

class Common {
    sodium = null

    static get HASH_ALGORITHM () { return 'SHA-256' }

    constructor (sodium) {
        this.sodium = sodium
    }

    generateKeyPair () {
        return this.sodium.crypto_kx_keypair()
    }

    generateNonce () {
        const nonce = this.sodium.randombytes_buf(this.sodium.crypto_secretbox_NONCEBYTES)
        return nonce
    }

    hash (value) {

    }

    static hash (value) {
        const digest = Oblivious.Point.hash(value)
        return digest
    }

    static base64Encode (bytes) {
        const base64Data = Buffer.from(new Uint8Array(bytes)).toString('base64')
        return base64Data
    }

    static base64Decode (str) {
        const bytes = new Buffer.from(str, 'base64')
        const arr = new Uint8Array(bytes)
        return bytes
    }
}

// sodium.crypto_generichash_batch = sodium_crypto_generichash_batch
function sodium_crypto_generichash_batch (arr) {
    const key = Buffer.alloc(this.crypto_generichash_KEYBYTES)
    const state = this.crypto_generichash_init(
        key,
        this.crypto_generichash_BYTES
    )
    arr.forEach(item => {
        this.crypto_generichash_update(state, item)
    })
    const combinedHash = this.crypto_generichash_final(state, this.crypto_generichash_BYTES)
    return combinedHash
}

exports.Common = Common
exports.Mask = Mask
exports.sodium_crypto_generichash_batch = sodium_crypto_generichash_batch
