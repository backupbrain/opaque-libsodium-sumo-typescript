const { Oblivious } = require('@nthparty/oblivious')
const _sodium = require('libsodium-wrappers-sumo')
let sodium = null


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

    static hash (value) {
        const digest = Oblivious.Point.hash(value)
        return digest
    }

    static base64Encode (bytes) {
        const base64Data = Buffer.from(new Uint8Array(bytes)).toString('base64')
        return base64Data
    }

    static base64Decode (str) {
        const buffer = new Buffer.from(str, 'base64')
        return new ArrayBuffer(buffer)
    }
}

exports.Common = Common
exports.Mask = Mask
