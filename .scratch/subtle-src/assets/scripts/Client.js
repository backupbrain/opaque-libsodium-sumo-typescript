class Client {

    publicKey = null
    privateKey = null

    constructor () {
        this.publicKey = null
        this.privateKey = null
    }

    async generateKeys () {
        // generate a key from a random point on an ED25519 curve
        // Step 1: Generate a random number *a*. This becomes our private key
        console.log(sodium)
        /*
        const privateKey = sodium.randombytes_buf(
            sodium.crypto_core_ed25519_SCALARBYTES
        )
        // Step 1: Multiply *a* times the base curve point *G*
        // this becomes our public key
        const publicKey = sodium.crypto_scalarmult_ed25519_base(
            privateKey
        )
        this.privateKey = privateKey
        this.publicKey = publicKey
        /* */
    }

    createOprfChallenge () {
        const secret = sodium.randombytes_buf(
            sodium.crypto_core_ed25519_UNIFORMBYTES
        )
        const challenge = sodium.crypto_core_ed25519_from_uniform(secret)
        return challenge
    }

}
