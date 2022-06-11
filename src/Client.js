const { Common } = require('./Common')

class Client {

    sodium = null

    get publicKey () { return this.keyPair.publicKey }
    get privateKey () { return this.keyPair.privateKey }
    get keytype () { return this.keyPair.keyType }

    serverChallengeResponse = null
    serverPublicKey = null

    constructor (sodium) {
        this.sodium = sodium
        this.common = new Common(sodium)
        this.keyPair = null
        this.serverChallengeResponse = null
        this.serverPublicKey = null
    }

    createKeyPair () {
        const keyPair = this.common.generateKeyPair()
        this.keyPair = keyPair
    }

    createBlindPassword (password) {
        const blindPassword = Buffer.from(password, 'utf8')
        return blindPassword
    }

    createRegistrationRequest (password, key) {
        const blindPassword = this.createBlindPassword(password)
        const output = {
            username: this.username,
            blindPassword: blindPassword
        }
        return output
    }

    /**
     * Hash a password using a generic hash
     * 
     * @params {Bytes[]} passwordBytes
     * @returns Bytes[] hashed password
     */
    _hashPassword (passwordBytes) {
        const hashLength = this.sodium.crypto_generichash_BYTES
        const hashedPassword = this.sodium.crypto_generichash(
            hashLength,
            passwordBytes
        )
        return hashedPassword
    }

    /**
     * Treat the hashed password as a vector value and map it to a valid point on an elliptic curve
     * 
     * @param {Bytes[]} hashedPassword
     * @returns Bytes[]
     */
    _mapHashedPasswordToEllicpicCurve (hashedPassword) {
        const mappedPassword = this.sodium.crypto_core_ed25519_from_uniform(
            hashedPassword
        )
        return mappedPassword
    }

    /**
     * Generate a random scalar that's valid for an elliptic curve
     * 
     * @returns Bytes[] representing a scalar
     */
    _createRandomScalar () {
        const randomScalar = this.sodium.crypto_core_ed25519_scalar_random()
        return randomScalar
    }

    /**
     * 
     * @param {string} password 
     * @returns 
     */
    createOprfChallenge (password) {
        const mappedPassword = this._getCurveMappedPassword(password)
        const randomScalar = this._createRandomScalar()
        const randomPointOnCurve = this.sodium.crypto_scalarmult_ed25519_base_noclamp(randomScalar)
        const oprfChallenge = this.sodium.crypto_core_ed25519_add(mappedPassword, randomPointOnCurve)
        return { oprfChallenge, randomScalar } 
    }

    /**
     * Create the client's OPRF challenge
     * 
     * @param {string} password 
     * @returns Object containing password as bytes[], hashed password, password mapped to curve, and a random number
     */
    _getCurveMappedPassword (password) {
        const passwordBytes = Buffer.from(password)
        const hashedPassword = this._hashPassword(passwordBytes)
        const mappedPassword = this._mapHashedPasswordToEllicpicCurve(hashedPassword)
        return mappedPassword
    }
    
    /**
     * Create a randomized password by hashing password, publicKey, and challenge response
     * 
     * @param {string} password
     * @param {bytes[]} randomScalar
     * @returns {bytes[]] 
     */
    _createRandomizedPassword (password, randomScalar, oprfPublicKey) {
        const passwordBytes = Buffer.from(password)
        const mappedPassword = this._getCurveMappedPassword(password)
        // invert the random scalar
        const invertedRandomScalar = this.sodium.crypto_core_ed25519_scalar_negate(randomScalar)
        // attempt to take publicKey ^ invertedRandomScalar
        const exponentiatedPublicKey = this.sodium.crypto_scalarmult_ed25519_noclamp(
            invertedRandomScalar,
            oprfPublicKey
        )
        const challengeResponseResult = this.sodium.crypto_core_ed25519_add(mappedPassword, exponentiatedPublicKey)
        const randomizedPassword = this.sodium.crypto_generichash_batch([
            passwordBytes,
            oprfPublicKey,
            challengeResponseResult
        ])
        return randomizedPassword
    }

    _createRandomizedPassword1 (password, serverChallengeResponse, oprfPublicKey, randomScalar) {
        const passwordBytes = Buffer.from(password)
        const invertedRandomScalar = this.sodium.crypto_core_ed25519_scalar_negate(randomScalar)
        const exponentiatedPublicKey = this.sodium.crypto_scalarmult_ed25519_noclamp(
            invertedRandomScalar,
            oprfPublicKey
        )
        const challengeResponseResult = this.sodium.crypto_core_ed25519_add(serverChallengeResponse, exponentiatedPublicKey)
        const randomizedPassword = this.sodium.crypto_generichash_batch([
            passwordBytes,
            oprfPublicKey,
            challengeResponseResult
        ])
        return randomizedPassword
    }

    /**
     * Create an argon2 secure hash of the randomized password generated by `._createRandomizedPassword()`
     * 
     * @param {bytes[]} randomizedPassword
     * @return {bytes[]} hashed randomized password
     */
    _createArgon2RandomizedPaswordHash (randomizedPassword) {
        // apply argon2 to rwd using the hardening params sent from the server
        const hashSalt = Buffer.alloc(this.sodium.crypto_pwhash_SALTBYTES)
        const hashOpsLimit = this.sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
        const hashMemLimit = this.sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
        const argon2HashedRandomizedPassword = this.sodium.crypto_pwhash(
            32, // TODO: replace with constant value
            randomizedPassword,
            hashSalt,
            hashOpsLimit,
            hashMemLimit,
            // TODO: check if this line needs to be crypto_pwhash_ALG_ARGON2I13
            // or possibly crypto_pwhash_ALG_ARGON2ID13
            this.sodium.crypto_pwhash_ALG_DEFAULT
        )
        return argon2HashedRandomizedPassword
    }

    /**
     * Create the registration envelope, which includes
     * - a nonce
     * - a ciphertext derived from the password and the server public key
     * 
     * @param {string} password the user's password
     * @param {bytes[]} randomScalar a random scalar number
     * @param {bytes[]} serverPublicKey the server's public key
     * @param {bytes[]} oprfPublicKey the public key for this authentication
     * @return {object} containing `.cipherText` an encrypted message containing 
     *                  user public key, user private key, and server public key
     */
    createOprfRegistrationEnvelope (password, randomScalar, serverChallengeResponse, serverPublicKey, oprfPublicKey) {
        // const randomScalar = this._createRandomScalar()
        const randomizedPassword = this._createRandomizedPassword1(
            password,
            serverChallengeResponse,
            oprfPublicKey,
            randomScalar
        )
        /*
        const randomizedPassword = this._createRandomizedPassword1(
            password,
            randomScalar,
            oprfPublicKey
        )
        /* */
        const argon2DerivedKey = this._createArgon2RandomizedPaswordHash(randomizedPassword)
        const nonce = this.common.generateNonce()
        const messageData = {
            userPublicKey: Common.base64Encode(this.publicKey),
            userPrivateKey:  Common.base64Encode(this.privateKey),
            serverPublicKey:  Common.base64Encode(serverPublicKey)
        }
        const messageBytes = Buffer.from(JSON.stringify(messageData))
        const cipherText = this.sodium.crypto_secretbox_easy(
            messageBytes,
            nonce,
            argon2DerivedKey
        )
        const oprfRegistrationEnvelope = {
            cipherText: cipherText,
            nonce: nonce
        }
        return oprfRegistrationEnvelope
    }

    /**
     * Decrypt the cipherText using the nonce and argon2 derived key
     * 
     * @param {bytes[]} cipherText the encrypted cypher text
     *                  containing user public key, user secret key, 
     *                  and server public key
     * @param {bytes[]} nonce a random scalar
     * @param {bytes[]} argon2DerivedKey the key derived from the 
     *                  randomized password
     * @returns {object} object containing user public key, user secret key
     *                   and server public key
     */
    _openEnvelope (cipherText, nonce, argon2DerivedKey) {
        // Note: expect that this will throw an error if it can't be decrypted
        const messageBytes = this.sodium.crypto_secretbox_open_easy(
            cipherText,
            nonce,
            argon2DerivedKey
        )
        // const messageString = new TextDecoder('utf-8').decode(messageBytes)
        const messageString = Buffer.from(messageBytes.buffer).toString("utf-8");
        const messageData = JSON.parse(messageString)
        const userPublicKey = Common.base64Decode(messageData.userPublicKey)
        const userPrivateKey = Common.base64Decode(messageData.userPrivateKey)
        const serverPublicKey = Common.base64Decode(messageData.serverPublicKey)
        const clientSessionKeys = this.sodium.crypto_kx_client_session_keys(
            userPublicKey,
            userPrivateKey,
            serverPublicKey
        )
        return clientSessionKeys
    }

    createUserSession (password, cipherText, nonce, oprfPublicKey, randomScalar, serverChallengeResponse) {
        const randomizedPassword = this._createRandomizedPassword1(password, serverChallengeResponse, oprfPublicKey, randomScalar)
        const argon2DerivedKey = this._createArgon2RandomizedPaswordHash(randomizedPassword)
        let clientSessionKeys = null
        console.log({cipherText})
        try {
            clientSessionKeys = this._openEnvelope(
                cipherText,
                nonce,
                argon2DerivedKey
            )
        } catch (error) {
            throw Error('Invalid password')
        }
        return clientSessionKeys
    }

}

exports.Client = Client
