const { Common } = require('./Common')
let sodium = null

class Server {

    sodium = null

    get publicKey () { return this.keyPair.publicKey }
    get privateKey () { return this.keyPair.privateKey }
    get keytype () { return this.keyPair.keyType }

    constructor (sodium) {
        this.sodium = sodium
        this.common = new Common(sodium)
        this.registeredClients = {}
    }

    createKeyPair () {
        const keyPair = this.generateKeyPair()
        this.keyPair = keyPair
    }

    generateKeyPair () {
        const privateKey = this.sodium.randombytes_buf(
            this.sodium.crypto_core_ed25519_SCALARBYTES
        )
        const publicKey = this.sodium.crypto_scalarmult_ed25519_base(
            privateKey
        )
        const keyPair = {
            publicKey: publicKey,
            privateKey: privateKey,
            keyType: 'ed25519'
        }
        return keyPair
    }

    _createOprfChallengeResponse (clientOprfChallenge, oprfPrivateKey) {
        const requiredChallengeLength = this.sodium.crypto_scalarmult_ed25519_BYTES
        if (clientOprfChallenge.length != requiredChallengeLength) {
            throw Error(`OPRF challenge is an invalid length. Needs ${requiredChallengeLength} bytes`)
        }
        // this value is called beta, b = a ^ k
        const beta = this.sodium.crypto_scalarmult_ed25519(
            oprfPrivateKey,
            clientOprfChallenge
        )
        return beta
    }

    createRegistrationResponse (username, clientOprfChallenge) {
        // Generate keys just for this auth flow
        const oprfKeyPair = this.generateKeyPair()
        // Generate challeng response
        const oprfChallengeResponse = this._createOprfChallengeResponse(
            clientOprfChallenge,
            oprfKeyPair.privateKey
        )
        // Store user data
        this.registeredClients[username] = {
            username: username,
            serverPublicKey: this.publicKey,
            oprfPrivateKey: oprfKeyPair.privateKey,
            oprfPublicKey: oprfKeyPair.publicKey,
            clientOprfChallenge: clientOprfChallenge
        }
        // return data to client
        const response = {
            serverPublicKey: this.publicKey,
            oprfPublicKey: oprfKeyPair.publicKey,
            oprfChallengeResponse: oprfChallengeResponse
        }
        return response
    }

    storeClientOprfRegistrationEnvelope (username, oprfRegistrationEnvelope, clientPublicKey) {
        if (!this.registeredClients[username]) {
            throw Error('Username not registered yet')
        }
        this.registeredClients[username] = {
            ...this.registeredClients[username],
            cipherText: oprfRegistrationEnvelope.cipherText,
            nonce: oprfRegistrationEnvelope.nonce,
            clientPublicKey: clientPublicKey
        }
    }

    createLoginChallengeResponse (username, clientOprfChallenge) {
        if (!this.registeredClients[username]) {
            throw Error(`User '${username}' is not registered`)
        }
        const userData = this.registeredClients[username]
        const oprfChallengeResponse = this._createOprfChallengeResponse(
            clientOprfChallenge,
            userData.oprfPrivateKey
        )
        const challengeResponseData = {
            envelope: { cipherText: userData.cipherText, nonce: userData.nonce },
            oprfPublicKey: userData.oprfPublicKey,
            oprfChallengeResponse: oprfChallengeResponse
        }
        return challengeResponseData
    }

    didLoginSucceed (username, userSession) {
        if (!this.registeredClients[username]) {
            throw Error('Username not registered yet')
        }
        const userData = this.registeredClients[username]
        const serverSession = this.sodium.crypto_kx_server_session_keys(
            this.publicKey,
            this.privateKey,
            userData.clientPublicKey
        )
        const isAuthorized = (JSON.stringify(userSession) === JSON.stringify(serverSession))
        /*
        const isAuthorized = this.sodium.sodium_memcmp(
            userSession,
            serverSession
        )
        /* */
        return isAuthorized
    }
}

exports.Server = Server
