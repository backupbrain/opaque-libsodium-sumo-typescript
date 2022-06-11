const _sodium = require('libsodium-wrappers-sumo')
const { Common, Mask } = require('./Common')
const { Client } = require('./Client')
const { Server } = require('./Server')

const username = 'abc123'

sodium_crypto_generichash_batch = (arr) => {
    const key = Buffer.alloc(sodium.crypto_generichash_KEYBYTES)
    const state = sodium.crypto_generichash_init(
        key,
        // sodium.crypto_generichash_KEYBYTES,
        sodium.crypto_generichash_BYTES
    )
    arr.forEach(item => {
        sodium.crypto_generichash_update(state, item)
    })
    const combinedHash = sodium.crypto_generichash_final(state, sodium.crypto_generichash_BYTES)
    return combinedHash
}

// const server = new Server('serverId')
// const client = new Client('clientId')
let ss = null

let sodium = null
_sodium.ready.then(() => {
    sodium = _sodium
    sodium.crypto_generichash_batch = sodium_crypto_generichash_batch
    ss = new Server(sodium)
    main()
})

// user creates a password
const userId = 'username'
const userPassword = 'password'

// user generates a public key and private key
// const keyPairs = client.generateKeyPairs()

const base64Encode = (byteArray) => {
    const buffer = new Buffer.from(byteArray)
    const b64DecodedString = buffer.toString('base64')
    return b64DecodedString
}

const getScalarFromUint8Array = (arr) => {
    const dataView = new DataView(arr.buffer)
    const scalar = dataView.getFloat32()
    return scalar
}

const getPointFromUint8Array = (arr) => {
    const x = getScalarFromUint8Array(arr.slice(0, 16))
    const y = getScalarFromUint8Array(arr.slice(16, 32))
    return [ x, y ]
}

const formatPoint = (arr) => {
    const point = getPointFromUint8Array(arr)
    return `(${point[0]}, ${point[1]})`
}

const hashPassword = (passwordBytes) => {
    const hashedPwd = sodium.crypto_generichash(sodium.crypto_generichash_BYTES, passwordBytes)
    const b64HashedPwd = base64Encode(hashedPwd)
    console.log(` Hashed password:      ${b64HashedPwd}`)
    return hashedPwd
}

const mapHashedPasswordToEllicpicCurve = (hashedPassword) => {
    const mappedPassword = sodium.crypto_core_ed25519_from_uniform(hashedPassword)
    const b64MappedPassword = base64Encode(mappedPassword)
    console.log(` Password as ed25590:  ${b64MappedPassword}`)
    return mappedPassword
}

const createRandomScalar = () => {
    const randomScalar = sodium.crypto_core_ed25519_scalar_random()
    const b64RandomScalar = base64Encode(randomScalar)
    console.log(` Random scalar:        ${b64RandomScalar}`)
    return randomScalar
}

const createClientOprfChallenge = () => {
    /*
    const secret = sodium.randombytes_buf(sodium.crypto_core_ed25519_UNIFORMBYTES)
    const challenge = sodium.crypto_core_ed25519_from_uniform(secret)
    const b64Challenge = base64Encode(challenge)
    console.log(` Challenge:            ${b64Challenge}`)
    return challenge
    /* */
    const challenge = sodium.randombytes_buf(sodium.crypto_core_ed25519_SCALARBYTES)
    const b64Challenge = base64Encode(challenge)
    console.log(` Challenge:            ${b64Challenge}`)
    return challenge

}

const createHashedAndMappedPasswords = (password) => {
    const passwordBytes = Buffer.from(password)
    const hashedPassword = hashPassword(passwordBytes)
    const mappedPassword = mapHashedPasswordToEllicpicCurve(hashedPassword)
    return {
        passwordBytes,
        hashedPassword,
        mappedPassword
    }
}

const createOprfRandomizedPassword = (passwordBytes, serverChallengeResponse, publicKey, randomScalar) => {
    // invert randomScalar
    const invertedRandomScalar = sodium.crypto_core_ed25519_scalar_negate(randomScalar)
    // console.log(`public key`)
    // console.log(parseInt(publicKey.toString('hex')))
    // take publicKey ^ inversedRandomScalar
    const exponentiatedPublicKey = sodium.crypto_scalarmult_ed25519_noclamp(
        invertedRandomScalar,
        publicKey
    )
    const challengeResponseResult = sodium.crypto_core_ed25519_add(serverChallengeResponse, exponentiatedPublicKey)
    // hash the password + publicKey + challenge/response result
    const randomizedPasssword = sodium.crypto_generichash_batch([
        passwordBytes,
        publicKey,
        challengeResponseResult
    ])
    const b64RandomizedPassword = base64Encode(randomizedPasssword)
    console.log(` Randomized password:  ${b64RandomizedPassword}`)
    return randomizedPasssword
}

const createOpsrfServerChallengeResponse = (secretKey, challenge) => {
    const requiredChallengeLength = sodium.crypto_scalarmult_ed25519_BYTES
    if (challenge.length != requiredChallengeLength) {
        throw Error(`OPRF challenge is an invalid length. Needs ${requiredChallengeLength} bytes`)
    }
    // this value is called beta, b = a ^ k
    const beta = sodium.crypto_scalarmult_ed25519(secretKey, challenge)
    const b64Beta = base64Encode(beta)
    console.log(` Server challenge response: ${b64Beta}`)
    return beta
}

const applyArgon2ToRandomizedPassword = (randomizedPassword) => {
    // apply argon2 to rwd using the hardening params sent from the server
    const hashSalt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES)
    const hashOpsLimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
    const hashMemLimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
    const key = sodium.crypto_pwhash(32, randomizedPassword, hashSalt, hashOpsLimit, hashMemLimit, sodium.crypto_pwhash_ALG_DEFAULT)
    const b64Key = base64Encode(key)
    console.log(` Argon2 key:           ${b64Key}`)
    return key
}

const generateNonce = () => {
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    const b64Nonce = base64Encode(nonce)
    console.log(` Nonce:                ${b64Nonce}`)
    return nonce
}


const createOprfEnvelope = (userPrivateKey, userPublicKey, serverPublicKey, argon2RandomizedPassword) => {
    // nonce is zero?!
    const nonce = generateNonce()
    const message = Buffer.from(JSON.stringify({
      userPublicKey: userPublicKey,
      userSecretKey: userPrivateKey,
      serverPublicKey: serverPublicKey
    }))
    const cipherText = sodium.crypto_secretbox_easy(message, nonce, argon2RandomizedPassword)
    const b64ipherText = base64Encode(cipherText)
    console.log(` cipherText:           ${b64ipherText}`)
    const envelope = { cipherText, nonce }
    return envelope
}

const client = {}
const server = { clients: {} }

const main = async () => {
    const common = new Common(sodium)
    // step 1. Generate key pair
    console.log('')
    console.log('=========================================')
    console.log('           CREATING KEY PAIR             ')
    console.log('-----------------------------------------')
    ss.createKeyPair()
    const keyPair = ss.keyPair
    // const keyPair = common.generateKeyPair()
    console.log(` Key type:    ${keyPair.keyType}`)
    console.log(` Private key: ${base64Encode(keyPair.privateKey)}`)
    console.log(` Public key:  ${base64Encode(keyPair.publicKey)}`)   
    console.log('=========================================')
    console.log('')

    // server's keyPair
    ss.createKeyPair()
    const serverKeyPair = ss.keyPair

    // step 2: generate OPRF challenge
    // this apparently hashes the password with a unique salt?
    // https://crypto.stackexchange.com/questions/39869/why-do-two-argon-hashes-with-the-same-password-differ
    console.log('=========================================')
    console.log('        CREATING OPRF CHALLENGE          ')
    console.log('-----------------------------------------')
    const randomScalar = createRandomScalar()
    const clientOprfChallenge = createClientOprfChallenge()
    const serverChallengeResponse = createOpsrfServerChallengeResponse(
        serverKeyPair.privateKey,
        clientOprfChallenge
    )
    const passwordData = createHashedAndMappedPasswords(userPassword)
    const randomizedPassword = createOprfRandomizedPassword(
        passwordData.passwordBytes,
        serverChallengeResponse,
        keyPair.publicKey,
        randomScalar
    )
    const argon2RandomizedPassword = applyArgon2ToRandomizedPassword(randomizedPassword)
    const envelope = createOprfEnvelope(
        keyPair.privateKey,
        keyPair.publicKey,
        serverKeyPair.publicKey,
        argon2RandomizedPassword
    )

    // store data
    client.publicKey = keyPair.publicKey
    client.privateKey = keyPair.privateKey
    client.serverPublicKey = serverKeyPair.publicKey
    client.serverChallengeResponse = serverChallengeResponse
    server.clients[username] = {
        secret: serverChallengeResponse,
        nonce: envelope.nonce,
        cipherText: envelope.cipherText
    }
    server.publicKey = serverKeyPair.publicKey
    server.privateKey = serverKeyPair.privateKey

    console.log('=========================================')
    console.log('')
    console.log('User creates "envelope" containing nonce and cipherText')
    console.log('User should send publicKey and envelope.')
    console.log('')
    console.log('Server can store this data plus it\'s oprf secret, linked to username')
    console.log('')
    console.log('=========================================')
    console.log('')
    console.log('User stores:')
    console.log('{')
    console.log(`    privateKey: "${base64Encode(keyPair.privateKey)}",`)
    console.log(`    publicKey: "${base64Encode(keyPair.publicKey)}",`)
    console.log(`    serverPublicKey: "${base64Encode(serverKeyPair.publicKey)}",`)
    console.log(`    secret: "${base64Encode(serverChallengeResponse)}",`)
    console.log('}')
    console.log('')
    console.log('-----------------------------------------')
    console.log('')
    console.log('Server stores:')
    console.log('{')
    console.log(`    username: "${username}",`)
    console.log(`    secret: "${base64Encode(serverChallengeResponse)}",`)
    console.log(`    nonce: "${base64Encode(envelope.nonce)}",`)
    console.log(`    ciherText: "${base64Encode(envelope.cipherText)}",`)
    console.log('}')
    console.log('')
    /* */

    login()
}

const createLoginChallenge = (password) => {
    const passwordData = createHashedAndMappedPasswords(password)
    const randomScalar = createRandomScalar()
    // blind password to safely send to server (challenge = H'(pwd) * g^r)
    const randomPointOnCurve = sodium.crypto_scalarmult_ed25519_base_noclamp(randomScalar)
    const challenge = sodium.crypto_core_ed25519_add(
        passwordData.mappedPassword,
        randomPointOnCurve
    )
    console.log(`challenge: ${formatPoint(challenge)}`)
    const b64Challenge = base64Encode(challenge)
    console.log(` Login challenge:      ${b64Challenge}`)
    return challenge
}

const getServerLoginResponse = (username, serverPrivateKey, clientLoginChallenge) => {
    if (clientLoginChallenge.length !== sodium.crypto_scalarmult_ed25519_BYTES) {
        throw Error('challenge is an invalid length')
    }
    // multiply the server private key (scalar) by the client login challenge (point)
    const beta = sodium.crypto_scalarmult_ed25519(serverPrivateKey, clientLoginChallenge)
    // The server retrieves some stuff it has stored about the client
    const loginResponse = {
        envelope: {
            nonce: server.clients[username].nonce,
            secret: server.clients[username].secret
        },
        response: beta,
        // hashOpsLimit: sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
        // hashMemLimit: sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        // hashSalt: Buffer.alloc(sodium.crypto_pwhash_SALTBYTES)
    }
    return loginResponse
}

const openEnvelope = (cipherText, nonce, argon2DerivedKey) => {
    const openedEnvelope = sodium.crypto_secretbox_open_easy(
        cipherText,
        nonce,
        argon2DerivedKey
    )
    if (!openedEnvelope) {
        throw Error('Couldn\'t open envelope')
    }
    return JSON.parse(openedEnvelope.toString())
}

const loadUserSession = (openedEnvelope) => {
    const userSession = sodium.crypto_kx_client_session_keys(
        sodium.crypto_kx_SESSIONKEYBYTES,
        null,
        openedEnvelope.userPublicKey,
        envelopenedEnvelopeope.userSecretKey,
        openedEnvelope.serverPublicKey,
        'uint8array'
    )
    return userSession
}


const login = () => {
    // start login
    const randomScalar = createRandomScalar()
    const loginChallenge = createLoginChallenge(userPassword)

    // server does something
    const serverLoginResponse = getServerLoginResponse(
        username,
        server.privateKey,
        loginChallenge
    )

    console.log(`serverLoginResponse`)
    console.log(serverLoginResponse.response)

    const randomizedPassword = createOprfRandomizedPassword(
        Buffer.from(userPassword),
        serverLoginResponse.response,
        client.publicKey,
        randomScalar
    )

    const argon2DerivedKey = applyArgon2ToRandomizedPassword(randomizedPassword)
    const openedEnvelope = openEnvelope(
        serverLoginResponse.envelope.secret, // secret = cipherText
        serverLoginResponse.envelope.nonce,
        argon2DerivedKey
    )
    const userSession = loadUserSession(openedEnvelope)
    // what do we do with this user session?
}



// expected registration process as I understand it to this point
// 1. Client generates private key, public key
// 2. creates a "challenge" from the password
// 
