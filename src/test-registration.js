const _sodium = require('libsodium-wrappers-sumo')
const { Common, Mask } = require('./Common')
const { Client } = require('./Client')
const { Server } = require('./Server')


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

const server = new Server('serverId')
const client = new Client('clientId')

let sodium = null
_sodium.ready.then(() => {
    sodium = _sodium
    sodium.crypto_generichash_batch = sodium_crypto_generichash_batch
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
  const secret = sodium.randombytes_buf(sodium.crypto_core_ed25519_UNIFORMBYTES)
  const challenge = sodium.crypto_core_ed25519_from_uniform(secret)
  const b64Challenge = base64Encode(challenge)
  console.log(` Challenge:              ${b64Challenge}`)
  return challenge
}

const createOprfChallenge = (password) => {
    const passwordBytes = Buffer.from(password)
    const hashedPassword = hashPassword(passwordBytes)
    const mappedPassword = mapHashedPasswordToEllicpicCurve(hashedPassword)
    const randomScalar = createRandomScalar()
    return {
        passwordBytes,
        hashedPassword,
        mappedPassword,
        randomScalar
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
    console.log(` Randomized password:     ${b64RandomizedPassword}`)
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

const main = async () => {
    const common = new Common(sodium)
    // step 1. Generate key pair
    console.log('')
    console.log('=========================================')
    console.log('           CREATING KEY PAIR             ')
    console.log('-----------------------------------------')
    const keyPair = common.generateKeyPair()
    const b64EncodedPublicKey = Common.base64Encode(keyPair.publicKey)
    const b64EncodedPrivateKey = Common.base64Encode(keyPair.privateKey)
    console.log(` Key type:    ${keyPair.keyType}`)
    console.log(` Private key: ${b64EncodedPrivateKey}`)
    console.log(` Public key:  ${b64EncodedPublicKey}`)   
    console.log('=========================================')
    console.log('')

    // step 2: generate OPRF challenge
    // this apparently hashes the password with a unique salt?
    // https://crypto.stackexchange.com/questions/39869/why-do-two-argon-hashes-with-the-same-password-differ
    console.log('=========================================')
    console.log('        CREATING OPRF CHALLENGE          ')
    console.log('-----------------------------------------')
    const oprfChallenge = createClientOprfChallenge()
    const serverChallengeResponse = createOpsrfServerChallengeResponse(
        keyPair.privateKey, // server's private key I think
        oprfChallenge
    )
    const oprfChallenge1 = createOprfChallenge(userPassword)
    const randomizedPassword = createOprfRandomizedPassword(
        oprfChallenge1.passwordBytes,
        serverChallengeResponse,
        keyPair.publicKey,
        oprfChallenge1.randomScalar
    )
    console.log(randomizedPassword)

    const hashSalt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES)
    const hashOpsLimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
    const hashMemLimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
    const key = sodium.crypto_pwhash(32, randomizedPassword, hashSalt, hashOpsLimit, hashMemLimit, sodium.crypto_pwhash_ALG_DEFAULT)
    console.log(key)
    console.log('=========================================')
    console.log('')
    /* */
}




// expected registration process as I understand it to this point
// 1. Client generates private key, public key
// 2. creates a "challenge" from the password
// 
