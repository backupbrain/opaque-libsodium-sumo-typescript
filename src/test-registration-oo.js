const _sodium = require('libsodium-wrappers-sumo')
const { sodium_crypto_generichash_batch } = require('./Common')
const { Client } = require('./Client')
const { Server } = require('./Server')

const username = 'abc123'
const password = 'password'

let server = null
let client = null

/**
 * Start running the program once the sodium library is loaded
 */
let sodium = null
_sodium.ready.then(() => {
    sodium = _sodium
    // extend sodium functionality to enable bulk hashing
    sodium.crypto_generichash_batch = sodium_crypto_generichash_batch
    main()
})

/**
 * Initialize the client and server
 */
const initializeEnvironment = () => {
    server = new Server(sodium)
    client = new Client(sodium)
    client.createKeyPair()
    server.createKeyPair()
}

/**
 * Have the client register with the server
 */
const registerClientWithServer = () => {
    console.log('')
    console.log('=============================================')
    console.log('Registering client with server')
    console.log('---------------------------------------------')
    console.log(`username '${username}', password: '${password}'`)
    console.log('---------------------------------------------')
    const clientOprfChallengeData = client.createOprfChallenge(password)
    const clientOprfChallenge = clientOprfChallengeData.oprfChallenge
    const randomScalar = clientOprfChallengeData.randomScalar
    console.log('1. Client generated OPRF challenge for Server')

    console.log(`challenge: ${sodium.to_base64(clientOprfChallenge)}`)

    const serverChallengeResponse = server.createRegistrationResponse(
        username,
        clientOprfChallenge
    )
    console.log('2. Server generated OPRF Response for Client')
    const oprfRegistrationEnvelope = client.createOprfRegistrationEnvelope(
        password,
        randomScalar,
        serverChallengeResponse.oprfChallengeResponse,
        serverChallengeResponse.serverPublicKey,
        serverChallengeResponse.oprfPublicKey
    )
    console.log('3. Client created OPRF Registration Envelope')

    // console.log(`cipherText: ${sodium.to_base64(oprfRegistrationEnvelope.cipherText)}`)
    // console.log(`nonce: ${sodium.to_base64(oprfRegistrationEnvelope.nonce)}`)
    // console.log(`client.publicKey: ${sodium.to_base64(client.publicKey)}`)
    server.storeClientOprfRegistrationEnvelope(
        username,
        oprfRegistrationEnvelope,
        client.publicKey
    )
    console.log('4. Server stored Client OPRF envelope')
    console.log('---------------------------------------------')
    console.log('   Registration succeeded!')
    console.log('=============================================')
    console.log('')
}

const loginClientToServer = (username, password) => {
    console.log('')
    console.log('=============================================')
    console.log('Logging in client to server')
    console.log('---------------------------------------------')
    console.log(`username '${username}', password: '${password}'`)
    console.log('---------------------------------------------')
    const clientOprfChallengeData = client.createOprfChallenge(password)
    const clientOprfChallenge = clientOprfChallengeData.oprfChallenge
    const randomScalar = clientOprfChallengeData.randomScalar
    console.log('1. Client generated OPRF challenge for Server')

    console.log(`challenge: ${sodium.to_base64(clientOprfChallenge)}`)
    try {
        serverChallengeResponse = server.createLoginChallengeResponse(
            username,
            clientOprfChallenge
        )
    } catch (error) {
        console.log('2. Server failed to generate for Client!')
        console.log('---------------------------------------------')
        console.log(`   Login failed: ${error.toString()}`)
        console.log('=============================================')
        console.log('')
        return
    }
    console.log('2. Server generated OPRF Response for Client')

    let clienSessionKeys = null
    try {
        clienSessionKeys = client.createUserSession(
            password,
            serverChallengeResponse.envelope.cipherText,
            serverChallengeResponse.envelope.nonce,
            serverChallengeResponse.oprfPublicKey,
            randomScalar,
            serverChallengeResponse.oprfChallengeResponse
        )
        console.log(clienSessionKeys)
        console.log(`sharedRx: ${sodium.to_base64(clienSessionKeys.sharedRx)}`)
        console.log(`sharedTx: ${sodium.to_base64(clienSessionKeys.sharedTx)}`)
    } catch (error) {
        console.log('3. Client failed to create shared session keys!')
        console.log('---------------------------------------------')
        console.log(`   Login failed: ${error.toString()}`)
        console.log('=============================================')
        console.log('')
        return
    }
    console.log('3. Client creates shared session keys')

    let isAuthorized = false
    try {
        isAuthorized = server.didLoginSucceed(username, clienSessionKeys)
    } catch (error) {
        console.log('3. Server failed to replicate session keys!')
        console.log('---------------------------------------------')
        console.log(`   Login failed: ${error.toString()}`)
        console.log('=============================================')
        console.log('')
        return
    }
    if (!isAuthorized) {
        console.log('3. Server failed to replicate session keys!')
        console.log('---------------------------------------------')
        console.log('   Login failed: isAuthorized = false ')
        console.log('=============================================')
        console.log('')
        return
    }
    console.log('4. Server creates identical session keys')
    console.log('---------------------------------------------')
    console.log('   Login succeeded! isAuthorized = true')
    console.log('=============================================')
    console.log('')
}

const main = async () => {
    initializeEnvironment()
    registerClientWithServer()
    loginClientToServer(username, password)
    loginClientToServer(username, 'badpassword')
    loginClientToServer('badusername', 'badpass')
}