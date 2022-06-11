const _sodium = require('libsodium-wrappers-sumo')
const { sodium_crypto_generichash_batch } = require('./Common')
const { Client } = require('./Client')
const { Server } = require('./Server')
const fetch = require("node-fetch")

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
const registerClientWithServer = async () => {
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

    const serverChallengeResponseJson = await fetch(
        'http://localhost:4000/graphql/', {
            method: 'POST',
            header: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ query: `
                mutation {
                    initializeRegistration(
                        input: {
                        username: "${username}"
                        challenge: "${sodium.to_base64(clientOprfChallenge)}"
                        }
                    ) {
                        serverPublicKey
                        oprfPublicKey
                        oprfChallengeResponse
                    }
                }
            `})
        }
    )
    console.log(serverChallengeResponseJson)
    const serverChallengeResponse = await serverChallengeResponseJson.json()
    const oprfChallengeResponse = sodium.from_base64(serverChallengeResponse.oprfChallengeResponse)
    const serverPublicKey = sodium.from_base64(serverChallengeResponse.serverPublicKey)
    const oprfPublicKey = sodium.from_base64(serverChallengeResponse.oprfPublicKey)
    console.log('2. Server generated OPRF Response for Client')
    const oprfRegistrationEnvelope = client.createOprfRegistrationEnvelope(
        password,
        randomScalar,
        oprfChallengeResponse,
        serverPublicKey,
        oprfPublicKey
    )
    console.log('3. Client created OPRF Registration Envelope')

    // console.log(`cipherText: ${sodium.to_base64(oprfRegistrationEnvelope.cipherText)}`)
    // console.log(`nonce: ${sodium.to_base64(oprfRegistrationEnvelope.nonce)}`)
    // console.log(`client.publicKey: ${sodium.to_base64(client.publicKey)}`)
    const cipherText = sodium.to_base64(oprfRegistrationEnvelope.cipherText)
    const nonce = sodium.to_base64(oprfRegistrationEnvelope.nonce)
    const serverRegisterResponseJson = await fetch(
        'http://localhost:4000/graphql/', {
            method: 'POST',
            header: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ query: `
                mutation {
                    finalizeRegistration(
                        input: {
                        username: "${username}"
                        secret: "${cipherText}"
                        nonce: "${nonce}"
                        clientPublicKey: "${sodium.to_base64(client.publicKey)}"
                        }
                    ) {
                        status
                    }
                }
            `})
        }
    )

    console.log('4. Server stored Client OPRF envelope')
    console.log('---------------------------------------------')
    console.log('   Registration succeeded!')
    console.log('=============================================')
    console.log('')
}

const loginClientToServer = async (username, password) => {
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
    let serverChallengeResponseJson = {}
    try {
        serverChallengeResponse = server.createLoginChallengeResponse(
            username,
            clientOprfChallenge
        )

        const serverChallengeResponseJson = await fetch(
            'http://localhost:4000/graphql/', {
                method: 'POST',
                header: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ query: `
                    mutation {
                        initializeLogin(
                            input: {
                            username: "${username}"
                            challenge: "${sodium.to_base64(clientOprfChallenge)}"
                            }
                        ) {
                            secret
                            nonce
                            oprfPublicKey
                            oprfChallengeResponse
                        }
                    }
                `})
            }
        )
        serverChallengeResponse = await serverChallengeResponse.json()
        console.log(serverChallengeResponse)
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
        const sharedRx = clienSessionKeys.sharedRx
        const sharedTx = clienSessionKeys.sharedTx
        const serverLoginResultJson = await fetch(
            'http://localhost:4000/graphql/', {
                method: 'POST',
                header: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ query: `
                    mutation {
                        initializeLogin(
                            input: {
                                username: "${username}"
                                sharedTx: "${sodium.to_base64(sharedRx)}"
                                sharedRx: "${sodium.to_base64(sharedTx)}"
                            }
                        ) {
                            secret
                            nonce
                            oprfPublicKey
                            oprfChallengeResponse
                        }
                    }
                `})
            }
        )
        const serverLoginResult = await serverLoginResultJson.json()
        console.log(serverLoginResult)
    } catch (error) {
        console.log('3. Server failed to replicate session keys!')
        console.log('---------------------------------------------')
        console.log(`   Login failed: ${error.toString()}`)
        console.log('=============================================')
        console.log('')
        return
    }
    console.log('4. Server creates identical session keys')
    console.log('---------------------------------------------')
    console.log('   Login succeeded!')
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