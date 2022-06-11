# OPAQUE-KE Tests in Javascript and Libsodium

OPAQUE is a way for users to type their username and password to log into a website, but then log in without sending their password across the Internet.

It uses a key-derivation function to facilitate a secure key-exchange between the client and server.

## How it works

### Registration

When you register, the server generates and sends a public key to the client. This acts as a pseudo-random number.

On the client side, the user's password is combined with the public key and the generated public key to derive an encryption private key.

This private key then encrypts some session data that will become important for login. The encrypted data is sent to the server for safe keeping.

The server generates information required to set up it's half of a key exchange that will be used to talk to create a secure communication channel with the client.

### Login

When you login, the server sends the same public key to the client.  The client uses this and the password to generate the encryption private key.

The server sends the encrypted data from the registration and the user decrypts it using the derived private key.

The descrypted packet contains the other half of the session keys used to create a secure channel with the server.

## Setup

Install modules

```console
$ yarn
```

## Running 

```console
$ yarn run demo
```

This runs the `src/test-registration-oo.js` script, which runs a series of registration and login tests, including:

* Register (OPAQUE)
* Successful login (key exchange)
* Unauthorized login attempt



