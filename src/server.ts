import { SessionKeys } from "./client";
import * as common from "./common";

export let publicKey: Uint8Array | undefined = undefined;
export let privateKey: Uint8Array | undefined = undefined;
export let keyType: string | undefined = undefined;

type RegistrationData = {
  username: string;
  serverPublicKey: Uint8Array;
  oprfPrivateKey: Uint8Array;
  oprfPublicKey: Uint8Array;
  clientOprfChallenge: Uint8Array;
  cipherText: Uint8Array | undefined;
  nonce: Uint8Array | undefined;
  clientPublicKey: Uint8Array | undefined;
};
const registeredClientsDatabase: { [username: string]: RegistrationData } = {};

export type OprfEnvelope = {
  cipherText: Uint8Array;
  nonce: Uint8Array;
};
export type LoginChallengeResponse = {
  envelope: OprfEnvelope;
  oprfPublicKey: Uint8Array;
  oprfChallengeResponse: Uint8Array;
};
export type RegistrationResponse = {
  serverPublicKey: Uint8Array;
  oprfPublicKey: Uint8Array;
  oprfChallengeResponse: Uint8Array;
};
export type AsymmetricKey = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  keyType: string;
};

/**
 * Generate a public key and private key for the client
 * @returns Object containing the public key and private key
 */
export const createKeyPair = async () => {
  const keyPair = await common.generateKeyPair();
  publicKey = keyPair.publicKey;
  privateKey = keyPair.privateKey;
  keyType = keyPair.keyType;
};

export const generateKeyPair = (): AsymmetricKey => {
  const privateKey = common.sodium.randombytes_buf(
    common.sodium.crypto_core_ed25519_SCALARBYTES
  );
  const publicKey = common.sodium.crypto_scalarmult_ed25519_base(privateKey);
  return {
    privateKey,
    publicKey,
    keyType: "ed25519",
  };
};

const _createOprfChallengeResponse = (
  clientOprfChallenge: Uint8Array,
  oprfPrivateKey: Uint8Array
) => {
  const requiredChallengeLength = common.sodium.crypto_scalarmult_ed25519_BYTES;
  if (clientOprfChallenge.length != requiredChallengeLength) {
    throw Error(
      `OPRF challenge is an invalid length. Needs ${requiredChallengeLength} bytes`
    );
  }
  // this value is called beta, b = a ^ k
  const beta = common.sodium.crypto_scalarmult_ed25519(
    oprfPrivateKey,
    clientOprfChallenge
  );
  return beta;
};

export const createRegistrationResponse = (
  username: string,
  clientOprfChallenge: Uint8Array
): RegistrationResponse => {
  // Generate keys just for this auth flow
  const oprfKeyPair = generateKeyPair();
  // Generate challeng response
  const oprfChallengeResponse = _createOprfChallengeResponse(
    clientOprfChallenge,
    oprfKeyPair.privateKey
  );
  // Store user data
  registeredClientsDatabase[username] = {
    username: username,
    serverPublicKey: publicKey!,
    oprfPrivateKey: oprfKeyPair.privateKey,
    oprfPublicKey: oprfKeyPair.publicKey,
    clientOprfChallenge: clientOprfChallenge,
    cipherText: undefined,
    nonce: undefined,
    clientPublicKey: undefined,
  };
  // return data to client
  const response: RegistrationResponse = {
    serverPublicKey: publicKey!,
    oprfPublicKey: oprfKeyPair.publicKey,
    oprfChallengeResponse: oprfChallengeResponse,
  };
  return response;
};

export const storeClientOprfRegistrationEnvelope = (
  username: string,
  oprfRegistrationEnvelope: OprfEnvelope,
  clientPublicKey: Uint8Array
) => {
  if (!registeredClientsDatabase[username]) {
    throw Error("Username not registered yet");
  }
  registeredClientsDatabase[username] = {
    ...registeredClientsDatabase[username],
    cipherText: oprfRegistrationEnvelope.cipherText,
    nonce: oprfRegistrationEnvelope.nonce,
    clientPublicKey: clientPublicKey,
  };
};

export const createLoginChallengeResponse = (
  username: string,
  clientOprfChallenge: Uint8Array
): LoginChallengeResponse => {
  if (!registeredClientsDatabase[username]) {
    throw Error(`User '${username}' is not registered`);
  }
  const userData = registeredClientsDatabase[username];
  const oprfChallengeResponse = _createOprfChallengeResponse(
    clientOprfChallenge,
    userData.oprfPrivateKey
  );
  const challengeResponseData: LoginChallengeResponse = {
    envelope: { cipherText: userData.cipherText!, nonce: userData.nonce! },
    oprfPublicKey: userData.oprfPublicKey,
    oprfChallengeResponse: oprfChallengeResponse,
  };
  return challengeResponseData;
};

export const didLoginSucceed = (username: string, userSession: SessionKeys) => {
  if (!registeredClientsDatabase[username]) {
    throw Error("Username not registered yet");
  }
  const userData = registeredClientsDatabase[username];
  const serverSession = common.sodium.crypto_kx_server_session_keys(
    publicKey,
    privateKey,
    userData.clientPublicKey
  );
  const isAuthorized =
    JSON.stringify(userSession) === JSON.stringify(serverSession);
  return isAuthorized;
};
