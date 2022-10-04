import { expect, test } from "@jest/globals";
import * as client from "../src/client";
import * as common from "../src/common";
import * as server from "../src/server";
let sodium: any = undefined;

const username = "abc123";
const password = "password";

const login = (username: string, password: string) => {
  const clientOprfChallengeData = client.createOprfChallenge(password);
  const clientOprfChallenge = clientOprfChallengeData.oprfChallenge;
  const randomScalar = clientOprfChallengeData.randomScalar;
  expect(clientOprfChallenge.length).toBe(32);
  expect(randomScalar.length).toBe(32);
  // 1. Client generated OPRF challenge for Server
  const serverChallengeResponse = server.createLoginChallengeResponse(
    username,
    clientOprfChallenge
  );
  expect(serverChallengeResponse.oprfChallengeResponse.length).toBe(32);
  expect(serverChallengeResponse.envelope.cipherText.length).toBeGreaterThan(0);
  expect(serverChallengeResponse.envelope.nonce.length).toBe(24);
  expect(serverChallengeResponse.oprfPublicKey.length).toBe(32);
  expect(serverChallengeResponse.oprfChallengeResponse.length).toBe(32);
  // 2. Server generated OPRF Response for Client
  const clienSessionKeys = client.createUserSession(
    password,
    serverChallengeResponse.envelope.cipherText,
    serverChallengeResponse.envelope.nonce,
    serverChallengeResponse.oprfPublicKey,
    randomScalar,
    serverChallengeResponse.oprfChallengeResponse
  );
  // 3. Client creates shared session keys
  const isAuthorized = server.didLoginSucceed(username, clienSessionKeys);
  // 4. Server creates matching session keys if login was successful
  return isAuthorized;
};

beforeAll(async () => {
  sodium = common.initializeSodium();
  client.createKeyPair();
  server.createKeyPair();
});

test("Create key pairs", () => {
  client.createKeyPair();
  expect(client.publicKey).toBeDefined();
  expect(client.privateKey).toBeDefined();
  server.createKeyPair();
  expect(server.publicKey).toBeDefined();
  expect(server.privateKey).toBeDefined();
});

test("Registration", () => {
  const clientOprfChallengeData = client.createOprfChallenge(password);
  const clientOprfChallenge = clientOprfChallengeData.oprfChallenge;
  const randomScalar = clientOprfChallengeData.randomScalar;

  expect(clientOprfChallenge.length).toBe(32);
  expect(randomScalar.length).toBe(32);
  // 1. Client generated OPRF challenge for Server
  const serverChallengeResponse = server.createRegistrationResponse(
    username,
    clientOprfChallenge
  );
  expect(serverChallengeResponse.serverPublicKey.length).toBe(32);
  expect(serverChallengeResponse.oprfPublicKey.length).toBe(32);
  expect(serverChallengeResponse.oprfChallengeResponse.length).toBe(32);

  // 2. Server generated OPRF Response for Client
  const oprfRegistrationEnvelope = client.createOprfRegistrationEnvelope(
    password,
    randomScalar,
    serverChallengeResponse.oprfChallengeResponse,
    serverChallengeResponse.serverPublicKey!,
    serverChallengeResponse.oprfPublicKey
  );
  expect(oprfRegistrationEnvelope.cipherText.length).toBeGreaterThan(0);
  expect(oprfRegistrationEnvelope.nonce.length).toBe(24);

  // 3. Client created OPRF Registration Envelope
  server.storeClientOprfRegistrationEnvelope(
    username,
    oprfRegistrationEnvelope,
    client.publicKey!
  );
  // 4. Server stored Client OPRF envelope
  // Registration succeeded
});

test("Successful Login", () => {
  const isAuthorized = login(username, password);
  expect(isAuthorized).toBe(true);
});

test("Bad Password", () => {
  expect(() => {
    login(username, "badpassword");
  }).toThrowError("Invalid password");
});

test("Bad Username", () => {
  expect(() => {
    login("badusername", "badpassword");
  }).toThrowError("Username not registered");
});
