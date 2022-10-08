import * as client from "./client";
import * as common from "./common";
import * as server from "./server";
let sodium: any = undefined;

common.initializeSodium().then((_sodium) => {
  sodium = _sodium;
  main();
});

const username = "abc123";
const password = "password";

/**
 * Initialize the client and server
 */
const initializeEnvironment = () => {
  console.log("initializing environment");
  client.createKeyPair();
  server.createKeyPair();
};

/**
 * Have the client register with the server
 */
const registerClientWithServer = (username: string, password: string) => {
  console.log("");
  console.log("=============================================");
  console.log("Registering client with server");
  console.log("---------------------------------------------");
  console.log(`username '${username}', password: '${password}'`);
  console.log("---------------------------------------------");
  const clientOprfChallengeData = client.createOprfChallenge(password);
  const clientOprfChallenge = clientOprfChallengeData.oprfChallenge;
  const randomScalar = clientOprfChallengeData.randomScalar;
  console.log("1. Client generated OPRF challenge for Server");

  const serverChallengeResponse = server.createRegistrationResponse(
    username,
    clientOprfChallenge
  );
  console.log("2. Server generated OPRF Response for Client");
  const oprfRegistrationEnvelope = client.createOprfRegistrationEnvelope(
    password,
    randomScalar,
    serverChallengeResponse.oprfChallengeResponse,
    serverChallengeResponse.serverPublicKey!,
    serverChallengeResponse.oprfPublicKey
  );
  console.log("3. Client created OPRF Registration Envelope");

  server.storeClientOprfRegistrationEnvelope(
    username,
    oprfRegistrationEnvelope,
    client.publicKey!
  );
  console.log("4. Server stored Client OPRF envelope");
  console.log("---------------------------------------------");
  console.log("   Registration succeeded!");
  console.log("=============================================");
  console.log("");
};

const loginClientToServer = (username: string, password: string) => {
  console.log("");
  console.log("=============================================");
  console.log("Logging in client to server");
  console.log("---------------------------------------------");
  console.log(`username '${username}', password: '${password}'`);
  console.log("---------------------------------------------");
  const clientOprfChallengeData = client.createOprfChallenge(password);
  const clientOprfChallenge = clientOprfChallengeData.oprfChallenge;
  const randomScalar = clientOprfChallengeData.randomScalar;
  console.log("1. Client generated OPRF challenge for Server");

  let serverChallengeResponse: server.LoginChallengeResponse | undefined =
    undefined;
  try {
    serverChallengeResponse = server.createLoginChallengeResponse(
      username,
      clientOprfChallenge
    );
  } catch (error) {
    console.log("2. Server failed to generate for Client!");
    console.log("---------------------------------------------");
    console.log(`   Login failed: ${error.toString()}`);
    console.log("=============================================");
    console.log("");
    return;
  }
  console.log("2. Server generated OPRF Response for Client");

  let clientSessionKeys: common.SessionKeys | undefined = undefined;
  let serverSessionKeys: common.SessionKeys | undefined = undefined;
  try {
    clientSessionKeys = client.createSession(
      password,
      serverChallengeResponse.envelope.cipherText,
      serverChallengeResponse.envelope.nonce,
      serverChallengeResponse.oprfPublicKey,
      randomScalar,
      serverChallengeResponse.oprfChallengeResponse
    );
    serverSessionKeys = server.createSession(client.publicKey!);
    console.log(
      `   Client sharedRx: ${sodium.to_base64(clientSessionKeys.sharedRx)}`
    );
    console.log(
      `   Client sharedTx: ${sodium.to_base64(clientSessionKeys.sharedTx)}`
    );
    console.log(
      `   Server sharedRx: ${sodium.to_base64(serverSessionKeys.sharedRx)}`
    );
    console.log(
      `   Server sharedTx: ${sodium.to_base64(serverSessionKeys.sharedTx)}`
    );
  } catch (error) {
    console.log("3. Client failed to create shared session keys!");
    console.log("---------------------------------------------");
    console.log(`   Login failed: ${error.toString()}`);
    console.log("=============================================");
    console.log("");
    return;
  }
  console.log("3. Client creates shared session keys");
  let isAuthorized = false;
  try {
    isAuthorized = server.didLoginSucceed(username, clientSessionKeys);
  } catch (error) {
    console.log("3. Server failed to replicate session keys!");
    console.log("---------------------------------------------");
    console.log(`   Login failed: ${error.toString()}`);
    console.log("=============================================");
    console.log("");
    return;
  }
  if (!isAuthorized) {
    console.log("3. Server failed to replicate session keys!");
    console.log("---------------------------------------------");
    console.log("   Login failed: isAuthorized = false ");
    console.log("=============================================");
    console.log("");
    return;
  }
  console.log("4. Server creates identical session keys");
  console.log("---------------------------------------------");
  console.log("   Login succeeded! isAuthorized = true");
  console.log("=============================================");
  console.log("");

  // Sending message from client to server using a shared key and sodium
  const clientMessage = "Client says hello.";
  const encryptedClientData = common.encryptWithSharedKey(
    clientMessage,
    clientSessionKeys.sharedTx
  );
  const decryptedClientMessage = common.decryptWithSharedKey(
    encryptedClientData.encryptedMessage,
    encryptedClientData.nonce,
    serverSessionKeys.sharedRx
  );
  console.log(`    Client sent: "${decryptedClientMessage}"`);
  const serverMessage = "Server says hello.";
  const encryptedServerData = common.encryptWithSharedKey(
    serverMessage,
    serverSessionKeys.sharedTx
  );
  const decryptedServerMessage = common.decryptWithSharedKey(
    encryptedServerData.encryptedMessage,
    encryptedServerData.nonce,
    clientSessionKeys.sharedRx
  );
  console.log(`    Server sent: "${decryptedServerMessage}"`);
  console.log("---------------------------------------------");
};

const main = async () => {
  initializeEnvironment();
  registerClientWithServer(username, password);
  loginClientToServer(username, password);
  loginClientToServer(username, "badpassword");
  loginClientToServer("badusername", "badpass");
};
