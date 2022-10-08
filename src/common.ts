import _sodium from "libsodium-wrappers-sumo";
export let sodium: any = null;

export type SessionKeys = {
  sharedRx: Uint8Array;
  sharedTx: Uint8Array;
};

export const initializeSodium = async (): Promise<void> => {
  await _sodium.ready;
  sodium = _sodium;
  sodium.crypto_generichash_batch = sodium_crypto_generichash_batch;
  return sodium;
};

// sodium.crypto_generichash_batch = sodium_crypto_generichash_batch
function sodium_crypto_generichash_batch(arr: Uint8Array[]): Uint8Array {
  const key = Buffer.alloc(_sodium.crypto_generichash_KEYBYTES);
  const state = _sodium.crypto_generichash_init(
    key,
    _sodium.crypto_generichash_BYTES
  );
  arr.forEach((item) => {
    _sodium.crypto_generichash_update(state, item);
  });
  const combinedHash = sodium.crypto_generichash_final(
    state,
    _sodium.crypto_generichash_BYTES
  );
  return combinedHash;
}

export const generateKeyPair = () => {
  const keyPair = sodium.crypto_kx_keypair();
  return keyPair;
};

export const generateNonce = () => {
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  return nonce;
};

export const base64Encode = (bytes: Uint8Array): string => {
  const base64Data = Buffer.from(new Uint8Array(bytes)).toString("base64");
  return base64Data;
};

export const base64Decode = (str: string): Uint8Array => {
  const bytes = Buffer.from(str, "base64");
  const arr = new Uint8Array(bytes);
  return arr;
};

const arr2String = (arr: Uint8Array): string => {
  const buffer = Buffer.from(arr);
  const str = buffer.toString("utf-8");
  return str;
};

export const encryptWithSharedKey = (
  message: string,
  sharedKey: Uint8Array
): { encryptedMessage: Uint8Array; nonce: Uint8Array } => {
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
  const additionData = "";
  const encryptedMessage = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    message,
    additionData,
    null,
    nonce,
    sharedKey
  );
  return { encryptedMessage, nonce };
};

export const decryptWithSharedKey = (
  encryptedMessage: Uint8Array,
  nonce: Uint8Array,
  sharedKey: Uint8Array
): string => {
  const additionalData = "";
  const decryptedClientMessage =
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      encryptedMessage,
      additionalData,
      nonce,
      sharedKey
    );
  return arr2String(decryptedClientMessage);
};
