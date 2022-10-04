import _sodium from "libsodium-wrappers-sumo";
export let sodium: any = null;

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
