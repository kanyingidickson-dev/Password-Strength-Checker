import { base64ToBytes, bytesToBase64, bytesToHex, bytesToUtf8, hexToBytes, utf8ToBytes } from "./format.js";

export async function digestText(algorithm, text, output, cryptoProvider) {
  const cryptoObj = cryptoProvider ?? globalThis.crypto;
  const algo = String(algorithm);
  const bytes = utf8ToBytes(text);
  const digest = await cryptoObj.subtle.digest(algo, bytes);
  const out = new Uint8Array(digest);
  return output === "base64" ? bytesToBase64(out) : bytesToHex(out);
}

export async function hmacText(algorithm, key, text, output, cryptoProvider) {
  const cryptoObj = cryptoProvider ?? globalThis.crypto;
  const algo = String(algorithm);
  const keyBytes = utf8ToBytes(key);
  const cryptoKey = await cryptoObj.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: { name: algo } },
    false,
    ["sign"],
  );
  const sig = await cryptoObj.subtle.sign("HMAC", cryptoKey, utf8ToBytes(text));
  const out = new Uint8Array(sig);
  return output === "base64" ? bytesToBase64(out) : bytesToHex(out);
}

export async function pbkdf2(password, salt, iterations, lengthBytes, cryptoProvider) {
  const cryptoObj = cryptoProvider ?? globalThis.crypto;
  const baseKey = await cryptoObj.subtle.importKey(
    "raw",
    utf8ToBytes(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );

  const bits = await cryptoObj.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: utf8ToBytes(salt),
      iterations: Number(iterations),
    },
    baseKey,
    Number(lengthBytes) * 8,
  );

  return bytesToHex(new Uint8Array(bits));
}

async function aesKeyFromText(keyText, cryptoProvider) {
  const cryptoObj = cryptoProvider ?? globalThis.crypto;
  const raw = await cryptoObj.subtle.digest("SHA-256", utf8ToBytes(keyText));
  return cryptoObj.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

function randomIv(cryptoProvider) {
  const cryptoObj = cryptoProvider ?? globalThis.crypto;
  const iv = new Uint8Array(12);
  cryptoObj.getRandomValues(iv);
  return iv;
}

export async function aesGcmEncrypt(keyText, plaintext, cryptoProvider) {
  const cryptoObj = cryptoProvider ?? globalThis.crypto;
  const key = await aesKeyFromText(keyText, cryptoObj);
  const iv = randomIv(cryptoObj);
  const cipher = await cryptoObj.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    utf8ToBytes(plaintext),
  );
  const payload = new Uint8Array(iv.length + cipher.byteLength);
  payload.set(iv, 0);
  payload.set(new Uint8Array(cipher), iv.length);
  return bytesToBase64(payload);
}

export async function aesGcmDecrypt(keyText, cipherB64, cryptoProvider) {
  const cryptoObj = cryptoProvider ?? globalThis.crypto;
  const key = await aesKeyFromText(keyText, cryptoObj);
  const payload = base64ToBytes(cipherB64);
  if (payload.length < 13) {
    throw new Error("Ciphertext too short");
  }
  const iv = payload.slice(0, 12);
  const data = payload.slice(12);
  const plain = await cryptoObj.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return bytesToUtf8(new Uint8Array(plain));
}

export function base64EncodeText(text) {
  return bytesToBase64(utf8ToBytes(text));
}

export function base64DecodeToText(b64) {
  return bytesToUtf8(base64ToBytes(b64));
}

export function normalizeHexOrBase64(input) {
  const s = input.trim();
  if (!s) throw new Error("Empty");
  if (/^[0-9a-fA-F]+$/.test(s)) {
    return bytesToBase64(hexToBytes(s));
  }
  return s;
}
