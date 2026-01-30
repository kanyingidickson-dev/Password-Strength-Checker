import test from "node:test";
import assert from "node:assert/strict";

import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  base64DecodeToText,
  base64EncodeText,
  digestText,
  hmacText,
  pbkdf2,
} from "../docs/assets/modules/crypto.js";


test("digestText returns stable hex output", async () => {
  const out = await digestText("SHA-256", "hello", "hex");
  assert.equal(out.length, 64);
  assert.match(out, /^[0-9a-f]+$/);
});

test("hmacText returns stable hex output", async () => {
  const out = await hmacText("SHA-256", "key", "hello", "hex");
  assert.equal(out.length, 64);
  assert.match(out, /^[0-9a-f]+$/);
});

test("pbkdf2 returns requested length", async () => {
  const out = await pbkdf2("password", "salt", 1000, 32);
  assert.equal(out.length, 64);
  assert.match(out, /^[0-9a-f]+$/);
});

test("AES-GCM round trip", async () => {
  const key = "correct horse battery staple";
  const plain = "hello world";

  const cipher = await aesGcmEncrypt(key, plain);
  const back = await aesGcmDecrypt(key, cipher);

  assert.equal(back, plain);
});

test("Base64 encode/decode round trip", () => {
  const s = "hello";
  const b64 = base64EncodeText(s);
  assert.equal(base64DecodeToText(b64), s);
});
