import test from "node:test";
import assert from "node:assert/strict";

import {
  analyzePassword,
  estimateCharsetSize,
  estimateEntropyBits,
  estimateShannonEntropyBits,
  hasKeyboardWalk,
  hasRepeatedRun,
  hasSimpleSequence,
} from "../docs/assets/modules/analyzer.js";

function makeMemoryStorage() {
  const store = new Map();
  return {
    getItem(k) {
      return store.has(k) ? store.get(k) : null;
    },
    setItem(k, v) {
      store.set(k, String(v));
    },
    removeItem(k) {
      store.delete(k);
    },
  };
}

test("entropy is 0 for empty", () => {
  assert.equal(estimateEntropyBits(""), 0);
  assert.equal(estimateShannonEntropyBits(""), 0);
});

test("shannon entropy behaves as a signal", () => {
  assert.equal(estimateShannonEntropyBits("aaaa"), 0);
  assert.ok(estimateShannonEntropyBits("abcd") > 0);
});

test("charset size increases with variety", () => {
  assert.ok(estimateCharsetSize("aaaa") < estimateCharsetSize("aA0!"));
});

test("pattern detectors flag common risky patterns", () => {
  assert.equal(hasRepeatedRun("aaaa"), true);
  assert.equal(hasSimpleSequence("abcd"), true);
  assert.equal(hasKeyboardWalk("qwerty123"), true);
});

test("analyzePassword produces deterministic shape", async () => {
  const storage = makeMemoryStorage();
  const commonSet = new Set(["password", "123456"]);

  const a1 = await analyzePassword("password", {
    commonSet,
    pepper: "pepper",
    saveHistory: true,
    storage,
    crypto: globalThis.crypto,
  });

  assert.ok(Number.isInteger(a1.score));
  assert.equal(typeof a1.label, "string");
  assert.ok(Array.isArray(a1.reasons));
  assert.equal(a1.reasons.length > 0, true);
  assert.equal(typeof a1.shannonEntropyBits, "number");

  const a2 = await analyzePassword("password", {
    commonSet,
    pepper: "pepper",
    saveHistory: true,
    storage,
    crypto: globalThis.crypto,
  });

  assert.equal(a2.isReused, true);
});

test("policy profiles affect scoring", async () => {
  const storage = makeMemoryStorage();
  const commonSet = new Set();
  const wordSet = new Set();

  const balanced = await analyzePassword("short", {
    commonSet,
    wordSet,
    policy: "balanced",
    toggles: { patterns: true, dictionary: true, reuse: false },
    pepper: "",
    saveHistory: false,
    storage,
    crypto: globalThis.crypto,
  });

  const strict = await analyzePassword("short", {
    commonSet,
    wordSet,
    policy: "strict",
    toggles: { patterns: true, dictionary: true, reuse: false },
    pepper: "",
    saveHistory: false,
    storage,
    crypto: globalThis.crypto,
  });

  assert.ok(strict.score <= balanced.score);
});

test("dictionary detection can be toggled", async () => {
  const storage = makeMemoryStorage();
  const commonSet = new Set();
  const wordSet = new Set(["correct"]);

  const withDict = await analyzePassword("CorrectHorseBatteryStaple", {
    commonSet,
    wordSet,
    policy: "balanced",
    toggles: { patterns: false, dictionary: true, reuse: false },
    pepper: "",
    saveHistory: false,
    storage,
    crypto: globalThis.crypto,
  });

  const withoutDict = await analyzePassword("CorrectHorseBatteryStaple", {
    commonSet,
    wordSet,
    policy: "balanced",
    toggles: { patterns: false, dictionary: false, reuse: false },
    pepper: "",
    saveHistory: false,
    storage,
    crypto: globalThis.crypto,
  });

  assert.equal(withDict.reasons.some((r) => r.startsWith("Dictionary word detected:")), true);
  assert.equal(withoutDict.reasons.some((r) => r.startsWith("Dictionary word detected:")), false);
});

test("analyzer fuzz: score stays within 0..100", async () => {
  const storage = makeMemoryStorage();
  const commonSet = new Set(["password", "qwerty"]);
  const wordSet = new Set(["about", "admin", "welcome", "correct"]);

  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$";
  let seed = 123;
  function randInt(maxExclusive) {
    seed = (seed * 1103515245 + 12345) % 2147483647;
    return seed % maxExclusive;
  }
  function randString(n) {
    let out = "";
    for (let i = 0; i < n; i += 1) {
      out += alphabet[randInt(alphabet.length)];
    }
    return out;
  }

  for (let i = 0; i < 100; i += 1) {
    const pw = randString(1 + (i % 40));
    const a = await analyzePassword(pw, {
      commonSet,
      wordSet,
      policy: i % 2 === 0 ? "balanced" : "strict",
      toggles: { patterns: true, dictionary: true, reuse: false },
      pepper: "",
      saveHistory: false,
      storage,
      crypto: globalThis.crypto,
    });
    assert.ok(a.score >= 0 && a.score <= 100);
  }
});
