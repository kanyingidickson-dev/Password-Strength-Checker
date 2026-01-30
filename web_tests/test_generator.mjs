import test from "node:test";
import assert from "node:assert/strict";

import { generatePassword } from "../docs/assets/modules/generator.js";

function makeDeterministicRng() {
  let x = 0;
  return {
    int(maxExclusive) {
      x = (x + 7) % maxExclusive;
      return x;
    },
  };
}

test("generator length matches requested", () => {
  const pw = generatePassword({
    length: 24,
    lower: true,
    upper: true,
    digits: true,
    symbols: true,
    avoidAmbiguous: true,
    requireEach: true,
    rng: makeDeterministicRng(),
  });

  assert.equal(pw.length, 24);
});

test("generator requires each selected set", () => {
  const pw = generatePassword({
    length: 12,
    lower: true,
    upper: true,
    digits: true,
    symbols: false,
    avoidAmbiguous: false,
    requireEach: true,
    rng: makeDeterministicRng(),
  });

  assert.match(pw, /[a-z]/);
  assert.match(pw, /[A-Z]/);
  assert.match(pw, /[0-9]/);
});

test("generator fuzz: always returns requested length", () => {
  const rng = makeDeterministicRng();
  for (let i = 0; i < 100; i += 1) {
    const length = 8 + (i % 32);
    const pw = generatePassword({
      length,
      lower: true,
      upper: true,
      digits: true,
      symbols: i % 3 === 0,
      avoidAmbiguous: i % 2 === 0,
      requireEach: true,
      rng,
    });
    assert.equal(pw.length, length);
  }
});
