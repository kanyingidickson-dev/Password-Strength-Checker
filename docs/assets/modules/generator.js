const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/";

const AMBIGUOUS = new Set(["0", "O", "o", "1", "l", "I"]);

function filterAmbiguous(s) {
  return [...s].filter((c) => !AMBIGUOUS.has(c)).join("");
}

function pick(rng, chars) {
  return chars[rng.int(chars.length)];
}

export function makeRng(cryptoProvider) {
  const cryptoObj = cryptoProvider ?? globalThis.crypto;
  if (!cryptoObj?.getRandomValues) {
    throw new Error("Secure randomness not available");
  }

  return {
    int(maxExclusive) {
      if (maxExclusive <= 0) throw new Error("Invalid range");
      const buf = new Uint32Array(1);
      const limit = Math.floor(0xffffffff / maxExclusive) * maxExclusive;
      while (true) {
        cryptoObj.getRandomValues(buf);
        const x = buf[0];
        if (x < limit) return x % maxExclusive;
      }
    },
  };
}

export function generatePassword(options) {
  const length = Number(options?.length ?? 20);
  const useLower = Boolean(options?.lower ?? true);
  const useUpper = Boolean(options?.upper ?? true);
  const useDigits = Boolean(options?.digits ?? true);
  const useSymbols = Boolean(options?.symbols ?? true);
  const avoidAmbiguous = Boolean(options?.avoidAmbiguous ?? true);
  const requireEach = Boolean(options?.requireEach ?? true);
  const rng = options?.rng ?? makeRng(options?.crypto);

  const groups = [];
  if (useLower) groups.push(avoidAmbiguous ? filterAmbiguous(LOWER) : LOWER);
  if (useUpper) groups.push(avoidAmbiguous ? filterAmbiguous(UPPER) : UPPER);
  if (useDigits) groups.push(avoidAmbiguous ? filterAmbiguous(DIGITS) : DIGITS);
  if (useSymbols) groups.push(SYMBOLS);

  if (groups.length === 0) {
    throw new Error("Select at least one character set");
  }
  if (length < 4) {
    throw new Error("Length too small");
  }
  if (requireEach && length < groups.length) {
    throw new Error("Length must be at least the number of selected sets");
  }

  const all = groups.join("");

  const out = [];
  if (requireEach) {
    for (const g of groups) {
      out.push(pick(rng, g));
    }
  }

  while (out.length < length) {
    out.push(pick(rng, all));
  }

  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = rng.int(i + 1);
    const tmp = out[i];
    out[i] = out[j];
    out[j] = tmp;
  }

  return out.join("");
}
