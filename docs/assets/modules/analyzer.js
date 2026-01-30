function buildKeyboardAdjacency() {
  const rows = [
    "`1234567890-=" ,
    "qwertyuiop[]\\",
    "asdfghjkl;'" ,
    "zxcvbnm,./" ,
  ];

  const pos = new Map();
  for (let y = 0; y < rows.length; y += 1) {
    const row = rows[y];
    for (let x = 0; x < row.length; x += 1) {
      pos.set(row[x], { x, y });
    }
  }

  const adj = new Map();
  for (const [c, p] of pos.entries()) {
    const set = new Set();
    for (let dy = -1; dy <= 1; dy += 1) {
      for (let dx = -1; dx <= 1; dx += 1) {
        if (dx === 0 && dy === 0) continue;
        const x = p.x + dx;
        const y = p.y + dy;
        const row = rows[y];
        if (!row) continue;
        const n = row[x];
        if (n) set.add(n);
      }
    }
    adj.set(c, set);
  }

  return adj;
}

const KEYBOARD_ADJ = buildKeyboardAdjacency();

export function estimateCharsetSize(password) {
  const hasLower = [...password].some((c) => c >= "a" && c <= "z");
  const hasUpper = [...password].some((c) => c >= "A" && c <= "Z");
  const hasDigit = [...password].some((c) => c >= "0" && c <= "9");
  const punctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
  const hasSymbol = [...password].some((c) => punctuation.includes(c));
  const hasOther = [...password].some(
    (c) =>
      !(c >= "a" && c <= "z") &&
      !(c >= "A" && c <= "Z") &&
      !(c >= "0" && c <= "9") &&
      !punctuation.includes(c),
  );

  let size = 0;
  if (hasLower) size += 26;
  if (hasUpper) size += 26;
  if (hasDigit) size += 10;
  if (hasSymbol) size += punctuation.length;
  if (hasOther) size += 32;

  return Math.max(size, 1);
}

export function estimateEntropyBits(password) {
  if (!password) return 0;
  const charset = estimateCharsetSize(password);
  return password.length * Math.log2(charset);
}

export function estimateShannonEntropyBits(password) {
  if (!password) return 0;
  const counts = new Map();
  for (const c of password) {
    counts.set(c, (counts.get(c) ?? 0) + 1);
  }
  const n = password.length;
  let h = 0;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h * n;
}

export function hasRepeatedRun(password, runLen = 4) {
  if (runLen <= 1) return false;
  let count = 1;
  let prev = null;
  for (const c of password) {
    if (c === prev) {
      count += 1;
      if (count >= runLen) return true;
    } else {
      count = 1;
      prev = c;
    }
  }
  return false;
}

function isSequence(s) {
  if (s.length < 4) return false;
  const diffs = [];
  for (let i = 0; i < s.length - 1; i += 1) {
    diffs.push(s.charCodeAt(i + 1) - s.charCodeAt(i));
  }
  return diffs.every((d) => d === 1) || diffs.every((d) => d === -1);
}

export function hasSimpleSequence(password) {
  const p = password.toLowerCase();
  for (let i = 0; i <= p.length - 4; i += 1) {
    const window = p.slice(i, i + 4);
    if (isSequence(window)) return true;
  }
  return false;
}

export function hasKeyboardWalk(password) {
  const p = password.toLowerCase();
  let run = 1;
  for (let i = 1; i < p.length; i += 1) {
    const prev = p[i - 1];
    const cur = p[i];
    const neigh = KEYBOARD_ADJ.get(prev);
    if (neigh && neigh.has(cur)) {
      run += 1;
      if (run >= 4) return true;
    } else {
      run = 1;
    }
  }
  return false;
}

export function isCommonPassword(password, commonSet) {
  if (!commonSet) return false;
  const p = password.trim().toLowerCase();
  return commonSet.has(p);
}

export function detectPatterns(password, commonSet) {
  const hits = [];
  if (hasRepeatedRun(password)) hits.push({ name: "repeated_chars", detail: "Contains repeated character runs" });
  if (hasSimpleSequence(password)) hits.push({ name: "sequence", detail: "Contains simple sequential characters" });
  if (hasKeyboardWalk(password)) hits.push({ name: "keyboard_walk", detail: "Contains keyboard-walk patterns" });
  if (isCommonPassword(password, commonSet)) hits.push({ name: "common_password", detail: "Matches a common password" });
  return hits;
}

export function detectDictionaryWords(password, wordSet) {
  if (!wordSet) return [];
  const p = password.toLowerCase();
  const out = new Set();
  for (const w of wordSet) {
    if (typeof w !== "string") continue;
    const word = w.trim().toLowerCase();
    if (word.length < 4) continue;
    if (word.length > p.length) continue;
    if (p.includes(word)) out.add(word);
    if (out.size >= 3) break;
  }
  return [...out];
}

export function labelForScore(score) {
  if (score < 40) return "weak";
  if (score < 70) return "ok";
  return "strong";
}

export function policyConfig(name) {
  const n = String(name ?? "balanced").toLowerCase();

  if (n === "strict") {
    return {
      weights: {
        lengthPenaltyShort: 30,
        lengthBonusOk: 8,
        lengthBonusGood: 22,
        entropyPenaltyLow: 25,
        entropyPenaltyShannonLow: 15,
        entropyBonusModerate: 8,
        entropyBonusHigh: 20,
        commonPasswordPenalty: 70,
        sequencePenalty: 25,
        repeatedPenalty: 12,
        reusePenalty: 35,
        dictionaryPenalty: 25,
      },
      entropyThresholds: { low: 45, high: 70 },
    };
  }

  if (n === "nist") {
    return {
      weights: {
        lengthPenaltyShort: 25,
        lengthBonusOk: 10,
        lengthBonusGood: 25,
        entropyPenaltyLow: 15,
        entropyPenaltyShannonLow: 10,
        entropyBonusModerate: 8,
        entropyBonusHigh: 15,
        commonPasswordPenalty: 70,
        sequencePenalty: 15,
        repeatedPenalty: 10,
        reusePenalty: 30,
        dictionaryPenalty: 20,
      },
      entropyThresholds: { low: 40, high: 60 },
    };
  }

  return {
    weights: {
      lengthPenaltyShort: 25,
      lengthBonusOk: 10,
      lengthBonusGood: 25,
      entropyPenaltyLow: 20,
      entropyPenaltyShannonLow: 10,
      entropyBonusModerate: 10,
      entropyBonusHigh: 25,
      commonPasswordPenalty: 60,
      sequencePenalty: 20,
      repeatedPenalty: 10,
      reusePenalty: 30,
      dictionaryPenalty: 20,
    },
    entropyThresholds: { low: 40, high: 60 },
  };
}

function mergedWeights(base, overrides) {
  if (!overrides) return base;
  const out = { ...base };
  for (const [k, v] of Object.entries(overrides)) {
    if (Number.isFinite(Number(v))) out[k] = Number(v);
  }
  return out;
}

export async function sha256HexWithPepper(password, pepper, cryptoProvider) {
  const cryptoObj = cryptoProvider ?? globalThis.crypto;
  if (!cryptoObj?.subtle) {
    throw new Error("Web Crypto not available");
  }

  const enc = new TextEncoder();
  const data = new Uint8Array([
    ...enc.encode(pepper),
    0,
    ...enc.encode(password),
  ]);
  const digest = await cryptoObj.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

function loadDigestSet(storage) {
  const raw = storage.getItem("psc_history_digests");
  if (!raw) return new Set();
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return new Set();
    const out = new Set();
    for (const x of parsed) {
      if (typeof x === "string" && x.length === 64) out.add(x);
    }
    return out;
  } catch {
    return new Set();
  }
}

function saveDigestSet(storage, set) {
  storage.setItem("psc_history_digests", JSON.stringify([...set].sort()));
}

export function clearLocalHistory(storage) {
  storage.removeItem("psc_history_digests");
}

export async function analyzePassword(password, options) {
  const commonSet = options?.commonSet ?? null;
  const wordSet = options?.wordSet ?? null;
  const saveHistory = Boolean(options?.saveHistory);
  const pepper = options?.pepper ?? "";
  const storage = options?.storage ?? globalThis.localStorage;
  const cryptoProvider = options?.crypto ?? globalThis.crypto;
  const policy = policyConfig(options?.policy);
  const weights = mergedWeights(policy.weights, options?.weights);
  const toggles = {
    patterns: options?.toggles?.patterns !== false,
    dictionary: options?.toggles?.dictionary !== false,
    reuse: options?.toggles?.reuse !== false,
  };

  const reasons = [];

  if (!password) {
    return {
      score: 0,
      label: "weak",
      entropyBits: 0,
      reasons: ["Password is empty"],
      isReused: false,
    };
  }

  let score = 0;

  const length = password.length;
  if (length < 8) {
    reasons.push("Too short (< 8 characters)");
    score -= weights.lengthPenaltyShort;
  } else if (length < 12) {
    reasons.push("Acceptable length (8–11), but longer is better");
    score += weights.lengthBonusOk;
  } else {
    reasons.push("Good length (>= 12)");
    score += weights.lengthBonusGood;
  }

  const entropy = estimateEntropyBits(password);
  const shannonEntropy = estimateShannonEntropyBits(password);
  if (entropy < policy.entropyThresholds.low) {
    reasons.push(`Low estimated entropy (${entropy.toFixed(1)} bits)`);
    score -= weights.entropyPenaltyLow;
  } else if (entropy < policy.entropyThresholds.high) {
    reasons.push(`Moderate estimated entropy (${entropy.toFixed(1)} bits)`);
    score += weights.entropyBonusModerate;
  } else {
    reasons.push(`High estimated entropy (${entropy.toFixed(1)} bits)`);
    score += weights.entropyBonusHigh;
  }

  if (shannonEntropy < 25) {
    reasons.push(`Low Shannon entropy signal (${shannonEntropy.toFixed(1)} bits)`);
    score -= weights.entropyPenaltyShannonLow;
  }

  if (toggles.patterns) {
    const hits = detectPatterns(password, commonSet);
    for (const hit of hits) {
      reasons.push(`Pattern detected: ${hit.detail}`);
    }

    if (hits.some((h) => h.name === "common_password")) score -= weights.commonPasswordPenalty;
    if (hits.some((h) => h.name === "keyboard_walk" || h.name === "sequence")) score -= weights.sequencePenalty;
    if (hits.some((h) => h.name === "repeated_chars")) score -= weights.repeatedPenalty;
  }

  if (toggles.dictionary) {
    const words = detectDictionaryWords(password, wordSet);
    if (words.length > 0) {
      reasons.push(`Dictionary word detected: ${words.join(", ")}`);
      score -= weights.dictionaryPenalty;
    }
  }

  let isReused = false;
  let digestHex = null;
  if (toggles.reuse && pepper && storage && cryptoProvider?.subtle) {
    digestHex = await sha256HexWithPepper(password, pepper, cryptoProvider);
    const digests = loadDigestSet(storage);
    isReused = digests.has(digestHex);
    if (isReused) {
      reasons.push("Password appears to be reused (seen in local history)");
      score -= weights.reusePenalty;
    }
    if (saveHistory) {
      digests.add(digestHex);
      saveDigestSet(storage, digests);
    }
  }

  const finalScore = Math.max(0, Math.min(100, score + 50));
  return {
    score: finalScore,
    label: labelForScore(finalScore),
    entropyBits: entropy,
    shannonEntropyBits: shannonEntropy,
    reasons,
    isReused,
    digestHex,
  };
}

export async function loadCommonPasswords(url) {
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error("Failed to load common passwords");
  }
  const text = await resp.text();
  const set = new Set();
  for (const line of text.split(/\r?\n/)) {
    const w = line.trim().toLowerCase();
    if (!w || w.startsWith("#")) continue;
    set.add(w);
  }
  return set;
}
