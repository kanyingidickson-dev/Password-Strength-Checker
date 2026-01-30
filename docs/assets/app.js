import { analyzePassword, clearLocalHistory, loadCommonPasswords } from "./modules/analyzer.js";
import { generatePassword } from "./modules/generator.js";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  base64DecodeToText,
  base64EncodeText,
  digestText,
  hmacText,
  pbkdf2,
} from "./modules/crypto.js";

function $(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element: ${id}`);
  return el;
}

function setActiveTab(name) {
  for (const b of document.querySelectorAll(".tab")) {
    b.classList.toggle("is-active", b.dataset.tab === name);
  }
  for (const p of document.querySelectorAll(".panel")) {
    p.classList.toggle("is-active", p.id === `panel-${name}`);
  }
}

function setText(id, value) {
  $(id).textContent = value;
}

function setOutput(id, value) {
  $(id).textContent = value || "—";
}

function normalizeHashText(s) {
  return String(s).trim().replaceAll(/\s+/g, "").toLowerCase();
}

function setMeter(score) {
  const el = $("meter-fill");
  el.style.width = `${Math.max(0, Math.min(100, score))}%`;
}

function renderReasons(items) {
  const ul = $("reasons");
  ul.replaceChildren();
  for (const r of items) {
    const li = document.createElement("li");
    li.textContent = r;
    ul.appendChild(li);
  }
}

async function copyToClipboard(text) {
  if (!text || text === "—") return;
  await navigator.clipboard.writeText(text);
}

let commonSet = null;
let wordSet = null;
let lastGenerated = "";
let lastAnalysis = null;

async function loadWords(url) {
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error("Failed to load words");
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

async function readTextFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Failed to read file"));
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.readAsText(file);
  });
}

async function loadUploadedWordlist(file) {
  const text = await readTextFile(file);
  const set = new Set();
  for (const line of text.split(/\r?\n/)) {
    const w = line.trim().toLowerCase();
    if (!w || w.startsWith("#")) continue;
    set.add(w);
  }
  return set;
}

function parseWeightsJson(text) {
  const raw = String(text ?? "").trim();
  if (!raw) return null;
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Invalid weights JSON");
  }
  return parsed;
}

async function runAnalysis(password, options) {
  const toggles = {
    patterns: $("toggle-patterns").checked,
    dictionary: $("toggle-dictionary").checked,
    reuse: $("toggle-reuse").checked,
  };

  const policy = $("policy").value;
  const weights = parseWeightsJson($("weights-json").value);

  const analysis = await analyzePassword(password, {
    commonSet,
    wordSet,
    policy,
    toggles,
    weights,
    pepper: options?.pepper ?? "",
    saveHistory: true,
  });

  lastAnalysis = analysis;

  setText("score", String(analysis.score));
  setText("label", analysis.label);
  setText("entropy", analysis.entropyBits.toFixed(1));
  setText("shannon", (analysis.shannonEntropyBits ?? 0).toFixed(1));
  setText("reuse", analysis.isReused ? "reused" : "not seen");
  setMeter(analysis.score);
  renderReasons(analysis.reasons);
}

function handleTabs() {
  for (const b of document.querySelectorAll(".tab")) {
    b.addEventListener("click", () => setActiveTab(String(b.dataset.tab)));
  }
}

function handleStrength() {
  const pwd = $("pwd");
  const pepper = $("pepper");

  $("wordlist").addEventListener("change", async () => {
    const input = $("wordlist");
    const file = input.files && input.files.length > 0 ? input.files[0] : null;
    if (!file) return;
    try {
      const custom = await loadUploadedWordlist(file);
      const merged = new Set(wordSet ?? []);
      for (const w of custom) merged.add(w);
      wordSet = merged;
    } catch (e) {
      renderReasons([String(e?.message ?? e)]);
    }
  });

  $("toggle-visibility").addEventListener("click", () => {
    const visible = pwd.type === "text";
    pwd.type = visible ? "password" : "text";
    $("toggle-visibility").textContent = visible ? "Show" : "Hide";
  });

  $("analyze").addEventListener("click", async () => {
    try {
      await runAnalysis(pwd.value, { pepper: pepper.value });
    } catch (e) {
      renderReasons([String(e?.message ?? e)]);
    }
  });

  pwd.addEventListener("keydown", async (ev) => {
    if (ev.key !== "Enter") return;
    await runAnalysis(pwd.value, { pepper: pepper.value });
  });

  $("clear-history").addEventListener("click", () => {
    clearLocalHistory(localStorage);
    setText("reuse", "—");
  });

  $("export-json").addEventListener("click", async () => {
    if (!lastAnalysis) return;
    const payload = {
      exportedAt: new Date().toISOString(),
      analysis: lastAnalysis,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2) + "\n"], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "password-analysis.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });
}

function handleGenerator() {
  $("generate").addEventListener("click", () => {
    const opts = {
      length: Number($("gen-length").value),
      lower: $("gen-lower").checked,
      upper: $("gen-upper").checked,
      digits: $("gen-digits").checked,
      symbols: $("gen-symbols").checked,
      avoidAmbiguous: $("gen-avoid-ambiguous").checked,
      requireEach: $("gen-require-each").checked,
    };
    try {
      lastGenerated = generatePassword(opts);
      setOutput("generated", lastGenerated);
    } catch (e) {
      setOutput("generated", String(e?.message ?? e));
    }
  });

  $("copy-generated").addEventListener("click", async () => {
    await copyToClipboard($("generated").textContent ?? "");
  });

  $("analyze-generated").addEventListener("click", async () => {
    if (!lastGenerated) return;
    setActiveTab("analyze");
    $("pwd").value = lastGenerated;
    await runAnalysis(lastGenerated, { pepper: $("pepper").value });
  });
}

function handleCrypto() {
  $("do-hash").addEventListener("click", async () => {
    const text = $("crypto-text").value;
    const algo = $("hash-algo").value;
    const format = $("hash-format").value;
    const key = $("hmac-key").value;
    const expected = $("hash-expected").value;

    try {
      const out = key
        ? await hmacText(algo, key, text, format)
        : await digestText(algo, text, format);
      setOutput("hash-out", out);

      if (expected.trim()) {
        const ok = normalizeHashText(out) === normalizeHashText(expected);
        setText("hash-match", ok ? "match" : "no match");
      } else {
        setText("hash-match", "—");
      }
    } catch (e) {
      setOutput("hash-out", String(e?.message ?? e));
      setText("hash-match", "—");
    }
  });

  $("copy-hash").addEventListener("click", async () => {
    await copyToClipboard($("hash-out").textContent ?? "");
  });

  $("do-kdf").addEventListener("click", async () => {
    const pw = $("kdf-password").value;
    const salt = $("kdf-salt").value;
    const iter = Number($("kdf-iter").value);
    const len = Number($("kdf-len").value);

    try {
      const out = await pbkdf2(pw, salt, iter, len);
      setOutput("kdf-out", out);
    } catch (e) {
      setOutput("kdf-out", String(e?.message ?? e));
    }
  });

  $("copy-kdf").addEventListener("click", async () => {
    await copyToClipboard($("kdf-out").textContent ?? "");
  });

  $("do-encrypt").addEventListener("click", async () => {
    try {
      const out = await aesGcmEncrypt($("aes-key").value, $("aes-plain").value);
      setOutput("aes-cipher", out);
      $("aes-input").value = out;
    } catch (e) {
      setOutput("aes-cipher", String(e?.message ?? e));
    }
  });

  $("copy-cipher").addEventListener("click", async () => {
    await copyToClipboard($("aes-cipher").textContent ?? "");
  });

  $("do-decrypt").addEventListener("click", async () => {
    try {
      const out = await aesGcmDecrypt($("aes-key").value, $("aes-input").value);
      setOutput("aes-plain-out", out);
    } catch (e) {
      setOutput("aes-plain-out", String(e?.message ?? e));
    }
  });

  $("b64-encode").addEventListener("click", () => {
    try {
      setOutput("b64-out", base64EncodeText($("b64-in").value));
    } catch (e) {
      setOutput("b64-out", String(e?.message ?? e));
    }
  });

  $("b64-decode").addEventListener("click", () => {
    try {
      setOutput("b64-out", base64DecodeToText($("b64-in").value));
    } catch (e) {
      setOutput("b64-out", String(e?.message ?? e));
    }
  });
}

async function init() {
  handleTabs();
  handleStrength();
  handleGenerator();
  handleCrypto();

  try {
    commonSet = await loadCommonPasswords("assets/common_passwords.txt");
  } catch {
    commonSet = new Set();
  }

  try {
    wordSet = await loadWords("assets/words_en.txt");
  } catch {
    wordSet = new Set();
  }
}

await init();
