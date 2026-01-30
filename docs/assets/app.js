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

function $maybe(id) {
  return document.getElementById(id);
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
let customWordSet = new Set();
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

function mergedWordSet(base, custom) {
  const merged = new Set(base ?? []);
  for (const w of custom ?? []) merged.add(w);
  return merged;
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

function handleNav() {
  const path = window.location.pathname.split("/").pop() || "index.html";
  for (const a of document.querySelectorAll(".navlink")) {
    const href = a.getAttribute("href") ?? "";
    const page = href.split("/").pop();
    a.classList.toggle("is-active", page === path);
  }
}

function handleStrength() {
  if (!$maybe("pwd")) return;
  const pwd = $("pwd");
  const pepper = $("pepper");

  $("wordlist").addEventListener("change", async () => {
    const input = $("wordlist");
    const file = input.files && input.files.length > 0 ? input.files[0] : null;
    if (!file) return;
    try {
      customWordSet = await loadUploadedWordlist(file);
      wordSet = mergedWordSet(wordSet, customWordSet);
    } catch (e) {
      renderReasons([String(e?.message ?? e)]);
    }
  });

  const dictLang = $maybe("dict-lang");
  if (dictLang) {
    dictLang.addEventListener("change", async () => {
      const lang = String(dictLang.value || "en");
      const url = lang === "es" ? "assets/words_es.txt" : lang === "fr" ? "assets/words_fr.txt" : "assets/words_en.txt";
      try {
        const base = await loadWords(url);
        wordSet = mergedWordSet(base, customWordSet);
      } catch (e) {
        wordSet = mergedWordSet(new Set(), customWordSet);
        renderReasons([String(e?.message ?? e)]);
      }
    });
  }

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

  const pending = sessionStorage.getItem("psc_analyze_password");
  if (pending) {
    sessionStorage.removeItem("psc_analyze_password");
    pwd.value = pending;
    runAnalysis(pending, { pepper: pepper.value }).catch(() => undefined);
  }
}

function handleGenerator() {
  if (!$maybe("gen-length")) return;
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
    sessionStorage.setItem("psc_analyze_password", lastGenerated);
    window.location.href = "./index.html";
  });
}

function handleHashPage() {
  if (!$maybe("do-hash")) return;
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
}

function handlePbkdf2Page() {
  if (!$maybe("do-kdf")) return;
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
}

function handleAesGcmPage() {
  if (!$maybe("do-encrypt")) return;
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
}

function handleBase64Page() {
  if (!$maybe("b64-encode")) return;
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
  handleNav();
  handleStrength();
  handleGenerator();
  handleHashPage();
  handlePbkdf2Page();
  handleAesGcmPage();
  handleBase64Page();

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
