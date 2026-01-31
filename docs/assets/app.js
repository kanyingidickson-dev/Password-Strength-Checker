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

function setOutput(id, value, options) {
  const el = $(id);
  const text = value || "—";
  el.textContent = text;
  el.classList.remove("is-success", "is-error", "is-empty");

  if (!value || text === "—") {
    el.classList.add("is-empty");
    return;
  }

  if (options?.status === "error") {
    el.classList.add("is-error");
  } else if (options?.status === "success") {
    el.classList.add("is-success");
  }
}

function setPill(id, text, tone = "is-neutral") {
  const el = $(id);
  el.textContent = text;
  el.classList.remove("is-good", "is-warn", "is-bad", "is-neutral");
  if (tone) el.classList.add(tone);
}

function normalizeHashText(s) {
  return String(s).trim().replaceAll(/\s+/g, "").toLowerCase();
}

function normalizeBase64Text(s) {
  return String(s).trim().replaceAll(/\s+/g, "");
}

function setMeter(score) {
  const el = $("meter-fill");
  const clamped = Math.max(0, Math.min(100, score));
  el.style.width = `${clamped}%`;
  el.classList.remove("is-good", "is-warn", "is-bad");
  const tone = clamped >= 80 ? "is-good" : clamped >= 50 ? "is-warn" : "is-bad";
  el.classList.add(tone);
}

function renderReasons(items) {
  const ul = $("reasons");
  ul.replaceChildren();

  const groups = new Map([
    ["Length", []],
    ["Entropy", []],
    ["Patterns", []],
    ["Dictionary", []],
    ["Reuse", []],
    ["Other", []],
  ]);

  for (const r of items ?? []) {
    const s = String(r);

    if (/\blength\b|Too short \(</i.test(s) || /Good length|Acceptable length/i.test(s)) {
      groups.get("Length").push(s);
    } else if (/entropy/i.test(s)) {
      groups.get("Entropy").push(s);
    } else if (/^Pattern detected:/i.test(s) || /keyboard-walk|sequential|repeated/i.test(s)) {
      groups.get("Patterns").push(s);
    } else if (/^Dictionary word detected:/i.test(s) || /dictionary/i.test(s)) {
      groups.get("Dictionary").push(s);
    } else if (/reuse|reused|local history/i.test(s)) {
      groups.get("Reuse").push(s);
    } else {
      groups.get("Other").push(s);
    }
  }

  for (const [name, arr] of groups.entries()) {
    if (!arr || arr.length === 0) continue;

    const header = document.createElement("li");
    header.className = "reason-header";
    header.textContent = name;
    ul.appendChild(header);

    for (const s of arr) {
      const li = document.createElement("li");
      li.textContent = s;
      ul.appendChild(li);
    }
  }

  if (!ul.firstChild) {
    const li = document.createElement("li");
    li.className = "is-empty";
    li.textContent = "Analyze a password to see the detailed feedback here.";
    ul.appendChild(li);
  }
}

async function copyToClipboard(text) {
  if (!text || text === "—") return;
  await navigator.clipboard.writeText(text);
}

async function copyWithFeedback(button, text) {
  if (!button) return;

  const originalText = button.textContent;
  button.disabled = true;
  button.classList.remove("is-copied", "is-error");

  try {
    await copyToClipboard(text);
    button.textContent = "Copied!";
    button.classList.add("is-copied");
  } catch {
    button.textContent = "Copy failed";
    button.classList.add("is-error");
  }

  window.setTimeout(() => {
    button.textContent = originalText;
    button.classList.remove("is-copied", "is-error");
    button.disabled = false;
  }, 1200);
}

function installSecretToggle(toggleButton, input, options) {
  if (!toggleButton || !input) return;
  const timeoutMs = Number(options?.timeoutMs ?? 10_000);
  let hideTimer = null;

  function setHidden() {
    input.type = "password";
    toggleButton.textContent = "Show";
    if (hideTimer) {
      window.clearTimeout(hideTimer);
      hideTimer = null;
    }
  }

  function setVisible() {
    input.type = "text";
    toggleButton.textContent = "Hide";
    if (hideTimer) window.clearTimeout(hideTimer);
    hideTimer = window.setTimeout(() => setHidden(), timeoutMs);
  }

  toggleButton.addEventListener("click", () => {
    const visible = input.type === "text";
    if (visible) setHidden();
    else setVisible();
  });

  window.addEventListener("pagehide", () => setHidden());
}

function autoGrowTextarea(el) {
  if (!el) return;
  el.style.height = "auto";
  el.style.height = `${el.scrollHeight}px`;
}

function installAutoGrowTextareas() {
  for (const el of document.querySelectorAll("textarea")) {
    autoGrowTextarea(el);
    el.addEventListener("input", () => autoGrowTextarea(el));
  }
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
  const tone = analysis.score >= 80 ? "is-good" : analysis.score >= 50 ? "is-warn" : "is-bad";
  setPill("label", analysis.label, tone);
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

  if ($maybe("reasons")) {
    renderReasons(null);
  }

  const advanced = $maybe("advanced-details");
  if (advanced) {
    const mm = window.matchMedia("(max-width: 900px)");
    const apply = () => {
      if (mm.matches) advanced.open = false;
      else advanced.open = true;
    };
    apply();
    mm.addEventListener("change", apply);
  }

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

  installSecretToggle($maybe("toggle-visibility"), pwd, { timeoutMs: 10_000 });
  installSecretToggle($maybe("toggle-pepper"), pepper, { timeoutMs: 10_000 });

  $("analyze").addEventListener("click", async () => {
    try {
      await runAnalysis(pwd.value, { pepper: pepper.value });
    } catch (e) {
      renderReasons([String(e?.message ?? e)]);
    }
  });

  const analyzeAdvanced = $maybe("analyze-advanced");
  if (analyzeAdvanced) {
    analyzeAdvanced.addEventListener("click", async () => {
      try {
        await runAnalysis(pwd.value, { pepper: pepper.value });
      } catch (e) {
        renderReasons([String(e?.message ?? e)]);
      }
    });
  }

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
      setOutput("generated", lastGenerated, { status: "success" });
    } catch (e) {
      setOutput("generated", String(e?.message ?? e), { status: "error" });
    }
  });

  $("copy-generated").addEventListener("click", async () => {
    await copyWithFeedback($("copy-generated"), $("generated").textContent ?? "");
  });

  $("analyze-generated").addEventListener("click", async () => {
    if (!lastGenerated) return;
    sessionStorage.setItem("psc_analyze_password", lastGenerated);
    window.location.href = "./index.html";
  });
}

function handleHashPage() {
  if (!$maybe("do-hash")) return;
  installSecretToggle($maybe("toggle-hmac-key"), $maybe("hmac-key"), { timeoutMs: 10_000 });

  function updateHashMatch() {
    const expectedEl = $maybe("hash-expected");
    const outEl = $maybe("hash-out");
    const matchEl = $maybe("hash-match");
    if (!expectedEl || !outEl || !matchEl) return;

    const expected = String(expectedEl.value ?? "").trim();
    const out = String(outEl.textContent ?? "");

    const formatEl = $maybe("hash-format");
    const format = String(formatEl?.value ?? "hex");

    if (!expected) {
      setPill("hash-match", "—", "is-neutral");
      return;
    }

    if (!out || out === "—") {
      setPill("hash-match", "—", "is-neutral");
      return;
    }

    const normalize = format === "base64" ? normalizeBase64Text : normalizeHashText;
    const ok = normalize(out) === normalize(expected);
    setPill("hash-match", ok ? "match" : "no match", ok ? "is-good" : "is-bad");
  }

  $("do-hash").addEventListener("click", async () => {
    const text = $("crypto-text").value;
    const algo = $("hash-algo").value;
    const format = $("hash-format").value;
    const key = $("hmac-key").value;

    try {
      const out = key
        ? await hmacText(algo, key, text, format)
        : await digestText(algo, text, format);
      setOutput("hash-out", out, { status: "success" });

      updateHashMatch();
    } catch (e) {
      setOutput("hash-out", String(e?.message ?? e), { status: "error" });
      setPill("hash-match", "—", "is-neutral");
    }
  });

  const expectedEl = $maybe("hash-expected");
  if (expectedEl) {
    expectedEl.addEventListener("input", () => updateHashMatch());
    expectedEl.addEventListener("change", () => updateHashMatch());
  }

  $("copy-hash").addEventListener("click", async () => {
    await copyWithFeedback($("copy-hash"), $("hash-out").textContent ?? "");
  });
}

function handlePbkdf2Page() {
  if (!$maybe("do-kdf")) return;
  installSecretToggle($maybe("toggle-kdf-password"), $maybe("kdf-password"), { timeoutMs: 10_000 });
  $("do-kdf").addEventListener("click", async () => {
    const pw = $("kdf-password").value;
    const salt = $("kdf-salt").value;
    const iter = Number($("kdf-iter").value);
    const len = Number($("kdf-len").value);

    try {
      const out = await pbkdf2(pw, salt, iter, len);
      setOutput("kdf-out", out, { status: "success" });
    } catch (e) {
      setOutput("kdf-out", String(e?.message ?? e), { status: "error" });
    }
  });

  $("copy-kdf").addEventListener("click", async () => {
    await copyWithFeedback($("copy-kdf"), $("kdf-out").textContent ?? "");
  });
}

function handleAesGcmPage() {
  if (!$maybe("do-encrypt")) return;
  installSecretToggle($maybe("toggle-aes-key"), $maybe("aes-key"), { timeoutMs: 10_000 });
  $("do-encrypt").addEventListener("click", async () => {
    try {
      const out = await aesGcmEncrypt($("aes-key").value, $("aes-plain").value);
      setOutput("aes-cipher", out, { status: "success" });
      $("aes-input").value = out;
      autoGrowTextarea($maybe("aes-input"));
    } catch (e) {
      setOutput("aes-cipher", String(e?.message ?? e), { status: "error" });
    }
  });

  $("copy-cipher").addEventListener("click", async () => {
    await copyWithFeedback($("copy-cipher"), $("aes-cipher").textContent ?? "");
  });

  $("do-decrypt").addEventListener("click", async () => {
    try {
      const out = await aesGcmDecrypt($("aes-key").value, $("aes-input").value);
      setOutput("aes-plain-out", out, { status: "success" });
    } catch (e) {
      setOutput("aes-plain-out", String(e?.message ?? e), { status: "error" });
    }
  });
}

function handleBase64Page() {
  if (!$maybe("b64-encode")) return;
  $("b64-encode").addEventListener("click", () => {
    try {
      setOutput("b64-out", base64EncodeText($("b64-in").value), { status: "success" });
    } catch (e) {
      setOutput("b64-out", String(e?.message ?? e), { status: "error" });
    }
  });

  $("b64-decode").addEventListener("click", () => {
    try {
      setOutput("b64-out", base64DecodeToText($("b64-in").value), { status: "success" });
    } catch (e) {
      setOutput("b64-out", String(e?.message ?? e), { status: "error" });
    }
  });

  const copyBtn = $maybe("copy-b64");
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      await copyWithFeedback(copyBtn, $("b64-out").textContent ?? "");
    });
  }
}

async function init() {
  handleNav();
  installAutoGrowTextareas();
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
