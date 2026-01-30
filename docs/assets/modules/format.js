export function clampInt(n, min, max) {
  const x = Number.isFinite(n) ? Math.trunc(n) : min;
  return Math.min(max, Math.max(min, x));
}

export function bytesToHex(bytes) {
  const out = [];
  for (const b of bytes) {
    out.push(b.toString(16).padStart(2, "0"));
  }
  return out.join("");
}

export function hexToBytes(hex) {
  const s = hex.trim();
  if (s.length % 2 !== 0) {
    throw new Error("Invalid hex");
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
    if (!Number.isFinite(byte)) {
      throw new Error("Invalid hex");
    }
    out[i] = byte;
  }
  return out;
}

export function bytesToBase64(bytes) {
  let bin = "";
  for (const b of bytes) {
    bin += String.fromCharCode(b);
  }
  return btoa(bin);
}

export function base64ToBytes(b64) {
  const bin = atob(b64.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

export function utf8ToBytes(s) {
  return new TextEncoder().encode(s);
}

export function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}
