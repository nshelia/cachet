const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const BASE64URL = /^[A-Za-z0-9_-]*$/;

export function encodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function encodeText(text: string): string {
  return encodeBytes(encoder.encode(text));
}

export function encodeJson(value: unknown): string {
  return encodeText(JSON.stringify(value));
}

/** Returns undefined instead of throwing so callers can attach their own context. */
export function decodeBytes(input: string): Uint8Array | undefined {
  if (!BASE64URL.test(input) || input.length % 4 === 1) return undefined;
  const padded = input.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((input.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function decodeJson(input: string): unknown {
  const bytes = decodeBytes(input);
  if (bytes === undefined) return undefined;
  try {
    return JSON.parse(decoder.decode(bytes));
  } catch {
    return undefined;
  }
}

export function toBytes(text: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(text);
}
