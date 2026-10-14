import { decodeJson, encodeBytes, toBytes } from "./base64url.js";
import { SdJwtError } from "./errors.js";
import { isPlainObject, parseJws, type JsonObject, type JwsHeader, type ParsedJws } from "./jws.js";

export interface Disclosure {
  /** The disclosure exactly as it appears in the token. */
  readonly encoded: string;
  /** The digest the credential uses to reference this disclosure. */
  readonly digest: string;
  readonly salt: string;
  /** The claim name, or undefined for an array element. */
  readonly name: string | undefined;
  readonly value: unknown;
}

export interface KeyBinding {
  readonly header: JwsHeader;
  readonly payload: JsonObject;
  /** The audience the holder signed for. */
  readonly audience: unknown;
  readonly nonce: unknown;
  readonly issuedAt: Date | undefined;
}

export interface DecodedSdJwt {
  /** Every claim the holder chose to reveal, merged into one plain object. */
  readonly claims: JsonObject;
  /** The credential type, e.g. "urn:eudi:pid:1". */
  readonly vct: string | undefined;
  readonly issuer: string | undefined;
  readonly issuedAt: Date | undefined;
  readonly expiresAt: Date | undefined;
  readonly header: JwsHeader;
  /** The signed payload as issued, with digests in place of hidden claims. */
  readonly payload: JsonObject;
  readonly disclosures: readonly Disclosure[];
  /** Present when the holder proved possession of the credential's key. */
  readonly keyBinding: KeyBinding | undefined;
}

/** @internal Everything `verify` needs on top of the public result. */
export interface ParsedSdJwt {
  readonly decoded: DecodedSdJwt;
  readonly issuerJws: ParsedJws;
  readonly keyBindingJws: ParsedJws | undefined;
  /** The `<issuer-jwt>~<disclosure>~...~` prefix that `sd_hash` covers. */
  readonly presentation: string;
  readonly hashAlgorithm: string;
}

const HASH_ALGORITHMS: Record<string, string> = { "sha-256": "SHA-256", "sha-384": "SHA-384", "sha-512": "SHA-512" };

export async function hash(input: string, algorithm: string): Promise<string> {
  const name = HASH_ALGORITHMS[algorithm];
  if (name === undefined) {
    throw new SdJwtError("unsupported_algorithm", `The hash algorithm "${algorithm}" isn't supported. Use sha-256, sha-384 or sha-512.`);
  }
  return encodeBytes(new Uint8Array(await crypto.subtle.digest(name, toBytes(input))));
}

function toDate(seconds: unknown): Date | undefined {
  return typeof seconds === "number" ? new Date(seconds * 1000) : undefined;
}

async function parseDisclosure(encoded: string, hashAlgorithm: string): Promise<Disclosure> {
  const value = decodeJson(encoded);
  const short = encoded.length > 24 ? `${encoded.slice(0, 24)}…` : encoded;
  if (!Array.isArray(value) || (value.length !== 2 && value.length !== 3) || typeof value[0] !== "string") {
    throw new SdJwtError("invalid_disclosure", `Disclosure "${short}" isn't a [salt, name, value] or [salt, value] array.`);
  }
  const name = value.length === 3 ? value[1] : undefined;
  if (value.length === 3 && typeof name !== "string") {
    throw new SdJwtError("invalid_disclosure", `Disclosure "${short}" has a claim name that isn't a string.`);
  }
  if (name === "_sd" || name === "...") {
    throw new SdJwtError("invalid_disclosure", `Disclosure "${short}" uses the reserved claim name "${name}".`);
  }
  return {
    encoded,
    digest: await hash(encoded, hashAlgorithm),
    salt: value[0],
    name,
    value: value[value.length - 1],
  };
}

function reconstruct(node: unknown, byDigest: ReadonlyMap<string, Disclosure>, used: Set<string>): unknown {
  if (Array.isArray(node)) {
    const result: unknown[] = [];
    for (const element of node) {
      if (isPlainObject(element) && Object.keys(element).length === 1 && typeof element["..."] === "string") {
        const disclosure = claim(element["..."], byDigest, used);
        if (disclosure === undefined) continue; // Hidden element or decoy.
        if (disclosure.name !== undefined) {
          throw new SdJwtError("invalid_disclosure", `Claim "${disclosure.name}" is disclosed as an array element.`);
        }
        result.push(reconstruct(disclosure.value, byDigest, used));
      } else {
        result.push(reconstruct(element, byDigest, used));
      }
    }
    return result;
  }

  if (!isPlainObject(node)) return node;

  const result: JsonObject = {};
  for (const [key, value] of Object.entries(node)) {
    if (key !== "_sd" && key !== "_sd_alg") result[key] = reconstruct(value, byDigest, used);
  }
  const digests = node._sd;
  if (digests === undefined) return result;
  if (!Array.isArray(digests)) {
    throw new SdJwtError("malformed", `"_sd" must be an array of digests.`);
  }
  for (const digest of digests) {
    const disclosure = claim(digest, byDigest, used);
    if (disclosure === undefined) continue;
    if (disclosure.name === undefined) {
      throw new SdJwtError("invalid_disclosure", "An array element disclosure is referenced as an object property.");
    }
    if (Object.hasOwn(result, disclosure.name)) {
      throw new SdJwtError("invalid_disclosure", `Claim "${disclosure.name}" is both disclosed and present in the clear.`);
    }
    result[disclosure.name] = reconstruct(disclosure.value, byDigest, used);
  }
  return result;
}

function claim(digest: unknown, byDigest: ReadonlyMap<string, Disclosure>, used: Set<string>): Disclosure | undefined {
  if (typeof digest !== "string") throw new SdJwtError("malformed", "A disclosure digest isn't a string.");
  const disclosure = byDigest.get(digest);
  if (disclosure === undefined) return undefined;
  if (used.has(digest)) {
    throw new SdJwtError("invalid_disclosure", `Digest "${digest}" is referenced more than once.`);
  }
  used.add(digest);
  return disclosure;
}

/** @internal */
export async function parse(token: string): Promise<ParsedSdJwt> {
  if (typeof token !== "string" || token.trim() === "") {
    throw new SdJwtError("malformed", "Expected an SD-JWT string, got nothing.");
  }
  const trimmed = token.trim();
  if (!trimmed.includes("~")) {
    throw new SdJwtError(
      "malformed",
      "This looks like a plain JWT, not an SD-JWT.",
      `SD-JWTs separate the issuer JWT and its disclosures with "~", and a token without disclosures still ends with "~".`,
    );
  }

  const parts = trimmed.split("~");
  const issuerJws = parseJws(parts[0]!, "credential");
  const lastPart = parts[parts.length - 1]!;
  const keyBindingJws = lastPart === "" ? undefined : parseJws(lastPart, "key binding JWT");
  const encodedDisclosures = parts.slice(1, -1);
  const presentation = trimmed.slice(0, trimmed.lastIndexOf("~") + 1);

  const { payload } = issuerJws;
  const hashAlgorithm = payload._sd_alg === undefined ? "sha-256" : payload._sd_alg;
  if (typeof hashAlgorithm !== "string") throw new SdJwtError("malformed", `"_sd_alg" must be a string.`);

  const disclosures = await Promise.all(encodedDisclosures.map((encoded) => parseDisclosure(encoded, hashAlgorithm)));
  const byDigest = new Map<string, Disclosure>();
  for (const disclosure of disclosures) {
    if (byDigest.has(disclosure.digest)) {
      throw new SdJwtError("invalid_disclosure", `The same disclosure appears twice ("${disclosure.name ?? "array element"}").`);
    }
    byDigest.set(disclosure.digest, disclosure);
  }

  const used = new Set<string>();
  const claims = reconstruct(payload, byDigest, used) as JsonObject;
  const unused = disclosures.find((disclosure) => !used.has(disclosure.digest));
  if (unused !== undefined) {
    throw new SdJwtError(
      "invalid_disclosure",
      `Disclosure "${unused.name ?? "array element"}" isn't referenced by the credential.`,
      "It was altered or doesn't belong to this credential.",
    );
  }

  const keyBinding: KeyBinding | undefined = keyBindingJws && {
    header: keyBindingJws.header,
    payload: keyBindingJws.payload,
    audience: keyBindingJws.payload.aud,
    nonce: keyBindingJws.payload.nonce,
    issuedAt: toDate(keyBindingJws.payload.iat),
  };

  return {
    decoded: {
      claims,
      vct: typeof payload.vct === "string" ? payload.vct : undefined,
      issuer: typeof payload.iss === "string" ? payload.iss : undefined,
      issuedAt: toDate(payload.iat),
      expiresAt: toDate(payload.exp),
      header: issuerJws.header,
      payload,
      disclosures,
      keyBinding,
    },
    issuerJws,
    keyBindingJws,
    presentation,
    hashAlgorithm,
  };
}

/**
 * Reads an SD-JWT without checking any signatures.
 *
 * Use it to inspect and debug credentials. Never trust the result for access
 * decisions — use `verify` for that.
 */
export async function decode(token: string): Promise<DecodedSdJwt> {
  return (await parse(token)).decoded;
}
