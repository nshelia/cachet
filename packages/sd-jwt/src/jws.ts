import { decodeBytes, decodeJson, encodeBytes, encodeJson, toBytes } from "./base64url.js";
import { SdJwtError } from "./errors.js";

export type JsonObject = { [key: string]: unknown };

export interface JwsHeader extends JsonObject {
  alg: string;
  typ?: string;
  kid?: string;
  x5c?: string[];
}

export interface ParsedJws {
  readonly header: JwsHeader;
  readonly payload: JsonObject;
  readonly compact: string;
  readonly signingInput: string;
  readonly signature: Uint8Array<ArrayBuffer>;
}

export type SigningAlgorithm = "ES256" | "ES384" | "ES512" | "EdDSA" | "Ed25519" | "PS256" | "RS256";

interface AlgorithmParams {
  importParams: EcKeyImportParams | RsaHashedImportParams | Algorithm;
  verifyParams: EcdsaParams | RsaPssParams | Algorithm;
}

const ALGORITHMS: Record<SigningAlgorithm, AlgorithmParams> = {
  ES256: { importParams: { name: "ECDSA", namedCurve: "P-256" }, verifyParams: { name: "ECDSA", hash: "SHA-256" } },
  ES384: { importParams: { name: "ECDSA", namedCurve: "P-384" }, verifyParams: { name: "ECDSA", hash: "SHA-384" } },
  ES512: { importParams: { name: "ECDSA", namedCurve: "P-521" }, verifyParams: { name: "ECDSA", hash: "SHA-512" } },
  EdDSA: { importParams: { name: "Ed25519" }, verifyParams: { name: "Ed25519" } },
  Ed25519: { importParams: { name: "Ed25519" }, verifyParams: { name: "Ed25519" } },
  PS256: { importParams: { name: "RSA-PSS", hash: "SHA-256" }, verifyParams: { name: "RSA-PSS", saltLength: 32 } },
  RS256: { importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verifyParams: { name: "RSASSA-PKCS1-v1_5" } },
};

export const SUPPORTED_ALGORITHMS = Object.keys(ALGORITHMS) as SigningAlgorithm[];

export function isPlainObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseJws(compact: string, label: string): ParsedJws {
  const parts = compact.split(".");
  if (parts.length !== 3) {
    throw new SdJwtError("malformed", `The ${label} isn't a compact JWS (expected 3 dot-separated parts, got ${parts.length}).`);
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
  const header = decodeJson(encodedHeader);
  const payload = decodeJson(encodedPayload);
  const signature = decodeBytes(encodedSignature);
  if (!isPlainObject(header) || typeof header.alg !== "string") {
    throw new SdJwtError("malformed", `The ${label} header isn't valid base64url-encoded JSON with an "alg".`);
  }
  if (!isPlainObject(payload)) {
    throw new SdJwtError("malformed", `The ${label} payload isn't a base64url-encoded JSON object.`);
  }
  if (signature === undefined) {
    throw new SdJwtError("malformed", `The ${label} signature isn't valid base64url.`);
  }
  return {
    header: header as JwsHeader,
    payload,
    compact,
    signingInput: `${encodedHeader}.${encodedPayload}`,
    signature: new Uint8Array(signature),
  };
}

function algorithmParams(alg: string, allowed: readonly string[], label: string): AlgorithmParams {
  if (!allowed.includes(alg) || !(alg in ALGORITHMS)) {
    throw new SdJwtError(
      "unsupported_algorithm",
      `The ${label} is signed with "${alg}", which isn't allowed.`,
      `Allowed algorithms: ${allowed.join(", ")}.`,
    );
  }
  return ALGORITHMS[alg as SigningAlgorithm];
}

/** Keeps only the public members of a JWK, so a private key passed by mistake can't be misused. */
function publicJwk(jwk: JsonWebKey): JsonWebKey {
  switch (jwk.kty) {
    case "EC":
      return { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y };
    case "OKP":
      return { kty: "OKP", crv: jwk.crv, x: jwk.x };
    case "RSA":
      return { kty: "RSA", n: jwk.n, e: jwk.e };
    default:
      throw new SdJwtError("invalid_key", `Unsupported JWK key type "${String(jwk.kty)}". Use an EC, OKP or RSA public key.`);
  }
}

export function isCryptoKey(key: unknown): key is CryptoKey {
  return typeof CryptoKey !== "undefined" && key instanceof CryptoKey;
}

export async function verifyJws(
  jws: ParsedJws,
  key: JsonWebKey | CryptoKey,
  allowed: readonly string[],
  label: string,
): Promise<boolean> {
  const params = algorithmParams(jws.header.alg, allowed, label);
  let cryptoKey: CryptoKey;
  try {
    cryptoKey = isCryptoKey(key)
      ? key
      : await crypto.subtle.importKey("jwk", publicJwk(key), params.importParams, false, ["verify"]);
  } catch (error) {
    if (error instanceof SdJwtError) throw error;
    throw new SdJwtError("invalid_key", `The key for the ${label} can't be used with "${jws.header.alg}".`);
  }
  try {
    return await crypto.subtle.verify(params.verifyParams, cryptoKey, jws.signature, toBytes(jws.signingInput));
  } catch {
    throw new SdJwtError("invalid_key", `The key for the ${label} doesn't match its "${jws.header.alg}" algorithm.`);
  }
}

/** ES256 only. Used by the testing helpers; production issuance belongs in a dedicated issuer. */
export async function signEs256(header: JsonObject, payload: JsonObject, privateKey: CryptoKey): Promise<string> {
  const signingInput = `${encodeJson({ ...header, alg: "ES256" })}.${encodeJson(payload)}`;
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, toBytes(signingInput));
  return `${signingInput}.${encodeBytes(new Uint8Array(signature))}`;
}
