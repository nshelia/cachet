/**
 * Test helpers: a throwaway issuer and wallet, so you can build and test a
 * verifier before you have real EU wallet credentials.
 *
 * Keys live in memory and are regenerated on every call. Never use these in production.
 */
import { encodeBytes, encodeJson } from "./base64url.js";
import { hash, parse } from "./decode.js";
import { isPlainObject, signEs256, type JsonObject } from "./jws.js";

export interface IssueOptions {
  /** Credential type. Defaults to "urn:eudi:pid:1". */
  vct?: string;
  /** Binds the credential to a holder. Pass `wallet.publicKey`. */
  holder?: JsonWebKey;
  /** Lifetime in seconds. Defaults to one year. */
  expiresIn?: number;
  /** Issuance time. Defaults to now. */
  issuedAt?: Date;
  /**
   * Which claims the holder can hide: "all" (the default), "none", or a list
   * of dotted paths such as ["birthdate", "address.street_address"].
   */
  disclosable?: "all" | "none" | readonly string[];
}

export interface TestIssuer {
  readonly issuer: string;
  /** Pass this to `verify({ issuerKey })`. */
  readonly publicKey: JsonWebKey;
  /** Issues an SD-JWT VC. The result has no key binding; present it with a wallet. */
  issue(claims: JsonObject, options?: IssueOptions): Promise<string>;
}

export interface PresentOptions {
  nonce: string;
  audience: string;
  /** Dotted paths to reveal, e.g. ["age_equal_or_over.18"]. Defaults to everything. */
  disclose?: readonly string[];
  /** Signing time of the key binding. Defaults to now. */
  issuedAt?: Date;
}

export interface TestWallet {
  /** Pass this as `holder` when issuing. */
  readonly publicKey: JsonWebKey;
  /** Creates a key-bound presentation revealing only the claims you ask for. */
  present(credential: string, options: PresentOptions): Promise<string>;
}

/** A PID shaped like the EU wallet's SD-JWT VC person identification data. */
export const samplePid = {
  given_name: "Erika",
  family_name: "Mustermann",
  birthdate: "1964-08-12",
  nationalities: ["DE"],
  age_equal_or_over: { "12": true, "14": true, "16": true, "18": true, "21": true, "65": false },
  address: { street_address: "Heidestraße 17", locality: "Köln", postal_code: "51147", country: "DE" },
} satisfies JsonObject;

const REGISTERED_CLAIMS = new Set(["iss", "iat", "exp", "nbf", "vct", "cnf", "status", "sub"]);

async function generateKeyPair(): Promise<{ privateKey: CryptoKey; publicKey: JsonWebKey }> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return { privateKey: pair.privateKey, publicKey: { kty, crv, x, y } };
}

function salt(): string {
  return encodeBytes(crypto.getRandomValues(new Uint8Array(16)));
}

function seconds(date: Date): number {
  return Math.floor(date.getTime() / 1000);
}

export async function createTestIssuer(issuer = "https://issuer.example"): Promise<TestIssuer> {
  const { privateKey, publicKey } = await generateKeyPair();

  return {
    issuer,
    publicKey,
    async issue(claims, options = {}) {
      const { disclosable = "all" } = options;
      const disclosures: string[] = [];
      const shouldDisclose = (path: string) =>
        disclosable === "all" || (disclosable !== "none" && disclosable.includes(path));

      const conceal = async (node: JsonObject, path: string): Promise<JsonObject> => {
        const result: JsonObject = {};
        const digests: string[] = [];
        for (const [name, raw] of Object.entries(node)) {
          const claimPath = path ? `${path}.${name}` : name;
          const value = isPlainObject(raw) ? await conceal(raw, claimPath) : raw;
          const topLevelRegistered = path === "" && REGISTERED_CLAIMS.has(name);
          if (!topLevelRegistered && shouldDisclose(claimPath)) {
            const disclosure = encodeJson([salt(), name, value]);
            disclosures.push(disclosure);
            digests.push(await hash(disclosure, "sha-256"));
          } else {
            result[name] = value;
          }
        }
        // Sorted so the digest order doesn't reveal the original claim order.
        if (digests.length > 0) result._sd = digests.sort();
        return result;
      };

      const issuedAt = seconds(options.issuedAt ?? new Date());
      const payload: JsonObject = {
        ...(await conceal(claims, "")),
        iss: issuer,
        iat: issuedAt,
        exp: issuedAt + (options.expiresIn ?? 365 * 86_400),
        vct: options.vct ?? "urn:eudi:pid:1",
        _sd_alg: "sha-256",
      };
      if (options.holder) payload.cnf = { jwk: options.holder };

      const jwt = await signEs256({ typ: "dc+sd-jwt" }, payload, privateKey);
      return [jwt, ...disclosures, ""].join("~");
    },
  };
}

export async function createTestWallet(): Promise<TestWallet> {
  const { privateKey, publicKey } = await generateKeyPair();

  return {
    publicKey,
    async present(credential, options) {
      const { decoded, issuerJws, hashAlgorithm } = await parse(credential);
      const byDigest = new Map(decoded.disclosures.map((disclosure) => [disclosure.digest, disclosure]));
      const requested = options.disclose;
      const wanted = (path: string) =>
        requested === undefined ||
        requested.some((target) => target === path || target.startsWith(`${path}.`) || path.startsWith(`${target}.`));

      const selected: string[] = [];
      const walk = (node: unknown, path: string): void => {
        if (Array.isArray(node)) {
          for (const element of node) {
            const digest = isPlainObject(element) ? element["..."] : undefined;
            const disclosure = typeof digest === "string" ? byDigest.get(digest) : undefined;
            if (disclosure && wanted(path)) {
              selected.push(disclosure.encoded);
              walk(disclosure.value, path);
            } else if (!disclosure) {
              walk(element, path);
            }
          }
          return;
        }
        if (!isPlainObject(node)) return;
        for (const [key, value] of Object.entries(node)) {
          if (key !== "_sd") walk(value, path ? `${path}.${key}` : key);
        }
        for (const digest of Array.isArray(node._sd) ? node._sd : []) {
          const disclosure = typeof digest === "string" ? byDigest.get(digest) : undefined;
          if (disclosure?.name === undefined) continue;
          const claimPath = path ? `${path}.${disclosure.name}` : disclosure.name;
          if (wanted(claimPath)) {
            selected.push(disclosure.encoded);
            walk(disclosure.value, claimPath);
          }
        }
      };
      walk(decoded.payload, "");

      const presentation = [issuerJws.compact, ...selected, ""].join("~");
      const keyBinding = await signEs256(
        { typ: "kb+jwt" },
        {
          iat: seconds(options.issuedAt ?? new Date()),
          aud: options.audience,
          nonce: options.nonce,
          sd_hash: await hash(presentation, hashAlgorithm),
        },
        privateKey,
      );
      return presentation + keyBinding;
    },
  };
}
