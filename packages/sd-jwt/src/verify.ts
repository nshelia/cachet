import { hash, parse, type DecodedSdJwt } from "./decode.js";
import { SdJwtError } from "./errors.js";
import { isPlainObject, SUPPORTED_ALGORITHMS, verifyJws, type JsonObject, type JwsHeader, type SigningAlgorithm } from "./jws.js";

export type IssuerKey = JsonWebKey | CryptoKey;

/**
 * Picks the issuer key for a credential, e.g. by looking up `iss` in your
 * trust list or validating the `x5c` certificate chain in the header.
 */
export type IssuerKeyResolver = (credential: { header: JwsHeader; payload: JsonObject }) => IssuerKey | Promise<IssuerKey>;

interface CommonOptions {
  /** The issuer's public key, or a function that returns the key for a given credential. */
  issuerKey: IssuerKey | IssuerKeyResolver;
  /** Only accept these credential types, e.g. "urn:eudi:pid:1". */
  vct?: string | readonly string[];
  /** Signing algorithms you accept. Defaults to every supported asymmetric algorithm. */
  algorithms?: readonly SigningAlgorithm[];
  /** The time to verify against. Defaults to now. */
  now?: Date;
  /** Allowed clock skew in seconds. Defaults to 60. */
  clockTolerance?: number;
  /** How old a key binding may be, in seconds. Defaults to 300. */
  keyBindingMaxAge?: number;
}

interface KeyBoundOptions extends CommonOptions {
  /** The nonce you sent with the request. Protects against replayed presentations. */
  nonce: string;
  /** Your identifier as the verifier, e.g. "https://shop.example" or your client_id. */
  audience: string;
  requireKeyBinding?: true;
}

interface UnboundOptions extends CommonOptions {
  /**
   * Accept credentials without proof that the presenter holds them.
   * Anyone who copies such a credential can replay it, so only turn this off
   * for credentials that aren't bound to a holder.
   */
  requireKeyBinding: false;
  nonce?: string;
  audience?: string;
}

export type VerifyOptions = KeyBoundOptions | UnboundOptions;

export interface VerifiedSdJwt extends DecodedSdJwt {
  /** The holder's public key from `cnf.jwk`, if the credential is bound to one. */
  readonly holderKey: JsonWebKey | undefined;
}

function describeSeconds(seconds: number): string {
  const units: [string, number][] = [["day", 86_400], ["hour", 3_600], ["minute", 60]];
  for (const [unit, size] of units) {
    const count = Math.floor(seconds / size);
    if (count >= 1) return `${count} ${unit}${count === 1 ? "" : "s"}`;
  }
  return `${Math.max(0, Math.round(seconds))} seconds`;
}

function readTime(payload: JsonObject, claim: "exp" | "nbf" | "iat", label: string): number | undefined {
  const value = payload[claim];
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new SdJwtError("malformed", `The ${label} "${claim}" must be a number of seconds since the epoch.`);
  }
  return value;
}

/**
 * Verifies an SD-JWT presentation and returns the claims the holder disclosed.
 *
 * Checks the issuer signature, every disclosure, the validity window and, unless
 * you opt out, the holder's key binding against your nonce and audience.
 * Throws an `SdJwtError` with a machine-readable `code` when anything is off.
 */
export async function verify(token: string, options: VerifyOptions): Promise<VerifiedSdJwt> {
  const { decoded, issuerJws, keyBindingJws, presentation, hashAlgorithm } = await parse(token);
  const allowed = options.algorithms ?? SUPPORTED_ALGORITHMS;
  const now = Math.floor((options.now ?? new Date()).getTime() / 1000);
  const tolerance = options.clockTolerance ?? 60;

  const issuerKey =
    typeof options.issuerKey === "function"
      ? await options.issuerKey({ header: decoded.header, payload: decoded.payload })
      : options.issuerKey;
  if (!(await verifyJws(issuerJws, issuerKey, allowed, "credential"))) {
    throw new SdJwtError(
      "invalid_signature",
      "The credential's signature doesn't match the issuer key.",
      "Either the credential was altered or it was issued by someone else.",
    );
  }

  const { payload } = decoded;
  const exp = readTime(payload, "exp", "credential");
  if (exp !== undefined && now - tolerance >= exp) {
    throw new SdJwtError("expired", `The credential expired ${describeSeconds(now - exp)} ago.`);
  }
  const nbf = readTime(payload, "nbf", "credential");
  if (nbf !== undefined && now + tolerance < nbf) {
    throw new SdJwtError("not_yet_valid", `The credential only becomes valid in ${describeSeconds(nbf - now)}.`);
  }

  if (options.vct !== undefined) {
    const accepted: readonly string[] = typeof options.vct === "string" ? [options.vct] : options.vct;
    if (decoded.vct === undefined || !accepted.includes(decoded.vct)) {
      throw new SdJwtError(
        "unexpected_type",
        `Expected a credential of type ${accepted.map((type) => `"${type}"`).join(" or ")}, got "${decoded.vct ?? "none"}".`,
      );
    }
  }

  const confirmation = payload.cnf;
  const holderKey = isPlainObject(confirmation) && isPlainObject(confirmation.jwk) ? (confirmation.jwk as JsonWebKey) : undefined;

  if (keyBindingJws === undefined) {
    if (options.requireKeyBinding === false) return { ...decoded, holderKey };
    throw new SdJwtError(
      "key_binding_required",
      "The presentation has no key binding, so there's no proof the presenter holds this credential.",
      "Ask the wallet for a key-bound presentation, or pass `requireKeyBinding: false` if the credential isn't holder-bound.",
    );
  }

  if (keyBindingJws.header.typ !== "kb+jwt") {
    throw new SdJwtError("key_binding_invalid", `The key binding JWT has type "${keyBindingJws.header.typ ?? "none"}", expected "kb+jwt".`);
  }
  if (holderKey === undefined) {
    throw new SdJwtError("key_binding_invalid", "The presentation has a key binding, but the credential names no holder key (cnf.jwk).");
  }
  if (!(await verifyJws(keyBindingJws, holderKey, allowed, "key binding JWT"))) {
    throw new SdJwtError("key_binding_invalid", "The key binding wasn't signed by the credential's holder.");
  }

  const kb = keyBindingJws.payload;
  const iat = readTime(kb, "iat", "key binding");
  if (iat === undefined) throw new SdJwtError("key_binding_invalid", `The key binding has no "iat".`);
  if (iat > now + tolerance) {
    throw new SdJwtError("key_binding_invalid", `The key binding was signed ${describeSeconds(iat - now)} in the future.`, "Check the device clocks.");
  }
  const maxAge = options.keyBindingMaxAge ?? 300;
  if (now - iat > maxAge + tolerance) {
    throw new SdJwtError("key_binding_invalid", `The key binding is ${describeSeconds(now - iat)} old; the limit is ${describeSeconds(maxAge)}.`);
  }
  if (kb.sd_hash !== (await hash(presentation, hashAlgorithm))) {
    throw new SdJwtError("key_binding_invalid", "The presentation was modified after the holder signed it (sd_hash mismatch).");
  }
  if (options.audience !== undefined && kb.aud !== options.audience) {
    throw new SdJwtError("audience_mismatch", `The presentation is meant for "${String(kb.aud)}", not "${options.audience}".`);
  }
  if (options.nonce !== undefined && kb.nonce !== options.nonce) {
    throw new SdJwtError("nonce_mismatch", "The nonce doesn't match the one you sent.", "This can be a replayed presentation.");
  }

  return { ...decoded, holderKey };
}
