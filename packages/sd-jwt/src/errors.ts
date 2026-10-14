export type SdJwtErrorCode =
  /** The token isn't a well-formed SD-JWT. */
  | "malformed"
  /** A disclosure is invalid, duplicated, or not referenced by the credential. */
  | "invalid_disclosure"
  /** The signing or hash algorithm isn't supported or isn't allowed. */
  | "unsupported_algorithm"
  /** The key you supplied (or the holder key in `cnf.jwk`) can't be used. */
  | "invalid_key"
  /** The issuer signature doesn't match. The credential was altered or the key is wrong. */
  | "invalid_signature"
  /** The credential is past its `exp`. */
  | "expired"
  /** The credential's `nbf` is in the future. */
  | "not_yet_valid"
  /** The credential type (`vct`) isn't one you asked for. */
  | "unexpected_type"
  /** You required a key binding (the default) but the presentation has none. */
  | "key_binding_required"
  /** The key binding JWT is invalid: bad signature, wrong type, stale, or the presentation was modified. */
  | "key_binding_invalid"
  /** The key binding nonce isn't the one you issued. */
  | "nonce_mismatch"
  /** The key binding audience isn't you. */
  | "audience_mismatch";

export class SdJwtError extends Error {
  override readonly name = "SdJwtError";

  constructor(
    readonly code: SdJwtErrorCode,
    message: string,
    /** A suggestion for fixing the problem, when there is one. */
    readonly hint?: string,
  ) {
    super(hint ? `${message} ${hint}` : message);
  }
}
