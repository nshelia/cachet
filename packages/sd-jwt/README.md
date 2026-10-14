# @cachet/sd-jwt

Decode and verify **SD-JWT** credentials, the format the EU Digital Identity Wallet uses for person identification data (PID), diplomas, and more.

- **Zero dependencies.** Built on standard WebCrypto, so it runs in browsers and Node 20+, and should run in any runtime with WebCrypto (Deno, Bun, edge functions).
- **Secure by default.** Key binding, nonce and audience checks are on unless you explicitly turn them off.
- **Errors you can act on.** Every failure has a stable `code` and a sentence that says what went wrong.
- **Testable today.** A built-in test issuer and wallet, so you can build your verifier before real wallets reach your users.

```sh
npm install @cachet/sd-jwt
```

## Verify a presentation

```ts
import { verify } from "@cachet/sd-jwt";

const { claims } = await verify(presentation, {
  issuerKey,                        // the issuer's public JWK, or a resolver function
  nonce: session.nonce,             // the nonce you sent with the request
  audience: "https://shop.example", // who the wallet signed the presentation for
});

claims.age_equal_or_over?.["18"]; // true
```

That's it. `verify` checks the issuer's signature, every disclosure, the validity window, and that the presenter holds the credential (the key binding). You get back only the claims the holder chose to share.

## Try it without a wallet

Real EU wallets are rolling out country by country. Meanwhile, the `testing` entry point gives you a throwaway issuer and wallet that produce the same kind of credentials:

```ts
import { verify } from "@cachet/sd-jwt";
import { createTestIssuer, createTestWallet, samplePid } from "@cachet/sd-jwt/testing";

const issuer = await createTestIssuer("https://pid.example.eu");
const wallet = await createTestWallet();

// The government issues a PID into the wallet.
const credential = await issuer.issue(samplePid, { holder: wallet.publicKey });

// The holder shares one fact with your site.
const presentation = await wallet.present(credential, {
  nonce: "n-0S6_WzA2Mj",
  audience: "https://shop.example",
  disclose: ["age_equal_or_over.18"],
});

const { claims } = await verify(presentation, {
  issuerKey: issuer.publicKey,
  nonce: "n-0S6_WzA2Mj",
  audience: "https://shop.example",
});

claims.age_equal_or_over; // { "18": true }
claims.given_name;        // undefined, never shared
```

## Inspect a token

```sh
npx @cachet/sd-jwt decode eyJhbGciOiJFUzI1NiIs...~WyJzYWx0Ii...~
```

```
  Type         urn:eudi:pid:1
  Issuer       https://pid.example.eu
  Expires      2027-10-14 22:02 UTC (in 365 days)
  Disclosures  3
  Holder proof key binding for https://shop.example (nonce abc123)

  Claims
  { "given_name": "Erika", "age_equal_or_over": { "18": true }, ... }

  Not verified. Use verify() before trusting these claims.
```

Add `--json` for machine-readable output, or pipe a token in through stdin. In code, `decode(token)` returns the same information.

## API

### `verify(token, options)`

Returns a `VerifiedSdJwt` or throws an `SdJwtError`.

| Option | | |
|---|---|---|
| `issuerKey` | required | A public `JsonWebKey`, a `CryptoKey`, or `({ header, payload }) => key`. Use the function form to look up `iss` in your trust list or to validate an `x5c` certificate chain. |
| `nonce` | required\* | The nonce you generated for this request. Rejects replayed presentations. |
| `audience` | required\* | Your verifier identifier. Rejects presentations meant for someone else. |
| `requireKeyBinding` | `true` | Set to `false` to accept credentials without holder proof. \*Then `nonce` and `audience` become optional. |
| `vct` | any | Accepted credential types, e.g. `["urn:eudi:pid:1"]`. |
| `algorithms` | all supported | Allowed signing algorithms: `ES256`, `ES384`, `ES512`, `EdDSA`, `PS256`, `RS256`. `none` and HMAC are never accepted. |
| `now` | current time | Verify as of another time. |
| `clockTolerance` | `60` | Allowed clock skew, in seconds. |
| `keyBindingMaxAge` | `300` | How old a key binding may be, in seconds. |

The result contains `claims`, `vct`, `issuer`, `issuedAt`, `expiresAt`, `holderKey`, `keyBinding`, plus the raw `header`, `payload` and `disclosures`.

### `decode(token)`

Same shape as `verify`, without any checks except that the token is well formed. **Don't use it for access decisions.**

### `SdJwtError`

```ts
try {
  await verify(presentation, options);
} catch (error) {
  if (error instanceof SdJwtError && error.code === "nonce_mismatch") {
    // Ask the wallet again with a fresh nonce.
  }
}
```

| `code` | Meaning |
|---|---|
| `malformed` | Not a well-formed SD-JWT. |
| `invalid_disclosure` | A disclosure was altered, duplicated, or doesn't belong to the credential. |
| `unsupported_algorithm` | The signing or hash algorithm isn't supported or allowed. |
| `invalid_key` | The supplied key, or the holder key in `cnf.jwk`, can't be used. |
| `invalid_signature` | The issuer signature doesn't match. |
| `expired` / `not_yet_valid` | Outside the credential's validity window. |
| `unexpected_type` | The `vct` isn't one you accept. |
| `key_binding_required` | No proof that the presenter holds the credential. |
| `key_binding_invalid` | Holder proof is invalid, stale, or the presentation was modified after signing. |
| `nonce_mismatch` / `audience_mismatch` | The presentation wasn't made for this request. |

### `@cachet/sd-jwt/testing`

| Export | |
|---|---|
| `createTestIssuer(iss?)` | Returns `{ issuer, publicKey, issue(claims, options) }`. Every claim is selectively disclosable by default; pass `disclosable: ["birthdate"]` or `"none"` to change that. |
| `createTestWallet()` | Returns `{ publicKey, present(credential, { nonce, audience, disclose }) }`. `disclose` takes dotted paths. |
| `samplePid` | Example person identification data in the EU PID shape. |

Test keys are generated in memory on every call. Never use them in production.

## What this package doesn't do (yet)

Be clear about these before you rely on it:

- **Trust decisions.** The library checks the signature against the key you give it. Deciding which issuers to trust, such as by validating an `x5c` chain against the EU trusted lists, is up to your `issuerKey` resolver for now.
- **Revocation.** Credentials can point to a status list (`status.status_list`). This version doesn't fetch or check it.
- **Requesting credentials from a wallet.** This package verifies what a wallet returns. Asking for it (OpenID4VP, the browser Digital Credentials API) is the job of the upcoming `@cachet/request`.
- **ISO mdoc.** Some wallets also issue mdoc credentials. A separate package will cover them.

## Standards

Implements IETF Selective Disclosure for JWTs (SD-JWT) and SD-JWT-based Verifiable Credentials (SD-JWT VC), including `dc+sd-jwt` credentials and `kb+jwt` key binding. The disclosure digest test vector comes from the SD-JWT specification.

## License

MIT
