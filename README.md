# Cachet

**Small, sharp SDKs for the EU Digital Identity Wallet.**

By the end of 2026, every EU country must offer its citizens a digital identity wallet. About a year later, banks, telecoms, health services and the largest online platforms must accept it. Most of the code needed to do that well doesn't exist yet.

Cachet is a family of packages that each do one job, with no dependencies you didn't ask for, and errors written for humans.

## Packages

| Package | Status | What it does |
|---|---|---|
| [`@cachet/sd-jwt`](packages/sd-jwt) | **0.1** | Decode and verify SD-JWT credentials, the wallet's main credential format. Includes a test issuer and wallet. |
| `@cachet/request` | Planned | Ask a wallet for exactly what you need, from the browser. `request({ ageOver: 18 })` builds the OpenID4VP query and calls the Digital Credentials API, with a QR fallback for desktop. |
| `@cachet/verifier` | Planned | The server half: nonces, sessions, response decryption, EU trusted-list validation and revocation checks, behind one `handle(response)` call. |
| `@cachet/react` | Planned | `<AgeGate minAge={18}>`, `<VerifyButton>`, and hooks that wrap the two packages above. |
| `@cachet/test-wallet` | Planned | A local wallet you can point any verifier at, like test cards for payments. Scripted users, expired credentials, revoked credentials, refusals. |
| `@cachet/issuer` | Planned | Issue your own credentials into citizens' wallets with OpenID4VCI: course certificates, employment records, memberships. |
| `@cachet/mdoc` | Planned | Decode and verify ISO 18013-5 mdoc credentials, the wallet's second format. |
| `@cachet/personhood` | Idea | One-human-one-account for any site: per-site pseudonyms from EU wallets, with passport NFC as a fallback for people outside the EU. |

## Quick look

```ts
import { verify } from "@cachet/sd-jwt";

const { claims } = await verify(presentation, { issuerKey, nonce, audience });

if (claims.age_equal_or_over?.["18"]) {
  // Over 18. You never saw their name or birth date.
}
```

Open [`examples/web-age-check`](examples/web-age-check) for the same flow in a browser, end to end, with a test wallet.

## Principles

1. **One job per package.** Install only what you use.
2. **Secure defaults.** The safe option is the default, and turning it off is explicit and named.
3. **Standards, not lock-in.** IETF SD-JWT, OpenID4VP and OpenID4VCI, W3C Digital Credentials. Nothing proprietary.
4. **Testable before launch.** Every package ships with fakes, so you can build today and switch to real wallets with a config change.
5. **Errors that explain.** Every error has a stable code, a plain sentence, and a hint when there is one.

## Development

```sh
pnpm install
pnpm test
pnpm build
```

## License

MIT
