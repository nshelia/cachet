# Cachet

Verify credentials from the EU Digital Identity Wallet.

```ts
import { verify } from "@cachet/sd-jwt";

const { claims } = await verify(presentation, { issuerKey, nonce, audience });

if (claims.age_equal_or_over?.["18"]) {
  // Over 18. You never saw their name or birth date.
}
```

- [`@cachet/sd-jwt`](packages/sd-jwt): decode and verify SD-JWT credentials, with a test issuer and wallet so you can build before real wallets reach your users.
- [`examples/web-age-check`](examples/web-age-check): the same flow in a browser.

## Development

```sh
pnpm install
pnpm test
```

## License

MIT
