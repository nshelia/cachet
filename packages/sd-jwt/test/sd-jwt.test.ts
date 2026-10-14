import { beforeAll, describe, expect, it } from "vitest";
import { decode, SdJwtError, verify, type SdJwtErrorCode } from "../src/index.js";
import { encodeJson } from "../src/base64url.js";
import { hash } from "../src/decode.js";
import { createTestIssuer, createTestWallet, samplePid, type TestIssuer, type TestWallet } from "../src/testing.js";

const audience = "https://shop.example";
const nonce = "n-0S6_WzA2Mj";

let issuer: TestIssuer;
let wallet: TestWallet;
let credential: string;

beforeAll(async () => {
  issuer = await createTestIssuer("https://pid.example.eu");
  wallet = await createTestWallet();
  credential = await issuer.issue(samplePid, { holder: wallet.publicKey });
});

async function rejection(promise: Promise<unknown>): Promise<SdJwtErrorCode> {
  const error = await promise.then(
    () => undefined,
    (error: unknown) => error,
  );
  expect(error).toBeInstanceOf(SdJwtError);
  return (error as SdJwtError).code;
}

describe("verify", () => {
  it("returns every disclosed claim from a key-bound presentation", async () => {
    const presentation = await wallet.present(credential, { nonce, audience });
    const result = await verify(presentation, { issuerKey: issuer.publicKey, nonce, audience });

    expect(result.claims).toMatchObject(samplePid);
    expect(result.vct).toBe("urn:eudi:pid:1");
    expect(result.issuer).toBe("https://pid.example.eu");
    expect(result.holderKey).toEqual(wallet.publicKey);
    expect(result.claims).not.toHaveProperty("_sd");
    expect(result.claims).not.toHaveProperty("_sd_alg");
  });

  it("reveals only what the holder chose to disclose", async () => {
    const presentation = await wallet.present(credential, { nonce, audience, disclose: ["age_equal_or_over.18"] });
    const { claims } = await verify(presentation, { issuerKey: issuer.publicKey, nonce, audience });

    expect(claims.age_equal_or_over).toEqual({ "18": true });
    expect(claims).not.toHaveProperty("given_name");
    expect(claims).not.toHaveProperty("birthdate");
  });

  it("accepts a resolver for the issuer key", async () => {
    const presentation = await wallet.present(credential, { nonce, audience });
    const seen: unknown[] = [];
    await verify(presentation, {
      nonce,
      audience,
      issuerKey: ({ payload }) => {
        seen.push(payload.iss);
        return issuer.publicKey;
      },
    });
    expect(seen).toEqual(["https://pid.example.eu"]);
  });

  it("rejects a credential signed by a different issuer", async () => {
    const impostor = await createTestIssuer("https://pid.example.eu");
    const forged = await impostor.issue(samplePid, { holder: wallet.publicKey });
    const presentation = await wallet.present(forged, { nonce, audience });
    expect(await rejection(verify(presentation, { issuerKey: issuer.publicKey, nonce, audience }))).toBe("invalid_signature");
  });

  it("rejects an altered disclosure", async () => {
    const presentation = await wallet.present(credential, { nonce, audience });
    const [jwt, first, ...rest] = presentation.split("~");
    const forged = encodeJson(["salt", "given_name", "Mallory"]);
    expect(first).toBeDefined();
    const tampered = [jwt, forged, ...rest].join("~");
    expect(await rejection(verify(tampered, { issuerKey: issuer.publicKey, nonce, audience }))).toBe("invalid_disclosure");
  });

  it("rejects a disclosure added after the holder signed", async () => {
    const minimal = await wallet.present(credential, { nonce, audience, disclose: ["given_name"] });
    const extra = (await decode(credential)).disclosures.find((d) => d.name === "birthdate")!;
    const parts = minimal.split("~");
    parts.splice(1, 0, extra.encoded);
    expect(await rejection(verify(parts.join("~"), { issuerKey: issuer.publicKey, nonce, audience }))).toBe(
      "key_binding_invalid",
    );
  });

  it("rejects a tampered payload", async () => {
    const presentation = await wallet.present(credential, { nonce, audience });
    const [header, , signature] = presentation.split("~")[0]!.split(".");
    const payload = encodeJson({ ...(await decode(credential)).payload, iss: "https://evil.example" });
    const tampered = presentation.replace(/^[^~]+/, `${header}.${payload}.${signature}`);
    expect(await rejection(verify(tampered, { issuerKey: issuer.publicKey, nonce, audience }))).toBe("invalid_signature");
  });

  it("rejects a replayed presentation", async () => {
    const presentation = await wallet.present(credential, { nonce: "old-nonce", audience });
    expect(await rejection(verify(presentation, { issuerKey: issuer.publicKey, nonce, audience }))).toBe("nonce_mismatch");
  });

  it("rejects a presentation meant for another verifier", async () => {
    const presentation = await wallet.present(credential, { nonce, audience: "https://other.example" });
    expect(await rejection(verify(presentation, { issuerKey: issuer.publicKey, nonce, audience }))).toBe("audience_mismatch");
  });

  it("rejects a key binding signed by someone other than the holder", async () => {
    const thief = await createTestWallet();
    const presentation = await thief.present(credential, { nonce, audience });
    expect(await rejection(verify(presentation, { issuerKey: issuer.publicKey, nonce, audience }))).toBe(
      "key_binding_invalid",
    );
  });

  it("rejects a stale key binding", async () => {
    const presentation = await wallet.present(credential, { nonce, audience, issuedAt: new Date(Date.now() - 3_600_000) });
    expect(await rejection(verify(presentation, { issuerKey: issuer.publicKey, nonce, audience }))).toBe(
      "key_binding_invalid",
    );
  });

  it("requires a key binding unless you opt out", async () => {
    expect(await rejection(verify(credential, { issuerKey: issuer.publicKey, nonce, audience }))).toBe("key_binding_required");
    const { claims } = await verify(credential, { issuerKey: issuer.publicKey, requireKeyBinding: false });
    expect(claims.given_name).toBe("Erika");
  });

  it("rejects expired and not-yet-valid credentials", async () => {
    const expired = await issuer.issue(samplePid, { issuedAt: new Date("2020-01-01"), expiresIn: 86_400 });
    expect(await rejection(verify(expired, { issuerKey: issuer.publicKey, requireKeyBinding: false }))).toBe("expired");

    const historical = await verify(expired, {
      issuerKey: issuer.publicKey,
      requireKeyBinding: false,
      now: new Date("2020-01-01T12:00:00Z"),
    });
    expect(historical.claims.family_name).toBe("Mustermann");
  });

  it("checks the credential type when asked", async () => {
    const options = { issuerKey: issuer.publicKey, requireKeyBinding: false } as const;
    await expect(verify(credential, { ...options, vct: ["urn:eudi:pid:1", "urn:eudi:pid:de:1"] })).resolves.toBeDefined();
    expect(await rejection(verify(credential, { ...options, vct: "urn:example:diploma" }))).toBe("unexpected_type");
  });

  it("refuses unsigned tokens", async () => {
    const payload = encodeJson({ iss: "x", _sd_alg: "sha-256" });
    const unsigned = `${encodeJson({ alg: "none" })}.${payload}.~`;
    expect(await rejection(verify(unsigned, { issuerKey: issuer.publicKey, requireKeyBinding: false }))).toBe(
      "unsupported_algorithm",
    );
  });

  it("refuses algorithms you didn't allow", async () => {
    expect(
      await rejection(verify(credential, { issuerKey: issuer.publicKey, requireKeyBinding: false, algorithms: ["EdDSA"] })),
    ).toBe("unsupported_algorithm");
  });
});

describe("decode", () => {
  it("reads claims and metadata without a key", async () => {
    const decoded = await decode(credential);
    expect(decoded.claims.given_name).toBe("Erika");
    expect(decoded.header.typ).toBe("dc+sd-jwt");
    expect(decoded.expiresAt).toBeInstanceOf(Date);
    expect(decoded.keyBinding).toBeUndefined();
    expect(decoded.disclosures.length).toBeGreaterThan(5);
  });

  it("exposes the key binding", async () => {
    const decoded = await decode(await wallet.present(credential, { nonce, audience }));
    expect(decoded.keyBinding).toMatchObject({ audience, nonce });
  });

  it("explains a plain JWT", async () => {
    const plain = credential.split("~")[0]!;
    await expect(decode(plain)).rejects.toThrow(/plain JWT/);
  });

  it("rejects duplicate disclosures", async () => {
    const [jwt, first, ...rest] = credential.split("~");
    expect(await rejection(decode([jwt, first, first, ...rest].join("~")))).toBe("invalid_disclosure");
  });

  it("reconstructs array elements and hides undisclosed ones", async () => {
    const shown = encodeJson(["salt-1", "FR"]);
    const hidden = encodeJson(["salt-2", "DE"]);
    const payload = {
      nationalities: [{ "...": await hash(shown, "sha-256") }, { "...": await hash(hidden, "sha-256") }, "IT"],
      _sd_alg: "sha-256",
    };
    const token = `${encodeJson({ alg: "ES256" })}.${encodeJson(payload)}.c2ln~${shown}~`;
    expect((await decode(token)).claims.nationalities).toEqual(["FR", "IT"]);
  });
});

describe("spec compatibility", () => {
  it("computes disclosure digests like the SD-JWT specification", async () => {
    // Example disclosure and digest from the IETF SD-JWT specification.
    const disclosure = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
    expect(await hash(disclosure, "sha-256")).toBe("X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0");
  });
});
