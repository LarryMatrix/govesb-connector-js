# govesb-connector-js

GovESB connector for Node.js – OAuth (client credentials), payload signing/verification (ECDSA P-256 + SHA-256), request formatting (JSON/XML), and end‑to‑end encryption (ECDH + HKDF-SHA256 + AES‑256‑GCM).

## Features

- OAuth client‑credentials token retrieval
- Request builders: `requestData`, `requestNida`, `pushData`
- Response helpers: `successResponse`, `failureResponse`, `verifyThenReturnData`
- Crypto:
  - ECDSA (P‑256) signing and verification over JSON/XML payloads
  - ECDH key agreement + HKDF‑SHA256 (salt=32 zero bytes, info="aes-encryption") → AES‑256‑GCM
  - Ciphertext format: `encryptedData = tag || ciphertext` (GCM tag prepended)

## Install

Once published:

```bash
npm i govesb-connector-js
```

Local path (before publishing):

```bash
npm i /absolute/path/to/systems/govesb/node
```

## Requirements

- Node.js >= 18 (uses global `fetch`). If you need older Node, inject your own `fetch`:
  - `new GovEsbHelper({ fetch: myFetch, ... })`
- Keys must be base64‑encoded DER (no PEM headers):
  - Private key: PKCS#8 DER → base64
  - Public key: X.509 SubjectPublicKeyInfo DER → base64

Convert PEM to base64 DER (examples):

```bash
# Private (PKCS#8 DER → base64)
openssl pkcs8 -topk8 -nocrypt -in private.pem -outform DER | base64

# Public (X.509 SPKI DER → base64)
openssl pkey -pubin -in public.pem -outform DER | base64
```

## Quick start

```js
const { GovEsbHelper } = require("govesb-connector-js");

const helper = new GovEsbHelper({
  clientPrivateKey: process.env.GOVESB_CLIENT_PRIVATE_KEY, // base64 PKCS#8 DER
  esbPublicKey: process.env.GOVESB_PUBLIC_KEY,             // base64 X.509 DER
  clientId: process.env.GOVESB_CLIENT_ID,
  clientSecret: process.env.GOVESB_CLIENT_SECRET,
  esbTokenUrl: process.env.GOVESB_TOKEN_URL,
  esbEngineUrl: process.env.GOVESB_ENGINE_URL,
  nidaUserId: process.env.GOVESB_NIDA_USER_ID || null,
  // fetch: customFetch // optional
});

(async () => {
  await helper.getAccessToken();
  const data = await helper.requestData("API_CODE", JSON.stringify({ hello: "world" }), "json");
  console.log("Response data:", data);
})();
```

## Signing and verification

```js
// Build a signed success response (JSON) and verify it
const response = await helper.successResponse(JSON.stringify({ ok: true }), "json");
const verifiedData = helper.verifyThenReturnData(response, "json");
if (!verifiedData) {
  throw new Error("Signature verification failed");
}
console.log("Verified:", verifiedData);
```

## Encrypt and decrypt (end‑to‑end)

The library performs ECDH over your private key and the recipient’s public key, derives an AES‑256 key via HKDF‑SHA256 (salt=32 zero bytes, info="aes-encryption"), and encrypts with AES‑GCM. The `encryptedData` field contains the 16‑byte GCM tag followed by ciphertext.

### Encrypt

```js
const payload = JSON.stringify([{ id: 1, title: "example" }]);

// Encrypt to the recipient's public key (base64 X.509 DER).
const encryptedJson = helper.encrypt(payload, helper.esbPublicKey);
// Persist to file or send over the wire
require("fs").writeFileSync("cipher.json", encryptedJson);
```

The resulting JSON looks like:

```json
{
  "ephemeralKey": "<base64-of-PEM-ephemeral-public-key>",
  "iv": "<base64-12-bytes>",
  "encryptedData": "<base64(tag||ciphertext)>"
}
```

### Decrypt

```js
const encryptedJsonString = require("fs").readFileSync("cipher.json", "utf8");
const plaintext = helper.decrypt(encryptedJsonString);
console.log(JSON.parse(plaintext));
```

### Interoperability notes

- The format is compatible with the Python and Java examples (ECDH + HKDF‑SHA256 + AES‑GCM, tag first).
- If you implement your own consumer, ensure you:
  - Use the same curve (P‑256/prime256v1)
  - HKDF parameters match exactly (salt=32 zero bytes, info="aes-encryption", length=32)
  - Keep tag prepended to ciphertext when serializing

## Minimal API reference

- `new GovEsbHelper(options)`
  - `clientPrivateKey` (base64 PKCS#8 DER), `esbPublicKey` (base64 X.509 DER),
    `clientId`, `clientSecret`, `esbTokenUrl`, `esbEngineUrl`, `nidaUserId?`, `fetch?`
- `getAccessToken(): Promise<any>`
- `requestData(apiCode, requestBody, format): Promise<string|null>`
- `requestNida(apiCode, requestBody, format): Promise<string|null>`
- `pushData(apiCode, requestBody, format): Promise<string|null>`
- `successResponse(requestBody, format): Promise<string>`
- `failureResponse(requestBody, message, format): Promise<string>`
- `verifyThenReturnData(esbResponse, format): string|null`
- `encrypt(data, recipientPublicKeyBase64): string` (JSON string)
- `decrypt(encryptedDataJson): string` (plaintext)

## Security best practices

- Treat private keys as secrets; never commit them.
- Rotate credentials and tokens regularly.
- Validate all inputs/outputs when bridging systems.

## License

MIT

## Contributors

- Japhari Mbaru
- Lawrance Massanja
