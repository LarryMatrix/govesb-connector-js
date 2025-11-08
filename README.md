# govesb-connector-js

GovESB connector for Node.js: OAuth, ECDSA signing/verification, ECDH+HKDF AES-GCM encryption/decryption, and JSON/XML request formatting.

## Install

Once published:

```bash
npm i govesb-connector-js
```

Local path (before publishing):

```bash
npm i /absolute/path/to/systems/govesb
```

## Requirements

- Node.js >= 18 (uses global `fetch`, or provide a custom `fetch` via options)
- Keys are expected in base64 DER:
  - Private key: PKCS8 DER (no PEM headers)
  - Public key: X.509 DER (no PEM headers)

## Usage

```js
const { GovEsbHelper } = require("govesb-connector-js");

const helper = new GovEsbHelper({
  clientPrivateKey: "base64-pkcs8-der",
  esbPublicKey: "base64-x509-der",
  clientId: process.env.GOVESB_CLIENT_ID,
  clientSecret: process.env.GOVESB_CLIENT_SECRET,
  esbTokenUrl: process.env.GOVESB_TOKEN_URL,
  esbEngineUrl: process.env.GOVESB_ENGINE_URL,
  nidaUserId: process.env.GOVESB_NIDA_USER_ID || null,
  // fetch: customFetch // optional, if not on Node 18+
});

(async () => {
  await helper.getAccessToken();
  const data = await helper.requestData(
    "API_CODE",
    JSON.stringify({ hello: "world" }),
    "json"
  );
  console.log("Response data:", data);
})();
```

## Crypto helpers

```js
// Sign + verify using ESB public key
const response = await helper.successResponse(
  JSON.stringify({ ok: true }),
  "json"
);
const verified = helper.verifyThenReturnData(response, "json"); // string or null

// ECDH + HKDF + AES-256-GCM (tag-prepended format for interoperability)
const encrypted = helper.encrypt("secret text", helper.esbPublicKey);
const plaintext = helper.decrypt(encrypted);
```

## License

MIT

## Contributors

- Japhari Mbaru
- Lawrance Massanja
