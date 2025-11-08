'use strict';

const { GovEsbHelper } = require('./GovEsbHelper');
const crypto = require('crypto');

async function main() {
	const offline = process.env.GOVESB_OFFLINE !== 'false';

	if (offline) {
		console.log('Running in OFFLINE demo mode (no network calls).');

		// Generate a self-contained EC key pair to demo signing/verification and ECDH
		const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
		const privateDerB64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
		const publicDerB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

		const helper = new GovEsbHelper({
			clientPrivateKey: privateDerB64,
			esbPublicKey: publicDerB64,
			clientId: 'demo-client-id',
			clientSecret: 'demo-client-secret',
			esbTokenUrl: 'https://example.com/token',
			esbEngineUrl: 'https://example.com/engine',
			nidaUserId: 'NIDA123'
		});

		// Build a signed response and verify it
		const requestBody = JSON.stringify({ hello: 'world' });
		const response = await helper.asyncSuccessResponse(requestBody, 'json');
		console.log('Signed response:', response);

		const verifiedData = helper.verifyThenReturnData(response, 'json');
		console.log('Verified data:', verifiedData);

		// ECDH + HKDF + AES-256-GCM encryption/decryption demo
		const secretMessage = 'Top Secret: 12345';
		const encrypted = helper.encrypt(secretMessage, publicDerB64);
		console.log('Encrypted blob:', encrypted);
		const decrypted = helper.decrypt(encrypted);
		console.log('Decrypted plaintext:', decrypted);

		if (decrypted !== secretMessage) {
			throw new Error('Decryption mismatch in offline demo.');
		}

		console.log('OFFLINE demo completed successfully.');
		return;
	}

	// LIVE mode (requires environment variables and network access)
	const helper = new GovEsbHelper({
		clientPrivateKey: process.env.GOVESB_CLIENT_PRIVATE_KEY, // base64 PKCS8 DER (no headers)
		esbPublicKey: process.env.GOVESB_PUBLIC_KEY, // base64 X.509 DER (no headers)
		clientId: process.env.GOVESB_CLIENT_ID,
		clientSecret: process.env.GOVESB_CLIENT_SECRET,
		esbTokenUrl: process.env.GOVESB_TOKEN_URL,
		esbEngineUrl: process.env.GOVESB_ENGINE_URL,
		nidaUserId: process.env.GOVESB_NIDA_USER_ID || null
	});

	// Optional: get token explicitly (request* methods also acquire it)
	await helper.getAccessToken();
	console.log('Access token acquired.');

	// Example: normal synchronous request
	const apiCode = process.env.GOVESB_API_CODE || 'DEMO_API';
	const body = JSON.stringify({ sample: 'payload' });
	const format = process.env.GOVESB_FORMAT || 'json';

	const result = await helper.requestData(apiCode, body, format);
	console.log('requestData result:', result);
}

main().catch(err => {
	console.error(err);
	process.exit(1);
});


