'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { GovEsbHelper } = require('./GovEsbHelper');

(async () => {
	try {
		const interopDir = path.resolve(__dirname, '../interop');
		const payloadPath = path.join(interopDir, 'payload.json');
		if (!fs.existsSync(payloadPath)) {
			throw new Error(`Missing payload file: ${payloadPath}`);
		}
		const payload = fs.readFileSync(payloadPath, 'utf8');

		// Generate a fresh EC keypair (prime256v1) for this interop
		const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
		const privateDerB64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
		const publicDerB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

		const helper = new GovEsbHelper({
			clientPrivateKey: privateDerB64,
			esbPublicKey: publicDerB64
		});

		const encryptedJson = helper.encrypt(payload, publicDerB64);

		// Write artifacts
		fs.writeFileSync(path.join(interopDir, 'private.der.b64'), privateDerB64);
		fs.writeFileSync(path.join(interopDir, 'public.der.b64'), publicDerB64);
		fs.writeFileSync(path.join(interopDir, 'encrypted_payload.json'), encryptedJson);
		fs.writeFileSync(path.join(interopDir, 'plaintext_payload.json'), payload);

		console.log('Wrote interop payload artifacts to:', interopDir);
		console.log('- private.der.b64');
		console.log('- public.der.b64');
		console.log('- encrypted_payload.json');
		console.log('- plaintext_payload.json');
	} catch (err) {
		console.error(err);
		process.exit(1);
	}
})();


