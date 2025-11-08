'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { GovEsbHelper } = require('./GovEsbHelper');

(async () => {
	try {
		const outDir = path.resolve(__dirname, '../interop');
		if (!fs.existsSync(outDir)) {
			fs.mkdirSync(outDir, { recursive: true });
		}

		// Generate an EC keypair (prime256v1) for interop
		const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
		const privateDerB64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
		const publicDerB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

		// Use Node helper to encrypt with the public key
		const helper = new GovEsbHelper({
			clientPrivateKey: privateDerB64,
			esbPublicKey: publicDerB64
		});

		const plaintext = 'Cross-language secret: Node->Python';
		const encryptedJson = helper.encrypt(plaintext, publicDerB64);

		// Write artifacts for Python to consume
		fs.writeFileSync(path.join(outDir, 'private.der.b64'), privateDerB64);
		fs.writeFileSync(path.join(outDir, 'public.der.b64'), publicDerB64);
		fs.writeFileSync(path.join(outDir, 'encrypted.json'), encryptedJson);
		fs.writeFileSync(path.join(outDir, 'plaintext.txt'), plaintext);

		console.log('Wrote interop artifacts to:', outDir);
		console.log('- private.der.b64');
		console.log('- public.der.b64');
		console.log('- encrypted.json');
		console.log('- plaintext.txt');
	} catch (err) {
		console.error(err);
		process.exit(1);
	}
})();


