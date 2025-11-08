'use strict';

const fs = require('fs');
const path = require('path');
const { GovEsbHelper } = require('./GovEsbHelper');

(async () => {
	try {
		const interopDir = path.resolve(__dirname, '../interop');
		const privPath = path.join(interopDir, 'py_private.der.b64');
		const pubPath = path.join(interopDir, 'py_public.der.b64');
		const encPath = path.join(interopDir, 'encrypted_payload_py.json');
		const outPath = path.join(interopDir, 'decrypted_payload_py.json');

		const privateDerB64 = fs.readFileSync(privPath, 'utf8').trim();
		const publicDerB64 = fs.readFileSync(pubPath, 'utf8').trim();
		const encryptedJson = fs.readFileSync(encPath, 'utf8').trim();

		const helper = new GovEsbHelper({
			clientPrivateKey: privateDerB64,
			esbPublicKey: publicDerB64
		});

		const plaintext = helper.decrypt(encryptedJson);
		fs.writeFileSync(outPath, plaintext);
		console.log('Decrypted payload written to:', outPath);
	} catch (err) {
		console.error(err);
		process.exit(1);
	}
})();


