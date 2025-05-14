const hcrypt = require('../build/Release/hcrypt');

const encryptedFilePath = 'text.txt.data.enf';
const password = 'Key';

try {
    const result = hcrypt.decrypt(encryptedFilePath, password);
    console.log('[Result]', result);
} catch (err) {
    console.error('[Error]', err.message || err);
}
