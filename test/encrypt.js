const hcrypt = require('../build/Release/hcrypt.node');

const filename = 'text.txt';
const password = 'Key';

console.log(hcrypt.encrypt(filename, password));
