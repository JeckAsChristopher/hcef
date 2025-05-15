const hcef = require('../Prebuild/build/Release/hcrypt')

filename = 'text.txt';
key = 'Hello';

console.log(hcef.encrypt(filename, key))

// I write this.
