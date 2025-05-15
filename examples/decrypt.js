const hcef = require('../Prebuild/build/Release/hcrypt')

const decryptfile = 'text.txt.data.enf';
const key = 'Hello';

const result = hcef.decrypt(decryptfile, key)

// Write this again
