# hcef

[![npm version](https://img.shields.io/npm/v/hcef)](https://www.npmjs.com/package/hcef)
[![GitHub issues](https://img.shields.io/github/issues/JeckAsChristopher/hcef)](https://github.com/JeckAsChristopher/hcef/issues)
[![Maintenance](https://img.shields.io/maintenance/yes/2025)](https://github.com/JeckAsChristopher/hcef)
[![Known Vulnerabilities](https://snyk.io/test/npm/hcef/badge.svg)](https://snyk.io/test/npm/hcef)

> **hcef** is a fast and secure Node.js native addon written in C++ that provides file encryption with custom obfuscation and HMAC integrity verification. Built using OpenSSL and N-API.

---

## Features

* OpenSSL-backed
* HMAC-SHA256 integrity check
* Obfuscation: Caesar cipher, XOR, and byte reversal
* Uses salt and IV for each encryption
* Secure key derivation (PBKDF2-HMAC-SHA256-ARGON2)
* Automatic Base64 encoding for file structure
* Native performance with clean memory handling 
* Zlib package for compression 

---

## Installation

```bash
npm install hcef
```

> **Note:** Requires a C++17-compatible compiler, `node-gyp`, and OpenSSL development headers installed.

---

## Usage

### Encrypt a file

```js
const hcef = require('hcef');

const result = hcef.encrypt('example.txt', 'myStrongPassword123');
console.log(result);
```

### Decrypt a file

```js
const hcef = require('hcef');

const result = hcef.decrypt('example.txt.enf', 'myStrongPassword123');
console.log(result);
```

> The output will be saved to `example.txt.enf` (encrypted) and `example.txt.enf.dnf` (decrypted)

---

## File Format Structure

The encrypted file is a Base64-encoded string containing:

```
MAGIC_HEADER:salt:iv:mac:ciphertext
```

* `MAGIC_HEADER`: To verify the file is encrypted using hcrypt-native
* `salt`, `iv`, `mac`, and `ciphertext` are all base64-encoded

---

## Security

* Keys are derived using 100,000 PBKDF2 iterations (HMAC-SHA256)
* HMAC prevents tampering and verifies integrity before decryption
* Memory is securely wiped using `OPENSSL_cleanse`
* Uses Both **PBKDF2** and **ARGON2** To Slow Down Brute Force Attacking [Latest Release]
* **zlib compression.**

> While this project is production-hardened, always stay updated with the latest OpenSSL and test thoroughly in your environment.

---

## Development & Testing

This package is actively maintained and tested with:

* Manual encryption-decryption consistency checks
* Corruption resilience tests (tampered file detection)
* Compatibility checks across major platforms

---

## License

MIT

---

## Contributing

Pull requests and suggestions are welcome. Please open issues to report bugs or request features.

---


## Changelog

| Version | Status       | Description                                      |
|---------|--------------|--------------------------------------------------|
| 2.2.6   | Stable       | Stable and secure, but many dependencies. Try using the latest. |
| 2.3.7   | Stable       | Stable release with added security layers.       |
| 2.4.3+   | Stable       | Stable Release Added zlib for compression 	|
| 2.5.2   |  Latest      | Latest Release **Adds Smart error handling, and Key Encryption Smart Handling**	|
---

## Author

Developed and maintained by [Jeck](https://github.com/JeckAsChristopher)
