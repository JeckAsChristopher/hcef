#ifndef BLOW_CIPHER_H
#define BLOW_CIPHER_H

#include <string>
#include <vector>

// --- Constants ---
#define KEY_LEN 32
#define IV_LEN 16
#define SALT_LEN 16
#define MAC_LEN 32
#define MAGIC_HEADER "HCRYPT_SECURE"

// --- Public API ---
std::string encryptFile(const std::string& filename, const std::string& password);
std::string decryptFile(const std::string& filename, const std::string& password);

// --- Internal Utility Functions ---
bool fileExists(const std::string& path);
void secureErase(std::vector<unsigned char>& data);

std::string base64Encode(const std::vector<unsigned char>& data);
std::vector<unsigned char> base64Decode(const std::string& encoded);

std::vector<unsigned char> deriveKey(const std::string& password, const std::vector<unsigned char>& salt);
std::vector<unsigned char> computeHMAC(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key);

// --- Obfuscation ---
void applyCaesar(std::vector<unsigned char>& data, int shift);
void reverseCaesar(std::vector<unsigned char>& data, int shift);
void xorObfuscate(std::vector<unsigned char>& data, unsigned char keyByte);
void reverseBytes(std::vector<unsigned char>& data);

#endif // BLOW_CIPHER_H
