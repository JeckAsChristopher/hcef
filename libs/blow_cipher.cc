#include <napi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <sys/stat.h>
#include <stdexcept>

#define KEY_LEN 32
#define IV_LEN 16
#define SALT_LEN 16
#define MAC_LEN 32
#define MAGIC_HEADER "HCRYPT_SECURE"

// --- Utility Functions ---
bool fileExists(const std::string& path) {
    struct stat buffer;
    return stat(path.c_str(), &buffer) == 0;
}

void secureErase(std::vector<unsigned char>& data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
        data.clear();
    }
}

std::string base64Encode(const std::vector<unsigned char>& data) {
    BIO* bio, *b64;
    BUF_MEM* bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

std::vector<unsigned char> base64Decode(const std::string& encoded) {
    BIO* bio, *b64;
    std::vector<unsigned char> buffer(encoded.size());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encoded.data(), encoded.size());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int len = BIO_read(bio, buffer.data(), encoded.size());
    buffer.resize(len);
    BIO_free_all(bio);
    return buffer;
}

// --- Key Derivation and MAC ---
std::vector<unsigned char> deriveKey(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(KEY_LEN);
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), 100000, EVP_sha256(), KEY_LEN, key.data())) {
        throw std::runtime_error("Error deriving key using PBKDF2_HMAC.");
    }
    return key;
}

std::vector<unsigned char> computeHMAC(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    unsigned int len = 0;
    std::vector<unsigned char> hmac(MAC_LEN);
    if (!HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), hmac.data(), &len)) {
        throw std::runtime_error("Error computing HMAC.");
    }
    return hmac;
}

// --- Custom Obfuscation ---
void applyCaesar(std::vector<unsigned char>& data, int shift) {
    for (auto& byte : data) byte = static_cast<unsigned char>(byte + shift);
}

void reverseCaesar(std::vector<unsigned char>& data, int shift) {
    for (auto& byte : data) byte = static_cast<unsigned char>(byte - shift);
}

void xorObfuscate(std::vector<unsigned char>& data, unsigned char keyByte) {
    for (auto& byte : data) byte ^= keyByte;
}

void reverseBytes(std::vector<unsigned char>& data) {
    std::reverse(data.begin(), data.end());
}

// --- Encryption ---
std::string encryptFile(const std::string& filename, const std::string& password) {
    if (filename.empty() || password.empty()) {
        return "[!] Filename and password must not be empty.";
    }

    std::ifstream in(filename, std::ios::binary);
    if (!in) {
        return "[!] Cannot open input file.";
    }

    std::vector<unsigned char> plaintext((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    std::vector<unsigned char> salt(SALT_LEN);
    std::vector<unsigned char> iv(IV_LEN);
    if (!RAND_bytes(salt.data(), salt.size()) || !RAND_bytes(iv.data(), iv.size())) {
        return "[!] Failed to generate random data (salt/iv).";
    }

    auto key = deriveKey(password, salt);

    // Apply obfuscation steps
    applyCaesar(plaintext, 5);
    xorObfuscate(plaintext, key[0]);
    reverseBytes(plaintext);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return "[!] Error creating EVP context.";
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, totalLen = 0;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        return "[!] Error initializing encryption.";
    }

    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return "[!] Error during encryption.";
    }
    totalLen = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return "[!] Final encryption step failed.";
    }
    totalLen += len;
    ciphertext.resize(totalLen);
    EVP_CIPHER_CTX_free(ctx);

    auto mac = computeHMAC(ciphertext, key);

    std::ostringstream oss;
    oss << MAGIC_HEADER << ":"
        << base64Encode(salt) << ":"
        << base64Encode(iv) << ":"
        << base64Encode(mac) << ":"
        << base64Encode(ciphertext);

    std::string outputFile = filename + ".enf";
    if (fileExists(outputFile)) {
        return "[!] Output file exists. Aborting.";
    }

    std::ofstream out(outputFile, std::ios::binary);
    out << oss.str();
    out.close();

    return "[+] File encrypted to: " + outputFile;
}

// --- Decryption ---
std::string decryptFile(const std::string& filename, const std::string& password) {
    if (filename.empty() || password.empty()) {
        return "[!] Filename and password must not be empty.";
    }

    std::ifstream in(filename, std::ios::binary);
    if (!in) {
        return "[!] Cannot open file.";
    }

    std::string full((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    if (full.find(MAGIC_HEADER) != 0) {
        return "[!] Invalid header.";
    }

    size_t p1 = full.find(':') + 1;
    size_t p2 = full.find(':', p1);
    size_t p3 = full.find(':', p2 + 1);
    size_t p4 = full.find(':', p3 + 1);

    auto salt = base64Decode(full.substr(p1, p2 - p1));
    auto iv = base64Decode(full.substr(p2 + 1, p3 - p2 - 1));
    auto mac = base64Decode(full.substr(p3 + 1, p4 - p3 - 1));
    auto ciphertext = base64Decode(full.substr(p4 + 1));

    auto key = deriveKey(password, salt);
    auto computedMac = computeHMAC(ciphertext, key);

    if (CRYPTO_memcmp(mac.data(), computedMac.data(), MAC_LEN) != 0) {
        return "[!] MAC verification failed. Data may be tampered.";
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return "[!] Error creating EVP context.";
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, totalLen = 0;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        return "[!] Error initializing decryption.";
    }

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return "[!] Error during decryption.";
    }
    totalLen = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return "[!] Final decryption step failed.";
    }
    totalLen += len;
    plaintext.resize(totalLen);
    EVP_CIPHER_CTX_free(ctx);

    reverseBytes(plaintext);
    xorObfuscate(plaintext, key[0]);
    reverseCaesar(plaintext, 5);

    std::string outputFile = filename + ".dnf";
    if (fileExists(outputFile)) {
        return "[!] Output file exists. Aborting.";
    }

    std::ofstream out(outputFile, std::ios::binary);
    out.write((char*)plaintext.data(), plaintext.size());
    out.close();

    return "[+] File decrypted to: " + outputFile;
}
