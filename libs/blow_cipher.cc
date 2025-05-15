#include <napi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <zlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <sys/stat.h>
#include <stdexcept>
#include "argon2.h"
#include <sys/mman.h>

#define KEY_LEN 32
#define IV_LEN 16
#define SALT_LEN 16
#define MAC_LEN 32
#define MAGIC_HEADER "HCRYPT_SECURE"

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

void secureErase(std::string& data) {
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
    if (BIO_write(bio, data.data(), data.size()) <= 0) {
        BIO_free_all(bio);
        throw std::runtime_error("[!] Base64 encode write error");
    }
    if (BIO_flush(bio) != 1) {
        BIO_free_all(bio);
        throw std::runtime_error("[!] Base64 encode flush error");
    }
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
    if (len < 0) {
        BIO_free_all(bio);
        throw std::runtime_error("[!] Base64 decode read error");
    }
    buffer.resize(len);
    BIO_free_all(bio);
    return buffer;
}

// Derives a key using PBKDF2 and then Argon2id for extra hardness
std::vector<unsigned char> deriveKey(const std::string& password, const std::vector<unsigned char>& salt) {

    std::vector<unsigned char> intermediate(KEY_LEN);
    if (mlock(intermediate.data(), intermediate.size()) != 0) {
        throw std::runtime_error("[!] Failed to lock intermediate memory.");
    }

    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(),
                           100000, EVP_sha256(), KEY_LEN, intermediate.data())) {
        munlock(intermediate.data(), intermediate.size());
        throw std::runtime_error("Error deriving intermediate key using PBKDF2_HMAC.");
    }

    std::vector<unsigned char> finalKey(KEY_LEN);
    if (mlock(finalKey.data(), finalKey.size()) != 0) {
        munlock(intermediate.data(), intermediate.size());
        throw std::runtime_error("[!] Failed to lock finalKey memory.");
    }

    int result = argon2id_hash_raw(
        2, 1 << 17, 4,
        intermediate.data(), intermediate.size(),
        salt.data(), salt.size(),
        finalKey.data(), finalKey.size()
    );

    OPENSSL_cleanse(intermediate.data(), intermediate.size());
    munlock(intermediate.data(), intermediate.size());
    intermediate.clear();

    if (result != ARGON2_OK) {
        munlock(finalKey.data(), finalKey.size());
        throw std::runtime_error("Error in Argon2id hashing: " + std::string(argon2_error_message(result)));
    }

    return finalKey;
}

std::vector<unsigned char> computeHMAC(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    unsigned int len = 0;
    std::vector<unsigned char> hmac(MAC_LEN);
    if (!HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), hmac.data(), &len)) {
        throw std::runtime_error("Error computing HMAC.");
    }
    if (len != MAC_LEN) {
        throw std::runtime_error("HMAC length mismatch.");
    }
    return hmac;
}

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

std::vector<unsigned char> compressData(const std::vector<unsigned char>& input) {
    uLong bound = compressBound(input.size());
    std::vector<unsigned char> compressed(bound);
    uLongf compressedSize = bound;

    if (compress(compressed.data(), &compressedSize, input.data(), input.size()) != Z_OK) {
        throw std::runtime_error("[!] Compression failed.");
    }

    compressed.resize(compressedSize);
    return compressed;
}

std::vector<unsigned char> decompressData(const std::vector<unsigned char>& input, size_t estimatedSize = 1024 * 1024 * 8) {
    std::vector<unsigned char> output(estimatedSize);
    uLongf decompressedSize = output.size();

    int res = uncompress(output.data(), &decompressedSize, input.data(), input.size());
    if (res == Z_BUF_ERROR) {
        // try doubling buffer size once
        output.resize(estimatedSize * 2);
        decompressedSize = output.size();
        res = uncompress(output.data(), &decompressedSize, input.data(), input.size());
    }

    if (res != Z_OK) {
        throw std::runtime_error("[!] Decompression failed.");
    }

    output.resize(decompressedSize);
    return output;
}

class EVP_Cipher_CTX {
    EVP_CIPHER_CTX* ctx;
public:
    EVP_Cipher_CTX() : ctx(EVP_CIPHER_CTX_new()) {
        if (!ctx) throw std::runtime_error("[!] EVP context creation failed.");
    }
    ~EVP_Cipher_CTX() {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
    }
    EVP_CIPHER_CTX* get() { return ctx; }
};

std::string encryptFile(const std::string& filename, const std::string& password) {
    try {
        if (filename.empty() || password.empty()) return "[!] Filename and password must not be empty.";

        std::ifstream in(filename, std::ios::binary | std::ios::ate);
        if (!in) return "[!] Cannot open input file.";

        std::streamsize size = in.tellg();
        if (size <= 0) return "[!] Input file is empty or unreadable.";
        if (size > 1024LL * 1024 * 1024) return "[!] Input file too large (>1GB).";

        in.seekg(0, std::ios::beg);
        std::vector<unsigned char> plaintext(static_cast<size_t>(size));
        if (!in.read((char*)plaintext.data(), size)) {
            return "[!] Error reading input file.";
        }
        in.close();

        plaintext = compressData(plaintext);

        std::vector<unsigned char> salt(SALT_LEN);
        std::vector<unsigned char> iv(IV_LEN);
        if (!RAND_bytes(salt.data(), salt.size()) || !RAND_bytes(iv.data(), iv.size())) {
            return "[!] Failed to generate random salt/iv.";
        }

        auto key = deriveKey(password, salt);

        applyCaesar(plaintext, 5);
        xorObfuscate(plaintext, key[0]);
        reverseBytes(plaintext);

        EVP_Cipher_CTX ctx;
        std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        int len = 0, totalLen = 0;

        if (!EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key.data(), iv.data())) {
            return "[!] Encryption init failed.";
        }

        if (!EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
            return "[!] Encryption update failed.";
        }
        totalLen = len;

        if (!EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len)) {
            return "[!] Encryption final step failed.";
        }
        totalLen += len;
        ciphertext.resize(totalLen);

        auto mac = computeHMAC(ciphertext, key);

        std::ostringstream oss;
        oss << MAGIC_HEADER << ":"
            << base64Encode(salt) << ":"
            << base64Encode(iv) << ":"
            << base64Encode(mac) << ":"
            << base64Encode(ciphertext);

        std::string outputFile = filename + ".data.enf";
        if (fileExists(outputFile)) return "[!] Output file exists.";

        std::ofstream out(outputFile, std::ios::binary);
        if (!out) return "[!] Cannot open output file for writing.";
        out << oss.str();
        out.close();

        secureErase(plaintext);
        secureErase(key);

        return "[+] File encrypted to: " + outputFile;
    } catch (const std::exception& e) {
        return std::string("[!] Exception during encryption: ") + e.what();
    }
}

std::string decryptFile(const std::string& filename, const std::string& password) {
    try {
        if (filename.empty() || password.empty()) return "[!] Filename and password must not be empty.";

        std::ifstream in(filename, std::ios::binary | std::ios::ate);
        if (!in) return "[!] Cannot open file.";

        std::streamsize size = in.tellg();
        if (size <= 0) return "[!] File is empty or unreadable.";

        in.seekg(0, std::ios::beg);
        std::string full(static_cast<size_t>(size), '\0');
        if (!in.read(full.data(), size)) {
            return "[!] Error reading file.";
        }
        in.close();

        if (full.compare(0, strlen(MAGIC_HEADER), MAGIC_HEADER) != 0) return "[!] Invalid header.";

        size_t p1 = full.find(':');
        if (p1 == std::string::npos) return "[!] Corrupt file format.";
        size_t p2 = full.find(':', p1 + 1);
        size_t p3 = full.find(':', p2 + 1);
        size_t p4 = full.find(':', p3 + 1);

        if (p2 == std::string::npos || p3 == std::string::npos || p4 == std::string::npos)
            return "[!] Corrupt file format.";

        auto salt = base64Decode(full.substr(p1 + 1, p2 - p1 - 1));
        auto iv = base64Decode(full.substr(p2 + 1, p3 - p2 - 1));
        auto mac = base64Decode(full.substr(p3 + 1, p4 - p3 - 1));
        auto ciphertext = base64Decode(full.substr(p4 + 1));

        auto key = deriveKey(password, salt);

        // Verify HMAC to detect tampering
        auto expectedMac = computeHMAC(ciphertext, key);
        if (expectedMac != mac) {
            secureErase(key);
            return "[!] HMAC verification failed. Possible wrong password or tampering.";
        }

        EVP_Cipher_CTX ctx;
        std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
        int len = 0, totalLen = 0;

        if (!EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key.data(), iv.data())) {
            secureErase(key);
            return "[!] Decryption init failed.";
        }

        if (!EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
            secureErase(key);
            return "[!] Decryption update failed.";
        }
        totalLen = len;

        if (!EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len)) {
            secureErase(key);
            return "[!] Decryption final step failed. Possibly wrong password or corrupted data.";
        }
        totalLen += len;
        plaintext.resize(totalLen);

        // Reverse the obfuscation
        reverseBytes(plaintext);
        xorObfuscate(plaintext, key[0]);
        reverseCaesar(plaintext, 5);

        // Decompress data
        auto decompressed = decompressData(plaintext);

        if (filename.size() <= 4 || filename.substr(filename.size() - 4) != ".enf") {
    throw std::runtime_error("Decryption error: input file must have a .enf extension");
}

std::string outputFile = filename.substr(0, filename.size() - 4) + ".dnf";
        if (fileExists(outputFile)) {
            secureErase(key);
            return "[!] Output file exists.";
        }

        std::ofstream out(outputFile, std::ios::binary);
        if (!out) {
            secureErase(key);
            return "[!] Cannot open output file for writing.";
        }
        out.write(reinterpret_cast<const char*>(decompressed.data()), decompressed.size());
        out.close();

        secureErase(key);
        secureErase(plaintext);
        secureErase(decompressed);

        return "[+] File decrypted to: " + outputFile;
    } catch (const std::exception& e) {
        return std::string("[!] Exception during decryption: ") + e.what();
    }
}
