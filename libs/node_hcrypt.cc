// blow_cipher.cc

#include <napi.h>
#include <string>
#include "blow_cipher.h"  // Header must declare encryptFile and decryptFile
#include <stdexcept>

// N-API wrapper for encryption
Napi::String EncryptFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
        Napi::TypeError::New(env, "Expected 2 string arguments: filename and password").ThrowAsJavaScriptException();
        return Napi::String::New(env, "");
    }

    std::string filename = info[0].As<Napi::String>().Utf8Value();
    std::string password = info[1].As<Napi::String>().Utf8Value();

    try {
        std::string result = encryptFile(filename, password);
        return Napi::String::New(env, result);
    } catch (const std::exception& ex) {
        Napi::Error::New(env, std::string("[EncryptFile Error] ") + ex.what()).ThrowAsJavaScriptException();
        return Napi::String::New(env, "");
    }
}

// N-API wrapper for decryption
Napi::String DecryptFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
        Napi::TypeError::New(env, "Expected 2 string arguments: filename and password").ThrowAsJavaScriptException();
        return Napi::String::New(env, "");
    }

    std::string filename = info[0].As<Napi::String>().Utf8Value();
    std::string password = info[1].As<Napi::String>().Utf8Value();

    try {
        std::string result = decryptFile(filename, password);
        return Napi::String::New(env, result);
    } catch (const std::exception& ex) {
        Napi::Error::New(env, std::string("[DecryptFile Error] ") + ex.what()).ThrowAsJavaScriptException();
        return Napi::String::New(env, "");
    }
}

// Initialize the module
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("encrypt", Napi::Function::New(env, EncryptFile));
    exports.Set("decrypt", Napi::Function::New(env, DecryptFile));
    return exports;
}

NODE_API_MODULE(hcrypt, Init)
