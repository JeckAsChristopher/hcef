// blow_cipher.cc

#include <napi.h>
#include <string>
#include "blow_cipher.h"

// Forward declarations of your core functions
std::string encryptFile(const std::string& filename, const std::string& password);
std::string decryptFile(const std::string& filename, const std::string& password);

// N-API Wrapper for encryption
Napi::String EncryptFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2) {
        Napi::TypeError::New(env, "Expected 2 arguments: filename and password").ThrowAsJavaScriptException();
        return Napi::String::New(env, "");
    }
    std::string filename = info[0].As<Napi::String>().Utf8Value();
    std::string password = info[1].As<Napi::String>().Utf8Value();
    std::string result = encryptFile(filename, password);
    return Napi::String::New(env, result);
}

// N-API Wrapper for decryption
Napi::String DecryptFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2) {
        Napi::TypeError::New(env, "Expected 2 arguments: filename and password").ThrowAsJavaScriptException();
        return Napi::String::New(env, "");
    }
    std::string filename = info[0].As<Napi::String>().Utf8Value();
    std::string password = info[1].As<Napi::String>().Utf8Value();
    std::string result = decryptFile(filename, password);
    return Napi::String::New(env, result);
}

// Initialize the module
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("encrypt", Napi::Function::New(env, EncryptFile));
    exports.Set("decrypt", Napi::Function::New(env, DecryptFile));
    return exports;
}

NODE_API_MODULE(hcrypt, Init)
