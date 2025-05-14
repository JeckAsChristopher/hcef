cmd_Release/obj.target/hcrypt/libs/blow_cipher.o := aarch64-linux-android-clang++ -o Release/obj.target/hcrypt/libs/blow_cipher.o ../libs/blow_cipher.cc '-DNODE_GYP_MODULE_NAME=hcrypt' '-DUSING_UV_SHARED=1' '-DUSING_V8_SHARED=1' '-DV8_DEPRECATION_WARNINGS=1' '-D_GLIBCXX_USE_CXX11_ABI=1' '-D_LARGEFILE_SOURCE' '-D_FILE_OFFSET_BITS=64' '-D__STDC_FORMAT_MACROS' '-DNAPI_DISABLE_CPP_EXCEPTIONS' '-DBUILDING_NODE_EXTENSION' '-D_GLIBCXX_USE_C99_MATH' -I/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node -I/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/src -I/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/deps/openssl/config -I/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/deps/openssl/openssl/include -I/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/deps/uv/include -I/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/deps/zlib -I/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/deps/v8/include "-I../\"/data/data/com.termux/files/home/hcrypt/node_modules/node-addon-api\"" -I../node_modules/node-addon-api -I/data/data/com.termux/files/home/hcrypt/deps/argon2 -I/data/data/com.termux/files/home/hcrypt/deps/argon2/include  -fPIC -Wall -Wextra -Wno-unused-parameter -O3 -fno-omit-frame-pointer -fPIC -I/sources/android/cpufeatures -fno-rtti -fno-strict-aliasing -std=gnu++20 -std=c++17 -fPIC -MMD -MF ./Release/.deps/Release/obj.target/hcrypt/libs/blow_cipher.o.d.raw   -c
Release/obj.target/hcrypt/libs/blow_cipher.o: ../libs/blow_cipher.cc \
  ../node_modules/node-addon-api/napi.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/node_api.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/js_native_api.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/js_native_api_types.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/node_api_types.h \
  ../node_modules/node-addon-api/napi-inl.h \
  ../node_modules/node-addon-api/napi-inl.deprecated.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/evp.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/macros.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/opensslconf.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/configuration.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/./configuration_asm.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/././archs/linux-elf/asm/include/openssl/configuration.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/opensslv.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/./opensslv_asm.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/././archs/linux-elf/asm/include/openssl/opensslv.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/types.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/e_os2.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/safestack.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/./safestack_asm.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/././archs/linux-elf/asm/include/openssl/safestack.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/stack.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/core.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/core_dispatch.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/symhacks.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/bio.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/./bio_asm.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/././archs/linux-elf/asm/include/openssl/bio.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/crypto.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/./crypto_asm.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/././archs/linux-elf/asm/include/openssl/crypto.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/cryptoerr.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/cryptoerr_legacy.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/bioerr.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/evperr.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/params.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/bn.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/bnerr.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/objects.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/obj_mac.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/asn1.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/./asn1_asm.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/././archs/linux-elf/asm/include/openssl/asn1.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/asn1err.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/objectserr.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/rand.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/randerr.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/hmac.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/buffer.h \
  /data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/buffererr.h \
  /data/data/com.termux/files/home/hcrypt/deps/argon2/include/argon2.h
../libs/blow_cipher.cc:
../node_modules/node-addon-api/napi.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/node_api.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/js_native_api.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/js_native_api_types.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/node_api_types.h:
../node_modules/node-addon-api/napi-inl.h:
../node_modules/node-addon-api/napi-inl.deprecated.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/evp.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/macros.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/opensslconf.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/configuration.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/./configuration_asm.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/././archs/linux-elf/asm/include/openssl/configuration.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/opensslv.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/./opensslv_asm.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/././archs/linux-elf/asm/include/openssl/opensslv.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/types.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/e_os2.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/safestack.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/./safestack_asm.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/././archs/linux-elf/asm/include/openssl/safestack.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/stack.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/core.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/core_dispatch.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/symhacks.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/bio.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/./bio_asm.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/././archs/linux-elf/asm/include/openssl/bio.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/crypto.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/./crypto_asm.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/././archs/linux-elf/asm/include/openssl/crypto.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/cryptoerr.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/cryptoerr_legacy.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/bioerr.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/evperr.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/params.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/bn.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/bnerr.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/objects.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/obj_mac.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/asn1.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/./asn1_asm.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/././archs/linux-elf/asm/include/openssl/asn1.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/asn1err.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/objectserr.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/rand.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/randerr.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/hmac.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/buffer.h:
/data/data/com.termux/files/home/.cache/node-gyp/23.11.0/include/node/openssl/buffererr.h:
/data/data/com.termux/files/home/hcrypt/deps/argon2/include/argon2.h:
