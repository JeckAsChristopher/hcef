{
  "targets": [
    {
      "target_name": "hcrypt",
      "sources": [
        "libs/blow_cipher.cc",
        "libs/node_hcrypt.cc"
      ],
      "include_dirs": [
        "<!(node -p \"require('node-addon-api').include\")",
        "<!(node -p \"require('node-addon-api').include_dir\")",
        "<(module_root_dir)/deps/argon2",
        "<(module_root_dir)/deps/argon2/include",
	"<(module_root_dir)/deps/zlib/include"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS"
      ],
      "cflags_cc": [
        "-std=c++17",
        "-fPIC"
      ],
      "cflags_cc!": [
        "-fno-exceptions"
      ],
      "libraries": [
        "-lssl",
        "-lcrypto",
        "<(module_root_dir)/deps/argon2/libargon2.a",
	"<(module_root_dir)/deps/zlib/build_local/lib/libz.a"
      ],
      "ldflags": [
        "-L<(module_root_dir)/deps"
      ],
      "dependencies": [],
      "link_settings": {
        "ldflags": ["-fPIC"]
      },
      "prebuild": [
        {
          "action": "make -C <(module_root_dir)/deps/argon2 CFLAGS='-fPIC'",
          "files": [
            "<(module_root_dir)/deps/argon2/src/argon2.c",
            "<(module_root_dir)/deps/argon2/src/core.c",
            "<(module_root_dir)/deps/argon2/src/blake2/blake2b.c",
            "<(module_root_dir)/deps/argon2/src/thread.c",
            "<(module_root_dir)/deps/argon2/src/encoding.c",
            "<(module_root_dir)/deps/argon2/src/ref.c",
            "<(module_root_dir)/deps/argon2/src/run.c"
          ]
        }
      ]
    }
  ]
}
