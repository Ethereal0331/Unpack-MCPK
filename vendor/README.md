# vendored binaries

`pycdc` — decompiler used by `mcp unpack`, built from
https://github.com/ejfkdev/pycdc (v0.8.2, MIT). Its licence is kept
in `LICENSE.pycdc`.

Built static for Android/bionic so it needs no shared libraries:

```sh
rustup target add aarch64-linux-android
RUSTFLAGS="-C target-feature=+crt-static" \
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$NDK/toolchains/llvm/prebuilt/linux-arm64/bin/aarch64-linux-android24-clang \
cargo build --release --target aarch64-linux-android
```

`make` embeds this file into `mcp` (see `mkres.py`). Rebuild it if the
upstream decompiler changes.
