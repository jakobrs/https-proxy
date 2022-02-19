#!/usr/bin/env bash

export RUSTFLAGS="-C target-cpu=cortex-a53 -C linker=lld"
export PATH="/usr/local/opt/llvm/bin:$PATH"
export CC=clang

cargo build --release --target arm-unknown-linux-musleabihf
