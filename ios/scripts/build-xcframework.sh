#!/usr/bin/env bash
# Build core-uniffi for iOS device + simulator, generate the Swift bindings and assemble
# ios/build/CoreUniFFI.xcframework (static) and ios/Generated/core_uniffi.swift. macOS only.
# Only needs core/ and ios/, so it runs from the public mirror alone (#83).
set -euo pipefail

IOS="$(cd "$(dirname "$0")/.." && pwd)"
CORE="$IOS/../core"
OUT="$IOS/build"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}"

cd "$CORE"
# ponytail: arm64 simulator only (Apple Silicon hosts); add x86_64-apple-ios + lipo if Intel simulators matter.
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim)
rustup target add "${TARGETS[@]}"
for t in "${TARGETS[@]}"; do
  cargo build --release --locked -p core-uniffi --target "$t"
done

# Bindings come from the host build; the interface is identical for every target.
cargo build --release --locked -p core-uniffi
rm -rf "$OUT" "$IOS/Generated"
mkdir -p "$OUT/headers" "$IOS/Generated"
cargo run --release --locked -p core-uniffi --features cli --bin uniffi-bindgen -- \
  generate --library target/release/libcore_uniffi.dylib --language swift --out-dir "$OUT/swift"
cp "$OUT/swift/core_uniffi.swift" "$IOS/Generated/"
cp "$OUT/swift/core_uniffiFFI.h" "$OUT/headers/"
cp "$OUT/swift/core_uniffiFFI.modulemap" "$OUT/headers/module.modulemap"

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libcore_uniffi.a -headers "$OUT/headers" \
  -library target/aarch64-apple-ios-sim/release/libcore_uniffi.a -headers "$OUT/headers" \
  -output "$OUT/CoreUniFFI.xcframework"
