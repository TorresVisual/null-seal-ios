#!/usr/bin/env bash
# Build the unsigned NullSeal.ipa from ios/ (run build-xcframework.sh first). macOS only.
# Unsigned on purpose: AltStore re-signs on install, and no signing material lives in the mirror.
set -euo pipefail

IOS="$(cd "$(dirname "$0")/.." && pwd)"
cd "$IOS"

xcodegen generate --spec project.yml
xcodebuild -project NullSeal.xcodeproj -scheme NullSeal -configuration Release \
  -sdk iphoneos -destination 'generic/platform=iOS' -derivedDataPath build/derived \
  ${NS_TAG:+MARKETING_VERSION="${NS_TAG#v}"} ${NS_BUILD:+CURRENT_PROJECT_VERSION="$NS_BUILD"} \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" build

rm -rf build/ipa && mkdir -p build/ipa/Payload
cp -R build/derived/Build/Products/Release-iphoneos/NullSeal.app build/ipa/Payload/
(cd build/ipa && zip -qry ../NullSeal.ipa Payload)
echo "built $IOS/build/NullSeal.ipa"
