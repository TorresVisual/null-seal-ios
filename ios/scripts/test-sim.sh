#!/usr/bin/env bash
# Run the XCTest bundle in an iPhone simulator (launches the app as test host). macOS only; run
# build-xcframework.sh first. Proves "launches in simulator" and "core call round-trips" (#85).
set -euo pipefail

IOS="$(cd "$(dirname "$0")/.." && pwd)"
cd "$IOS"

# First available iPhone, so the script does not hardcode a model the runner image may lack.
UDID="$(xcrun simctl list devices available iPhone | grep -Eo '[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}' | head -1)"
[ -n "$UDID" ] || { echo "no iPhone simulator available" >&2; exit 1; }

xcodegen generate --spec project.yml
xcodebuild test -project NullSeal.xcodeproj -scheme NullSeal -destination "id=$UDID" \
  -only-testing:NullSealTests -derivedDataPath build/derived-sim CODE_SIGNING_ALLOWED=NO
