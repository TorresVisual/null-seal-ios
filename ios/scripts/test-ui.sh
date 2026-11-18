#!/usr/bin/env bash
# Run the XCUITest flows in an iPhone simulator against a local stand-in relay (core-uniffi's
# `ui_relay` example) and export every screenshot to ios/build/screenshots. macOS only; run
# build-xcframework.sh first (#92). Exits with the test result, screenshots exported either way.
set -euo pipefail

IOS="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$IOS/build/ui"
SHOTS="$IOS/build/screenshots"

(cd "$IOS/../core" && cargo build --locked -p core-uniffi --example ui_relay)
rm -rf "$OUT" "$SHOTS"
mkdir -p "$OUT/fixture"
"$IOS/../core/target/debug/examples/ui_relay" "$OUT/fixture" &
RELAY=$!
trap 'kill "$RELAY" 2>/dev/null || true' EXIT
for _ in $(seq 60); do [ -f "$OUT/fixture/relay" ] && break; sleep 1; done
[ -f "$OUT/fixture/relay" ] || { echo "ui_relay did not start" >&2; exit 1; }

cd "$IOS"
UDID="$(xcrun simctl list devices available iPhone | grep -Eo '[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}' | head -1)"
[ -n "$UDID" ] || { echo "no iPhone simulator available" >&2; exit 1; }
xcodegen generate --spec project.yml
# A cold simulator is the usual cause of "timed out while launching the application".
xcrun simctl bootstatus "$UDID" -b

# TEST_RUNNER_ variables reach the UI test runner without the prefix.
set +e
TEST_RUNNER_NS_UI_RELAY="$(cat "$OUT/fixture/relay")" \
TEST_RUNNER_NS_UI_CODE="$(cat "$OUT/fixture/code")" \
TEST_RUNNER_NS_UI_PASSWORD="$(cat "$OUT/fixture/password")" \
  xcodebuild test -project NullSeal.xcodeproj -scheme NullSeal -destination "id=$UDID" \
    -only-testing:NullSealUITests -derivedDataPath build/derived-ui \
    -resultBundlePath "$OUT/ui.xcresult" CODE_SIGNING_ALLOWED=NO
STATUS=$?
set -e

xcrun xcresulttool export attachments --path "$OUT/ui.xcresult" --output-path "$SHOTS" || true
# Files come out as <uuid>.png; give them the names the test chose (01-onboarding, ...).
python3 - "$SHOTS" <<'PY' || true
import json, os, sys
d = sys.argv[1]
def walk(x):
    if isinstance(x, dict):
        if "exportedFileName" in x and "suggestedHumanReadableName" in x:
            yield x
        for v in x.values():
            yield from walk(v)
    elif isinstance(x, list):
        for v in x:
            yield from walk(v)
for a in walk(json.load(open(os.path.join(d, "manifest.json")))):
    src = os.path.join(d, a["exportedFileName"])
    if os.path.exists(src):
        os.rename(src, os.path.join(d, a["suggestedHumanReadableName"]))
# upload-artifact refuses names with quotes, colons etc. (failure attachments have them)
for f in os.listdir(d):
    clean = f.translate({ord(c): "_" for c in "\"':<>|*?\r\n"})
    if clean != f:
        os.rename(os.path.join(d, f), os.path.join(d, clean))
PY
ls "$SHOTS" || true
exit "$STATUS"
