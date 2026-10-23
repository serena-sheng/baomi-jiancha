#!/bin/bash
# 编译 保密检查.app
set -euo pipefail
NAME="保密检查"
BIN="Baomi"
OUT="build"
APP="$OUT/${NAME}.app"
cd "$(dirname "$0")"

echo "→ 编译"
mkdir -p "$OUT"
swiftc -O Sources/*.swift -o "$OUT/$BIN" \
  -framework Cocoa -framework SwiftUI -framework Vision -framework PDFKit \
  -lsqlite3 2>&1 | tail -20

echo "→ 组装 .app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$OUT/$BIN" "$APP/Contents/MacOS/$BIN"
cp Info.plist "$APP/Contents/Info.plist"
cp Resources/AppIcon.icns "$APP/Contents/Resources/"
codesign --force --sign - "$APP" >/dev/null 2>&1 || true
echo "✓ $APP"
echo "  运行: open \"$APP\""
