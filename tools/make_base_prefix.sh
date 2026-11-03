#!/usr/bin/env bash
# Create (once) the base Wine prefix used by wine_run.sh. Headless: no X connection is made.
set -euo pipefail
WINE="${WINE:-$(command -v wine || echo /usr/bin/wine)}"
[ -x "$WINE" ] || WINE=/usr/bin/wine
BASE="${TP_BASE_PREFIX:-$HOME/.cache/ws2_corpus/prefix}"
if [ -d "$BASE/drive_c" ]; then echo "base prefix exists: $BASE"; exit 0; fi
mkdir -p "$(dirname "$BASE")"
env -u DISPLAY -u WAYLAND_DISPLAY WINEPREFIX="$BASE" WINEARCH=win64 WINEDEBUG=-all "$WINE" wineboot -i >/dev/null 2>&1 || true
env -u DISPLAY -u WAYLAND_DISPLAY WINEPREFIX="$BASE" WINEDEBUG=-all "$WINE" wineboot -s  >/dev/null 2>&1 || true
env -u DISPLAY -u WAYLAND_DISPLAY WINEPREFIX="$BASE" "$(dirname "$WINE")/wineserver" -k 2>/dev/null || true
echo "created $BASE"
