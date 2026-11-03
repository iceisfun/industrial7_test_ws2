#!/usr/bin/env bash
# Run one test exe under Wine in a throw-away, HEADLESS sandbox.
#   tools/wine_run.sh build/<area>.exe [name-filter]
# - fresh copy of the base prefix per run (tests cannot pollute each other or your real prefix)
# - no X: DISPLAY/WAYLAND_DISPLAY are unset so Wine uses its built-in null display driver; this keeps
#   the main X session untouched (many parallel wine runs with persistent explorer.exe exhausted the X
#   server's client slots before). Set TP_DISPLAY=xephyr to run inside a nested Xephyr server instead
#   (only for tests that genuinely need a display driver); the nested server is torn down afterwards.
# - hard timeout, and the prefix's wineserver and children are killed + the prefix removed afterwards.
set -uo pipefail
EXE="$1"; FILTER="${2:-}"
WINE="${WINE:-$(command -v wine || echo /usr/bin/wine)}"
[ -x "$WINE" ] || WINE=/usr/bin/wine
# Shared hosts: at most ${TP_SLOTS:-3} wine runs at once, each in a memory-capped scope.
if [ -z "${TP_CAPPED:-}" ]; then
  export TP_CAPPED=1
  for s in $(seq 1 "${TP_SLOTS:-3}"); do
    exec 9>"/tmp/tp_wine_slot.$s"; flock -n 9 && exec systemd-run --user --scope --quiet -p MemoryMax=${TP_MEM_GB:-3}G -p MemorySwapMax=0 "$0" "$@"
  done
  exec 9>"/tmp/tp_wine_slot.1"; flock 9; exec systemd-run --user --scope --quiet -p MemoryMax=${TP_MEM_GB:-3}G -p MemorySwapMax=0 "$0" "$@"
fi
BASE="${TP_BASE_PREFIX:-$HOME/.cache/ws2_corpus/prefix}"
TMO="${TP_TIMEOUT:-600}"
[ -d "$BASE/drive_c" ] || "$(dirname "$0")/make_base_prefix.sh" >&2
RUN="$(mktemp -d "${TMPDIR:-/tmp}/tp_prefix.XXXXXX")"
cp -a --reflink=auto "$BASE/." "$RUN/"
cleanup() {
  WINEPREFIX="$RUN" "$(dirname "$WINE")/wineserver" -k 2>/dev/null
  sleep 0.3
  rm -rf "$RUN"
  [ -n "${XEPID:-}" ] && kill "$XEPID" 2>/dev/null
}
trap cleanup EXIT
ENVV=(WINEPREFIX="$RUN" WINEARCH=win64 WINEDEBUG="${WINEDEBUG:--all}")
if [ "${TP_DISPLAY:-none}" = "xephyr" ]; then
  N=$((100 + RANDOM % 800)); Xephyr ":$N" -screen 1024x768 -nolisten tcp >/dev/null 2>&1 & XEPID=$!
  sleep 1; ENVV+=(DISPLAY=":$N")
  env -u WAYLAND_DISPLAY "${ENVV[@]}" timeout "$TMO" "$WINE" "$EXE" ${FILTER:+"$FILTER"}
else
  env -u DISPLAY -u WAYLAND_DISPLAY "${ENVV[@]}" timeout "$TMO" "$WINE" "$EXE" ${FILTER:+"$FILTER"}
fi
