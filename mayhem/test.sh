#!/usr/bin/env bash
#
# mayhem/test.sh — runs upstream's own gtest unit tests for the parsers the harnesses fuzz
# (SMBIOS, EDID, drive SMART, INI file, update manifest, cursor codec round trip), built by
# mayhem/build.sh with normal flags into mayhem/out/aspia_parser_tests. Known-answer assertions,
# so a neutered program fails. Emits a CTRF summary.
#
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/mayhem/out/aspia_parser_tests"
if [ ! -x "$RUNNER" ]; then
  echo "test runner $RUNNER missing — mayhem/build.sh must build it" >&2
  emit_ctrf "gtest" 0 1 0
  exit 1
fi

log="$(mktemp)"
QT_QPA_PLATFORM=offscreen "$RUNNER" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}

passed=$(sed -n 's/^\[  PASSED  \] \([0-9]\+\) test.*/\1/p' "$log" | tail -1)
failed=$(sed -n 's/^\[  FAILED  \] \([0-9]\+\) test.*/\1/p' "$log" | tail -1)
skipped=$(sed -n 's/^\[  SKIPPED \] \([0-9]\+\) test.*/\1/p' "$log" | tail -1)
ran=$(sed -n 's/^\[==========\] \([0-9]\+\) tests\? from .* ran\..*/\1/p' "$log" | tail -1)
rm -f "$log"
passed=${passed:-0}; failed=${failed:-0}; skipped=${skipped:-0}
# A run that crashed or never printed its summary counts as a failure.
if [ -z "$ran" ] || { [ "$rc" -ne 0 ] && [ "$failed" -eq 0 ]; }; then
  failed=$(( failed + 1 ))
fi
emit_ctrf "gtest" "$passed" "$failed" "$skipped"
