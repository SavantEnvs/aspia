#!/usr/bin/env bash
#
# mayhem/build.sh — build aspia's fuzz harnesses (and the oracle test runner).
#
# Upstream builds against a static Qt6 + ~30 libraries from its own vcpkg submodule
# (vcpkg4aspia, a multi-hour build that fetches from the network). The harnesses only need the
# parsers in `source/base` (plus the generated protobuf messages), so this script compiles exactly
# those upstream sources against Debian's Qt6Core / protobuf / libvpx / opus / zstd / libyuv
# (installed by mayhem/Dockerfile), with $SANITIZER_FLAGS, into build-mayhem/libaspia_fuzz.a:
#   * the protobuf messages: protoc + upstream's own `tools/qtprotoc` plugin (built here) generate
#     `proto/<name>.pb.{h,cc}` and the `proto/<name>.{h,cc}` wrappers, exactly as source/proto does;
#   * Q_GADGET/Q_OBJECT headers go through Qt's moc, as CMake's AUTOMOC would.
# Runs offline (everything comes from apt packages in the image) and is re-runnable.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
S="$SRC/source"
B="$SRC/mayhem/build"           # gitignored by mayhem/.gitignore
OUT="$SRC/mayhem/out"
mkdir -p "$B/gen/proto" "$B/obj" "$B/moc" "$OUT"

# opus headers live in include/opus; QtGlobal is force-included because sinc_resampler.h tests
# Q_PROCESSOR_X86 before including any Qt header (upstream gets it transitively from its vcpkg Qt).
QT_CFLAGS="$(pkg-config --cflags Qt6Core Qt6DBus opus) -include QtGlobal"
# Version defines, as the top-level CMakeLists.txt sets them (GIT_COMMIT_COUNT pinned to 0, as
# upstream does when git is unavailable, so the build does not depend on the history depth).
ver() { sed -n "s/^set(ASPIA_VERSION_$1 \([0-9]*\))/\1/p" "$SRC/CMakeLists.txt"; }
QT_CFLAGS="$QT_CFLAGS -DASPIA_VERSION_MAJOR=$(ver MAJOR) -DASPIA_VERSION_MINOR=$(ver MINOR)"
QT_CFLAGS="$QT_CFLAGS -DASPIA_VERSION_PATCH=$(ver PATCH) -DGIT_COMMIT_COUNT=0"
QT_LIBS="$(pkg-config --libs Qt6Core Qt6DBus)"
MOC="$(pkg-config --variable=libexecdir Qt6Core)/moc"
[ -x "$MOC" ] || MOC=/usr/lib/qt6/libexec/moc
DEP_LIBS="-lprotobuf -lvpx -lopus -lzstd -lyuv -lssl -lcrypto -lsqlite3 -licuuc -lpthread"

# 1) Generated protobuf code (host tool, normal flags — not instrumented).
$CXX -std=c++20 -O1 -include google/protobuf/descriptor.h -include sstream \
    "$S/tools/qtprotoc/main.cc" -lprotoc -lprotobuf -o "$B/qtprotoc"
PROTOS=()
for f in "$S"/proto/*.proto; do PROTOS+=("$(basename "$f" .proto)"); done
( cd "$B/gen/proto" && \
  protoc --cpp_out=. --plugin=protoc-gen-qt="$B/qtprotoc" --qt_out=. -I"$S/proto" \
      $(for p in "${PROTOS[@]}"; do echo "$S/proto/$p.proto"; done) )

# 2) moc for the Q_GADGET/Q_OBJECT headers we compile.
for h in base/desktop/mouse_cursor.h base/codec/video_decoder.h base/peer/authenticator.h \
         base/peer/server_authenticator.h base/peer/client_authenticator.h \
         common/clipboard_file_transfer.h; do
    "$MOC" -I"$S" "$S/$h" -o "$B/moc/moc_$(basename "${h%.h}").cpp"
done

BASE_SOURCES=(
    base/logging.cc base/logging_file.cc base/location.cc base/debug.cc base/crash_handler.cc
    base/system_error.cc base/scoped_clear_last_error.cc base/string_util.cc
    base/aligned_memory.cc base/smbios_parser.cc base/edid.cc base/drive_smart.cc base/ini_file.cc
    base/update/update_info.cc
    base/desktop/mouse_cursor.cc
    base/codec/cursor_decoder.cc base/codec/scoped_zstd_stream.cc
    base/codec/video_decoder.cc base/codec/video_decoder_vpx.cc base/codec/scoped_vpx_codec.cc
    base/codec/audio_decoder.cc base/codec/audio_bus.cc base/codec/multi_channel_resampler.cc
    base/codec/sinc_resampler.cc base/codec/vector_math.cc
    base/peer/authenticator.cc base/peer/server_authenticator.cc base/peer/client_authenticator.cc
    base/peer/user.cc base/serialization.cc base/version_constants.cc base/sys_info.cc
    base/sys_info_linux.cc base/cpuid_util.cc base/physical_drive_reader.cc
    base/physical_drive_reader_linux.cc
    base/sql/sql_database.cc base/sql/sql_query.cc base/sql/sql_transaction.cc
    base/crypto/big_num.cc base/crypto/generic_hash.cc base/crypto/key_pair.cc
    base/crypto/openssl_util.cc base/crypto/random.cc base/crypto/secure_byte_array.cc
    base/crypto/secure_memory.cc base/crypto/secure_string.cc base/crypto/srp_math.cc
    common/clipboard_file_transfer.cc common/file_depacketizer.cc
)

# SanCov on the project code too (not only the harness), so the fuzzer sees the parsers' edges.
COV_FLAGS="-fsanitize=fuzzer-no-link"
CXXFLAGS_FUZZ="-std=c++20 -O1 $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -fPIC -I$S -I$B/gen $QT_CFLAGS"

compile() { # src obj
    $CXX $CXXFLAGS_FUZZ -c "$1" -o "$2"
}
export -f compile
export CXXFLAGS_FUZZ

objs=()
jobs_list=()
for src in "${BASE_SOURCES[@]}"; do
    o="$B/obj/$(echo "$src" | tr '/' '_').o"; objs+=("$o"); jobs_list+=("$S/$src $o")
done
for p in "${PROTOS[@]}"; do
    for ext in pb.cc cc; do
        o="$B/obj/proto_${p}_${ext}.o"; objs+=("$o"); jobs_list+=("$B/gen/proto/$p.$ext $o")
    done
done
for m in "$B"/moc/*.cpp; do
    o="$B/obj/$(basename "$m" .cpp).o"; objs+=("$o"); jobs_list+=("$m $o")
done
printf '%s\n' "${jobs_list[@]}" | xargs -P "$MAYHEM_JOBS" -L1 bash -c 'compile "$0" "$1"'

rm -f "$B/libaspia_fuzz.a"
ar rcs "$B/libaspia_fuzz.a" "${objs[@]}"

# 3) Harnesses: libFuzzer binary + standalone reproducer each.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
HARNESSES=(fuzz_smbios fuzz_edid_smart fuzz_update_info fuzz_ini_file
           fuzz_cursor_decoder fuzz_video_decoder fuzz_audio_decoder
           fuzz_server_authenticator fuzz_client_authenticator
           fuzz_clipboard_file_transfer fuzz_file_depacketizer)
for h in "${HARNESSES[@]}"; do
    $CXX $CXXFLAGS_FUZZ -c "$SRC/mayhem/harnesses/$h.cc" -o "$B/obj/harness_$h.o"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/obj/harness_$h.o" "$B/lsan_off.o" \
        "$B/libaspia_fuzz.a" $QT_LIBS $DEP_LIBS -o "$OUT/$h"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/standalone_main.o" "$B/obj/harness_$h.o" "$B/lsan_off.o" \
        "$B/libaspia_fuzz.a" $QT_LIBS $DEP_LIBS -o "$OUT/$h-standalone"
done

# 4) Functional oracle: upstream's own gtest unit tests for the same parsers, built with NORMAL flags.
T="$B/tests"
mkdir -p "$T/obj"
TEST_CXXFLAGS="-std=c++20 -O1 -fPIC -I$S -I$B/gen $QT_CFLAGS $COVERAGE_FLAGS"
TEST_SOURCES=(
    base/smbios_parser_unittest.cc base/edid_unittest.cc base/drive_smart_unittest.cc
    base/ini_file_unittest.cc base/update/update_info_unittest.cc base/codec/cursor_codec_unittest.cc
    base/codec/cursor_encoder.cc base/codec/zstd_stream_compressor.cc base/codec/zstd_stream_decompressor.cc
    common/file_depacketizer_unittest.cc common/file_packetizer_unittest.cc common/file_packetizer.cc
)
tobjs=()
for src in "${BASE_SOURCES[@]}" "${TEST_SOURCES[@]}"; do
    o="$T/obj/$(echo "$src" | tr '/' '_').o"; tobjs+=("$o")
    $CXX $TEST_CXXFLAGS -c "$S/$src" -o "$o" &
    while [ "$(jobs -rp | wc -l)" -ge "$MAYHEM_JOBS" ]; do wait -n; done
done
for p in "${PROTOS[@]}"; do
    for ext in pb.cc cc; do
        o="$T/obj/proto_${p}_${ext}.o"; tobjs+=("$o")
        $CXX $TEST_CXXFLAGS -c "$B/gen/proto/$p.$ext" -o "$o" &
    done
done
for m in "$B"/moc/*.cpp; do
    o="$T/obj/$(basename "$m" .cpp).o"; tobjs+=("$o")
    $CXX $TEST_CXXFLAGS -c "$m" -o "$o" &
done
wait
$CXX $COVERAGE_FLAGS "${tobjs[@]}" -lgtest -lgtest_main $QT_LIBS $DEP_LIBS -o "$OUT/aspia_parser_tests"
