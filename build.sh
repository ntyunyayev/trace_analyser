#!/usr/bin/env bash
# Usage:
#   ./build.sh           # auto-detect DPDK (default)        -> ./analyser
#   ./build.sh dpdk      # require DPDK; fail if pcpp lacks  -> ./analyser
#   ./build.sh nodpdk    # build without DPDK                -> ./analyser
#   ./build.sh both      # build both flavours side-by-side  -> ./analyser-dpdk + ./analyser-nodpdk
#   ./build.sh clean     # rm -rf build*
#
# Forwards to CMake via -DWITH_DPDK=AUTO|ON|OFF and (for `both`)
# -DANALYSER_NAME=analyser-{dpdk,nodpdk} into separate build dirs.

set -euo pipefail

mode=${1:-auto}

build_one() {
    local with_dpdk=$1 build_dir=$2 binary_name=$3
    cmake -S . -B "$build_dir" -DWITH_DPDK="$with_dpdk" -DANALYSER_NAME="$binary_name"
    cmake --build "$build_dir"
}

case "$mode" in
    auto)   build_one AUTO build analyser ;;
    dpdk)   build_one ON   build analyser ;;
    nodpdk) build_one OFF  build analyser ;;
    both)
        build_one ON  build-dpdk   analyser-dpdk
        build_one OFF build-nodpdk analyser-nodpdk
        ;;
    clean)
        rm -rf build build-dpdk build-nodpdk
        exit 0
        ;;
    -h | --help | help)
        sed -n '2,9p' "$0"
        exit 0
        ;;
    *)
        echo "unknown mode '$mode' (try: auto | dpdk | nodpdk | both | clean)" >&2
        exit 2
        ;;
esac
