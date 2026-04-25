#!/usr/bin/env bash
# Usage:
#   ./build.sh           # auto-detect DPDK (default)
#   ./build.sh dpdk      # require DPDK; fail if pcpp lacks it
#   ./build.sh nodpdk    # build without DPDK
#   ./build.sh clean     # rm -rf build/
#
# Forwards to CMake via -DWITH_DPDK=AUTO|ON|OFF.

set -euo pipefail

BUILD_DIR=build
mode=${1:-auto}

case "$mode" in
  auto)    with_dpdk=AUTO ;;
  dpdk)    with_dpdk=ON ;;
  nodpdk)  with_dpdk=OFF ;;
  clean)   rm -rf "$BUILD_DIR"; exit 0 ;;
  -h|--help|help)
    sed -n '2,7p' "$0"; exit 0 ;;
  *)
    echo "unknown mode '$mode' (try: auto | dpdk | nodpdk | clean)" >&2
    exit 2 ;;
esac

cmake -S . -B "$BUILD_DIR" -DWITH_DPDK="$with_dpdk"
cmake --build "$BUILD_DIR"
