#!/usr/bin/env bash
# Usage:
#   ./build.sh           # auto-detect DPDK (default)         -> ./analyser
#   ./build.sh dpdk      # build with DPDK                    -> ./analyser-dpdk
#   ./build.sh nodpdk    # build without DPDK                 -> ./analyser-nodpdk
#   ./build.sh both      # build both flavours side-by-side   -> ./analyser-dpdk + ./analyser-nodpdk
#   ./build.sh deps-dpdk # only build the vendored DPDK
#   ./build.sh deps-pcpp # only build the vendored PcapPlusPlus
#   ./build.sh clean     # rm -rf analyser build dirs (KEEPS vendored deps)
#   ./build.sh clean-dpdk# rm -rf vendored DPDK build/install
#   ./build.sh clean-pcpp# rm -rf vendored PcapPlusPlus build/install
#   ./build.sh clean-deps# both clean-dpdk and clean-pcpp
#   ./build.sh clean-all # clean + clean-deps  (forces full ~10-min rebuild)
#
# DPDK and PcapPlusPlus are vendored as git submodules under external/. Their
# builds happen ONCE into project-local prefixes (external/dpdk/install,
# external/PcapPlusPlus/install-{dpdk,nodpdk}) and are skipped on subsequent
# invocations.

set -euo pipefail

EXT="$(pwd)/external"
DPDK_PREFIX="$EXT/dpdk/install"
# Pin meson's --libdir to "lib" so the install layout is identical on every
# distro. Without this, Debian/Ubuntu install into lib/x86_64-linux-gnu/
# (multi-arch) and Fedora into lib64/, which makes PKG_CONFIG_PATH
# unportable. We force "lib" in build_dpdk's meson invocation below.
DPDK_LIBDIR="$DPDK_PREFIX/lib"

require_submodules() {
    [ -d "$EXT/dpdk/.git" ] || [ -f "$EXT/dpdk/.git" ] || {
        echo "submodule external/dpdk missing; run: git submodule update --init --recursive" >&2
        exit 2
    }
    [ -d "$EXT/PcapPlusPlus/.git" ] || [ -f "$EXT/PcapPlusPlus/.git" ] || {
        echo "submodule external/PcapPlusPlus missing; run: git submodule update --init --recursive" >&2
        exit 2
    }
}

build_dpdk() {
    if [ -f "$DPDK_LIBDIR/pkgconfig/libdpdk.pc" ]; then
        return 0
    fi
    require_submodules
    echo "==> Building DPDK into $DPDK_PREFIX (one-time, ~10 min)"
    meson setup --prefix="$DPDK_PREFIX" \
                --libdir=lib \
                -Ddefault_library=static \
                "$EXT/dpdk/build" "$EXT/dpdk"
    ninja -C "$EXT/dpdk/build" install
}

build_pcpp() {
    local with_dpdk=$1
    local prefix
    if [ "$with_dpdk" = "ON" ]; then
        prefix="$EXT/PcapPlusPlus/install-dpdk"
    else
        prefix="$EXT/PcapPlusPlus/install-nodpdk"
    fi
    if [ -f "$prefix/include/pcapplusplus/Packet.h" ]; then
        return 0
    fi
    require_submodules
    echo "==> Building PcapPlusPlus (DPDK=$with_dpdk) into $prefix (one-time, ~3 min)"
    local build_dir="$EXT/PcapPlusPlus/build-${with_dpdk,,}"
    rm -rf "$build_dir"
    local args=(
        -DCMAKE_INSTALL_PREFIX="$prefix"
        -DPCAPPP_BUILD_PCAPPP=ON
        -DPCAPPP_BUILD_EXAMPLES=OFF
        -DPCAPPP_BUILD_TESTS=OFF
        -DPCAPPP_BUILD_FUZZERS=OFF
        -DBUILD_SHARED_LIBS=OFF
    )
    if [ "$with_dpdk" = "ON" ]; then
        args+=( -DPCAPPP_USE_DPDK=ON -DDPDK_ROOT="$DPDK_PREFIX" )
        export PKG_CONFIG_PATH="$DPDK_LIBDIR/pkgconfig:${PKG_CONFIG_PATH:-}"
        export LIBRARY_PATH="$DPDK_LIBDIR:${LIBRARY_PATH:-}"
    fi
    cmake -S "$EXT/PcapPlusPlus" -B "$build_dir" "${args[@]}"
    cmake --build "$build_dir" -j"$(nproc)"
    cmake --install "$build_dir"
}

build_one() {
    local with_dpdk=$1 build_dir=$2 binary_name=$3
    require_submodules
    if [ "$with_dpdk" != "OFF" ]; then
        build_dpdk
    fi
    build_pcpp "$with_dpdk"
    cmake -S . -B "$build_dir" -DWITH_DPDK="$with_dpdk" -DANALYSER_NAME="$binary_name"
    cmake --build "$build_dir" -j"$(nproc)"
}

mode=${1:-auto}

case "$mode" in
    auto)      build_one AUTO build         analyser ;;
    dpdk)      build_one ON   build-dpdk    analyser-dpdk ;;
    nodpdk)    build_one OFF  build-nodpdk  analyser-nodpdk ;;
    both)
        build_one ON  build-dpdk   analyser-dpdk
        build_one OFF build-nodpdk analyser-nodpdk
        ;;
    deps-dpdk) build_dpdk ;;
    deps-pcpp) build_pcpp "${2:-ON}" ;;
    clean)
        rm -rf build build-dpdk build-nodpdk build-dpdk-dbg
        rm -f analyser analyser-dpdk analyser-nodpdk analyser-dpdk-dbg
        exit 0
        ;;
    clean-dpdk)
        rm -rf "$EXT/dpdk/build" "$DPDK_PREFIX"
        exit 0
        ;;
    clean-pcpp)
        rm -rf "$EXT/PcapPlusPlus/build-on" "$EXT/PcapPlusPlus/build-off"
        rm -rf "$EXT/PcapPlusPlus/install-dpdk" "$EXT/PcapPlusPlus/install-nodpdk"
        exit 0
        ;;
    clean-deps)
        rm -rf "$EXT/dpdk/build" "$DPDK_PREFIX"
        rm -rf "$EXT/PcapPlusPlus/build-on" "$EXT/PcapPlusPlus/build-off"
        rm -rf "$EXT/PcapPlusPlus/install-dpdk" "$EXT/PcapPlusPlus/install-nodpdk"
        exit 0
        ;;
    clean-all)
        rm -rf build build-dpdk build-nodpdk build-dpdk-dbg
        rm -f analyser analyser-dpdk analyser-nodpdk analyser-dpdk-dbg
        rm -rf "$EXT/dpdk/build" "$DPDK_PREFIX"
        rm -rf "$EXT/PcapPlusPlus/build-on" "$EXT/PcapPlusPlus/build-off"
        rm -rf "$EXT/PcapPlusPlus/install-dpdk" "$EXT/PcapPlusPlus/install-nodpdk"
        exit 0
        ;;
    -h | --help | help)
        sed -n '2,16p' "$0"
        exit 0
        ;;
    *)
        echo "unknown mode '$mode' (try: auto | dpdk | nodpdk | both | deps-dpdk | deps-pcpp | clean | clean-dpdk | clean-pcpp | clean-deps | clean-all)" >&2
        exit 2
        ;;
esac
