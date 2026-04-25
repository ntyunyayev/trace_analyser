# What is the project about?


This is a small project, that aims to provide a script to analyse the protocol distribution from large traces. It relies on PCAP++.

The tool provides for each protocol, the total number of packets, bytes and connections.

## Prerequisites

- PcapPlusPlus
- gflags
- (optional, for the DPDK backend) DPDK, and a PcapPlusPlus build that
  includes DPDK support — see below.

## Building PcapPlusPlus with DPDK support

The DPDK backend in this project compiles only when the installed PcapPlusPlus
exposes its `DpdkDevice.h` / `DpdkDeviceList.h` headers, which are emitted
only when pcpp itself was built with `-DPCAPPP_USE_DPDK=ON`. Stock distro
packages and the precompiled releases on
[github.com/seladb/PcapPlusPlus/releases](https://github.com/seladb/PcapPlusPlus/releases)
are built with DPDK off, so you have to build pcpp from source against your
DPDK install.

### Prerequisites

- DPDK installed (we used DPDK 23.03 here). `pkg-config --modversion libdpdk`
  must return a version. If it doesn't, point `PKG_CONFIG_PATH` at your DPDK
  install's `lib/pkgconfig` directory before invoking CMake.
- PcapPlusPlus source checkout (`git clone https://github.com/seladb/PcapPlusPlus.git`).

### Build & install

In the PcapPlusPlus source tree:

    cmake -S . -B build \
          -DPCAPPP_USE_DPDK=ON \
          -DDPDK_ROOT=<dpdk-install-prefix>
    LIBRARY_PATH=<dpdk-install-prefix>/lib/x86_64-linux-gnu \
        cmake --build build -j$(nproc)
    sudo -E cmake --install build               # writes to /usr/local

The `LIBRARY_PATH` prefix on the build step works around an upstream issue in
pcpp's `cmake/modules/FindDPDK.cmake`: the `DPDK::DPDK` IMPORTED INTERFACE
target sets `INTERFACE_LINK_LIBRARIES` (the `-lrte_*` names) but never sets
`INTERFACE_LINK_DIRECTORIES`, so without `LIBRARY_PATH` the link line for
pcpp's example binaries fails with `cannot find -lrte_mldev` even though the
library is on disk. `sudo -E` is needed because `sudo` strips environment
variables by default and the install step can re-link.

If you'd rather skip the workaround, you can also disable Examples and Tests
in the pcpp configure step (the libraries themselves still link fine):

    cmake -S . -B build \
          -DPCAPPP_USE_DPDK=ON \
          -DDPDK_ROOT=<dpdk-install-prefix> \
          -DPCAPPP_BUILD_EXAMPLES=OFF \
          -DPCAPPP_BUILD_TESTS=OFF
    cmake --build build -j$(nproc)
    sudo cmake --install build

### Optional: side-by-side install

If you'd rather not overwrite the system PcapPlusPlus install at `/usr/local`,
use a private prefix and tell this project's CMake about it via
`CMAKE_PREFIX_PATH`:

    cmake -S . -B build \
          -DPCAPPP_USE_DPDK=ON \
          -DDPDK_ROOT=<dpdk-install-prefix> \
          -DCMAKE_INSTALL_PREFIX=$HOME/local-pcpp-dpdk
    LIBRARY_PATH=<dpdk-install-prefix>/lib/x86_64-linux-gnu \
        cmake --build build -j$(nproc)
    cmake --install build                        # no sudo
    # back in this project:
    CMAKE_PREFIX_PATH=$HOME/local-pcpp-dpdk ./build.sh dpdk

### Verifying

After install, `/usr/local/include/pcapplusplus/DpdkDevice.h` should exist,
and `./build.sh dpdk` here will print
`DPDK backend: ENABLED (libdpdk <version>) [WITH_DPDK=ON]`.

## Building

    ./build.sh           # auto-detect DPDK     -> ./analyser
    ./build.sh dpdk      # require DPDK         -> ./analyser
    ./build.sh nodpdk    # build without DPDK   -> ./analyser
    ./build.sh both      # build both flavours  -> ./analyser-dpdk + ./analyser-nodpdk
    ./build.sh clean     # rm -rf build build-dpdk build-nodpdk

Equivalent direct CMake invocation:
`cmake -S . -B build -DWITH_DPDK=AUTO|ON|OFF && cmake --build build`.
The output binary name can be overridden with `-DANALYSER_NAME=<name>`.

`./build.sh both` is the easy way to keep a DPDK and a non-DPDK binary side
by side — useful for benchmarking the offline-only path against the DPDK
build, or for shipping the no-DPDK variant to machines that don't have DPDK
in their `LD_LIBRARY_PATH`.

## Flags

All flags below are gflags (`--name=value` or `--name value`). `./analyser
--help` prints the live list.

### Input / output

| Flag                          | Type   | Default       | Description                                                                                              |
|-------------------------------|--------|---------------|----------------------------------------------------------------------------------------------------------|
| `--input_file`                | string | `input.pcap`  | Input pcap/pcapng file. Ignored when `--dpdk_port >= 0`.                                                 |
| `--output_csv`                | string | `stats.csv`   | Path for the per-protocol summary CSV (always written).                                                  |

### Per-connection packet-distance

| Flag                          | Type   | Default | Description                                                                                                       |
|-------------------------------|--------|---------|-------------------------------------------------------------------------------------------------------------------|
| `--compute_packet_distance`   | bool   | `false` | Compute per-protocol average packet-index distance between consecutive packets of the same connection.            |
| `--output_connections_csv`    | string | `""`    | If set, write a per-connection CSV (`Protocol,IpA,PortA,IpB,PortB,Packet_Count,Gap_Samples,Avg_Packet_Distance`). Requires `--compute_packet_distance`. |

### Header-size distribution

| Flag                          | Type   | Default | Description                                                                                                                  |
|-------------------------------|--------|---------|------------------------------------------------------------------------------------------------------------------------------|
| `--compute_header_sizes`      | bool   | `false` | Count per-protocol distributions of IP and TCP header sizes (uses `IPv4Layer/IPv6Layer/TcpLayer::getHeaderLen()`).           |
| `--output_header_sizes_csv`   | string | `""`    | If set, write the header-size CSV (`Protocol,Header,Size_Bytes,Count`, long format). UDP omitted (always 8). Requires `--compute_header_sizes`. |

### DPDK live capture

Only effective when the binary was built with DPDK on (`./build.sh dpdk`).

| Flag                          | Type    | Default   | Description                                                                                                                                                       |
|-------------------------------|---------|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--dpdk_port`                 | int32   | `-1`      | If `>= 0`, capture live from this DPDK port ID instead of reading `--input_file`.                                                                                 |
| `--dpdk_eal_args`             | string  | `"-c 0x3"`| EAL args for `rte_eal_init` (space-separated). **Must include core selection via `-c <hex_mask>`** (≥ 2 bits: master + ≥ 1 worker; multiple worker bits → multi-thread RSS capture). Other typical args: `-a 0000:03:00.0`, `--file-prefix analyser`, `--socket-mem 1024`. |
| `--dpdk_mbuf_pool_size`       | int32   | `4095`    | mbuf pool size per DPDK device. Must be `2^q − 1`.                                                                                                                |
| `--duration_sec`              | int32   | `0`       | Stop capture after N seconds (`0` = no limit).                                                                                                                    |
| `--max_packets`               | uint64  | `0`       | Stop capture after N classified packets across all workers (`0` = no limit).                                                                                      |
| `--dpdk_stats_interval_sec`   | int32   | `1`       | NIC stats sample interval in seconds: `rx`, `cpu_missed` (= DPDK's `imissed`: NIC dropped because the host CPU couldn't drain the RX queue fast enough), `erroneous`, `mbuf_alloc_fail`. `0` disables periodic logging; a final summary is always emitted at stop. |

Stop conditions are OR-combined: SIGINT (Ctrl-C), `--duration_sec`, or
`--max_packets` — whichever fires first triggers a clean shutdown and writes
the configured CSVs.

## Usage

### Offline (pcap file)

sudo  ./analyser --input_file=<trace.pcap> --output_csv=<output.csv>

### Live (DPDK)

Requires a PcapPlusPlus build with DPDK support (see
[Building PcapPlusPlus with DPDK support](#building-pcapplusplus-with-dpdk-support)
above). If `cmake` prints `DPDK backend: ENABLED` here, the DPDK path is
compiled in.

At runtime, pass `--dpdk_port=<id>` instead of `--input_file`. Cores are
selected inside `--dpdk_eal_args` via `-c <hex>` (a DPDK EAL core mask; needs
at least 2 bits set — main + 1 worker). Any other standard EAL args
(`-a <pci>`, `--file-prefix`, `--socket-mem`, ...) can be appended to the same
string.

    sudo ./analyser --dpdk_port=0 --dpdk_eal_args="-c 0x3 -a 0000:03:00.0" \
                    --duration_sec=10 --output_csv=live.csv

Stop conditions (any of them triggers a clean shutdown + CSV write):
Ctrl-C (SIGINT), `--duration_sec=N`, or `--max_packets=N`.

### Header-size distribution

    ./analyser --input_file=<trace.pcap> --output_csv=<stats.csv> \
               --compute_header_sizes --output_header_sizes_csv=<hdr.csv>

Produces a long-format CSV (`Protocol,Header,Size_Bytes,Count`) with one row
per `(protocol bucket, IP|TCP, observed header size)` — useful for spotting
IPv4 options, IPv6 extension headers, and TCP options usage. UDP is omitted
(always 8 bytes).

