# What is the project about?

A per-protocol traffic analyser built on PcapPlusPlus. It reads either an
offline pcap/pcapng file or captures live from a DPDK-bound NIC (single-thread
or multi-core RSS), classifies each packet into a protocol bucket
(IPv4/IPv6 × TCP/UDP, with HTTPS/2 and HTTPS/3 broken out separately), and
emits one or more CSV reports.

For each protocol bucket the main report contains:

- packet count, total bytes
- distinct 5-tuple connections
- distinct client-side IPs ("users", inferred from the higher-port endpoint)

Optional add-ons (each gated by its own flag, see the [Flags](#flags) section):

- per-connection average packet-index distance between consecutive packets
  of the same flow (useful for studying interleaving)
- per-protocol distribution of IP and TCP header sizes (useful for spotting
  IPv4/IPv6 options usage, IPv6 extension headers, and TCP-options
  negotiation rates such as timestamps and SACK)
- when running over DPDK: periodic and final NIC drop counters
  (`rxPacketsDroppedByHW` etc.) so you can tell whether your CPU is keeping
  up with the wire

## Prerequisites

PcapPlusPlus and DPDK are vendored as git submodules under `external/` and
built once into project-local prefixes; they don't need to be installed
globally. You only need DPDK's own build/runtime deps system-wide:

    # Debian / Ubuntu
    sudo apt install python3 meson ninja-build pkg-config \
                     libnuma-dev libpcap-dev linux-headers-$(uname -r) \
                     build-essential cmake

    # RHEL / Fedora
    sudo dnf install python3 meson ninja-build pkg-config \
                     numactl-devel libpcap-devel kernel-devel \
                     gcc-c++ cmake

For DPDK runtime (only needed for the live-capture binary): mount hugepages
and bind your NIC to `vfio-pci` (or `igb_uio`) per the standard DPDK setup.

CLI flags are parsed via POSIX `getopt_long` (libc); no third-party flag
library is needed.

## Building

    git clone --recursive https://...trace_analyser.git
    cd trace_analyser
    ./build.sh dpdk        # first run: ~10 min DPDK + ~3 min pcpp + analyser

If you forgot `--recursive` on the original clone:

    git submodule update --init --recursive

`./build.sh` modes:

    ./build.sh           # auto-detect (uses DPDK if its install is built)  -> ./analyser
    ./build.sh dpdk      # build vendored DPDK + pcpp(dpdk) + analyser      -> ./analyser
    ./build.sh nodpdk    # build vendored pcpp(nodpdk) + analyser, no DPDK  -> ./analyser
    ./build.sh both      # builds both flavours side-by-side                -> ./analyser-dpdk + ./analyser-nodpdk
    ./build.sh deps-dpdk # only build the vendored DPDK
    ./build.sh deps-pcpp # only build the vendored PcapPlusPlus
    ./build.sh clean     # rm -rf all build dirs + vendored install dirs

Subsequent `./build.sh dpdk` invocations skip the DPDK and pcpp steps (the
project-local install dirs at `external/dpdk/install/` and
`external/PcapPlusPlus/install-{dpdk,nodpdk}/` are reused as caches).

The analyser binary has an `$ORIGIN`-relative RPATH baked in that points at
the vendored DPDK install, so it finds `librte_*.so` at runtime without
needing `LD_LIBRARY_PATH`. Same for pcpp — it's statically linked, so no
`libPcap++.so` runtime dep either.

Equivalent direct CMake invocation (after the deps are built):
`cmake -S . -B build -DWITH_DPDK=AUTO|ON|OFF && cmake --build build`.

## Flags

Flags are parsed with POSIX `getopt_long`; both `--name=value` and `--name
value` are accepted. `./analyser --help` prints the live list.

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

