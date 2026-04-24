# What is the project about?


This is a small project, that aims to provide a script to analyse the protocol distribution from large traces. It relies on PCAP++.

The tool provides for each protocol, the total number of packets, bytes and connections.

## Prerequisites

- PCAP++
- GFLAG
- (optional, for the DPDK backend) DPDK, and PcapPlusPlus built with `-DPCAPPP_USE_DPDK=ON`

## Usage

### Offline (pcap file)

sudo  ./analyser --input_file=<trace.pcap> --output_csv=<output.csv>

### Live (DPDK)

Requires PcapPlusPlus to have been built with DPDK support. If `cmake` prints
`DPDK backend: ENABLED` for this project, the DPDK path is compiled in; if it
prints `DISABLED`, rebuild PcapPlusPlus against DPDK first, e.g.:

    cd <PcapPlusPlus-src>/build
    cmake -DPCAPPP_USE_DPDK=ON -DDPDK_ROOT=<dpdk-install-prefix> ..
    make -j && sudo make install

Then rebuild this project. At runtime, pass `--dpdk_port=<id>` instead of
`--input_file`. Cores are selected inside `--dpdk_eal_args` via `-c <hex>` (a
DPDK EAL core mask; needs at least 2 bits set — main + 1 worker). Any other
standard EAL args (`-a <pci>`, `--file-prefix`, `--socket-mem`, ...) can be
appended to the same string.

    sudo ./analyser --dpdk_port=0 --dpdk_eal_args="-c 0x3 -a 0000:03:00.0" \
                    --duration_sec=10 --output_csv=live.csv

Stop conditions (any of them triggers a clean shutdown + CSV write):
Ctrl-C (SIGINT), `--duration_sec=N`, or `--max_packets=N`.

