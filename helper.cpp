#include "helper.h"

DEFINE_string(input_file, "input.pcap", "Input file");

DEFINE_string(output_csv, "stats.csv", "Path to the output CSV file");

DEFINE_bool(compute_packet_distance, false,
            "Compute per-protocol average packet-index distance between "
            "consecutive packets of the same connection");

DEFINE_string(output_connections_csv, "",
              "If set, write per-connection CSV with packet-distance info to "
              "this path (requires --compute_packet_distance)");

DEFINE_bool(compute_header_sizes, false,
            "Count per-protocol distributions of IP and TCP header sizes");

DEFINE_string(output_header_sizes_csv, "",
              "If set, write header-size distribution CSV to this path "
              "(requires --compute_header_sizes)");

DEFINE_int32(dpdk_port, -1,
             "If >=0, capture live from this DPDK port ID instead of reading "
             "--input_file");

DEFINE_int32(dpdk_mbuf_pool_size, 4095, "mbuf pool size per DPDK device");

DEFINE_string(dpdk_eal_args, "-c 0x3",
              "EAL args for rte_eal_init (space-separated). Must include "
              "core selection via \"-c <hex_mask>\" (at least 2 cores: main + "
              "1 worker). Other typical args: \"-a 0000:03:00.0\", "
              "\"--file-prefix analyser\", \"--socket-mem 1024\"");

DEFINE_int32(duration_sec, 0, "Stop capture after N seconds (0 = no limit)");

DEFINE_uint64(max_packets, 0, "Stop capture after N packets (0 = no limit)");
