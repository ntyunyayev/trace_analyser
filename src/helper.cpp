#include "helper.h"

#include <cstdint>
#include <cstdlib>
#include <getopt.h>
#include <iostream>
#include <string>

std::string FLAGS_input_file = "input.pcap";
std::string FLAGS_output_csv = "stats.csv";

bool FLAGS_compute_packet_distance = false;
std::string FLAGS_output_connections_csv = "";

bool FLAGS_compute_header_sizes = false;
std::string FLAGS_output_header_sizes_csv = "";

int32_t FLAGS_dpdk_port = -1;
int32_t FLAGS_dpdk_mbuf_pool_size = 4095;
std::string FLAGS_dpdk_eal_args = "-c 0x3";

int32_t FLAGS_duration_sec = 0;
uint64_t FLAGS_max_packets = 0;
int32_t FLAGS_dpdk_stats_interval_sec = 1;

namespace {

enum : int {
    OPT_INPUT_FILE = 1000,
    OPT_OUTPUT_CSV,
    OPT_COMPUTE_PACKET_DISTANCE,
    OPT_OUTPUT_CONNECTIONS_CSV,
    OPT_COMPUTE_HEADER_SIZES,
    OPT_OUTPUT_HEADER_SIZES_CSV,
    OPT_DPDK_PORT,
    OPT_DPDK_MBUF_POOL_SIZE,
    OPT_DPDK_EAL_ARGS,
    OPT_DURATION_SEC,
    OPT_MAX_PACKETS,
    OPT_DPDK_STATS_INTERVAL_SEC,
    OPT_HELP,
};

const struct option kLongOpts[] = {
    {"input_file", required_argument, nullptr, OPT_INPUT_FILE},
    {"output_csv", required_argument, nullptr, OPT_OUTPUT_CSV},
    {"compute_packet_distance", no_argument, nullptr, OPT_COMPUTE_PACKET_DISTANCE},
    {"output_connections_csv", required_argument, nullptr, OPT_OUTPUT_CONNECTIONS_CSV},
    {"compute_header_sizes", no_argument, nullptr, OPT_COMPUTE_HEADER_SIZES},
    {"output_header_sizes_csv", required_argument, nullptr, OPT_OUTPUT_HEADER_SIZES_CSV},
    {"dpdk_port", required_argument, nullptr, OPT_DPDK_PORT},
    {"dpdk_mbuf_pool_size", required_argument, nullptr, OPT_DPDK_MBUF_POOL_SIZE},
    {"dpdk_eal_args", required_argument, nullptr, OPT_DPDK_EAL_ARGS},
    {"duration_sec", required_argument, nullptr, OPT_DURATION_SEC},
    {"max_packets", required_argument, nullptr, OPT_MAX_PACKETS},
    {"dpdk_stats_interval_sec", required_argument, nullptr, OPT_DPDK_STATS_INTERVAL_SEC},
    {"help", no_argument, nullptr, OPT_HELP},
    {nullptr, 0, nullptr, 0},
};

void printHelp(const char *prog) {
    std::cout
        << "Usage: " << prog << " [options]\n"
        << "\n"
        << "Input/output:\n"
        << "  --input_file=<path>                 Input pcap (default: input.pcap)\n"
        << "  --output_csv=<path>                 Per-protocol summary CSV (default: stats.csv)\n"
        << "\n"
        << "Per-connection packet distance:\n"
        << "  --compute_packet_distance           Enable per-flow distance metric\n"
        << "  --output_connections_csv=<path>     Per-connection CSV (requires "
           "--compute_packet_distance)\n"
        << "\n"
        << "Header-size distribution:\n"
        << "  --compute_header_sizes              Enable IP/TCP header-size histogram\n"
        << "  --output_header_sizes_csv=<path>    Header-size CSV (requires "
           "--compute_header_sizes)\n"
        << "\n"
        << "DPDK live capture (requires the dpdk-flavour binary):\n"
        << "  --dpdk_port=<int>                   DPDK port id; <0 means file mode (default: -1)\n"
        << "  --dpdk_eal_args=<str>               EAL args (default: \"-c 0x3\")\n"
        << "  --dpdk_mbuf_pool_size=<2^q-1>       mbuf pool size (default: 4095)\n"
        << "  --duration_sec=<int>                Stop after N seconds (0 = no limit)\n"
        << "  --max_packets=<uint>                Stop after N packets (0 = no limit)\n"
        << "  --dpdk_stats_interval_sec=<int>     NIC stats sample period in s (default: 1)\n"
        << "\n"
        << "  --help                              Print this message and exit\n";
}

} // namespace

void parseArgs(int argc, char **argv) {
    int c;
    while ((c = getopt_long(argc, argv, "", kLongOpts, nullptr)) != -1) {
        switch (c) {
        case OPT_INPUT_FILE:
            FLAGS_input_file = optarg;
            break;
        case OPT_OUTPUT_CSV:
            FLAGS_output_csv = optarg;
            break;
        case OPT_COMPUTE_PACKET_DISTANCE:
            FLAGS_compute_packet_distance = true;
            break;
        case OPT_OUTPUT_CONNECTIONS_CSV:
            FLAGS_output_connections_csv = optarg;
            break;
        case OPT_COMPUTE_HEADER_SIZES:
            FLAGS_compute_header_sizes = true;
            break;
        case OPT_OUTPUT_HEADER_SIZES_CSV:
            FLAGS_output_header_sizes_csv = optarg;
            break;
        case OPT_DPDK_PORT:
            FLAGS_dpdk_port = std::atoi(optarg);
            break;
        case OPT_DPDK_MBUF_POOL_SIZE:
            FLAGS_dpdk_mbuf_pool_size = std::atoi(optarg);
            break;
        case OPT_DPDK_EAL_ARGS:
            FLAGS_dpdk_eal_args = optarg;
            break;
        case OPT_DURATION_SEC:
            FLAGS_duration_sec = std::atoi(optarg);
            break;
        case OPT_MAX_PACKETS:
            FLAGS_max_packets = std::strtoull(optarg, nullptr, 10);
            break;
        case OPT_DPDK_STATS_INTERVAL_SEC:
            FLAGS_dpdk_stats_interval_sec = std::atoi(optarg);
            break;
        case OPT_HELP:
            printHelp(argv[0]);
            std::exit(0);
        case '?':
        default:
            std::exit(2);
        }
    }
}
