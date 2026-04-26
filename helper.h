#pragma once

#include <cstdint>
#include <string>

extern std::string FLAGS_input_file;
extern std::string FLAGS_output_csv;

extern bool FLAGS_compute_packet_distance;
extern std::string FLAGS_output_connections_csv;

extern bool FLAGS_compute_header_sizes;
extern std::string FLAGS_output_header_sizes_csv;

extern int32_t FLAGS_dpdk_port;
extern int32_t FLAGS_dpdk_mbuf_pool_size;
extern std::string FLAGS_dpdk_eal_args;

extern int32_t FLAGS_duration_sec;
extern uint64_t FLAGS_max_packets;
extern int32_t FLAGS_dpdk_stats_interval_sec;

// Parse command-line flags into the FLAGS_* globals using POSIX getopt_long.
// Exits the process on --help (status 0) or on unknown flags (status 2).
void parseArgs(int argc, char **argv);
