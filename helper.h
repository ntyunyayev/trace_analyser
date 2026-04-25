#pragma once

#include <gflags/gflags.h>

DECLARE_string(input_file);
DECLARE_string(output_csv);

DECLARE_bool(compute_packet_distance);
DECLARE_string(output_connections_csv);

DECLARE_bool(compute_header_sizes);
DECLARE_string(output_header_sizes_csv);

DECLARE_int32(dpdk_port);
DECLARE_int32(dpdk_mbuf_pool_size);
DECLARE_string(dpdk_eal_args);

DECLARE_int32(duration_sec);
DECLARE_uint64(max_packets);

DECLARE_int32(dpdk_stats_interval_sec);
