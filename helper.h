#pragma once

#include <gflags/gflags.h>

DEFINE_string(input_file, "input.pcap", "Input file");

DEFINE_string(output_csv, "stats.csv", "Path to the output CSV file");

DEFINE_bool(compute_packet_distance, false,
            "Compute per-protocol average packet-index distance between "
            "consecutive packets of the same connection");

DEFINE_string(output_connections_csv, "",
              "If set, write per-connection CSV with packet-distance info to "
              "this path (requires --compute_packet_distance)");

