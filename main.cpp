#include "helper.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional> // Required for std::hash
#include <gflags/gflags.h>
#include <iomanip>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>

// --- 1. The Key Struct ---
struct alignas(8) FlowKey {
  std::array<uint8_t, 16> ipA;
  std::array<uint8_t, 16> ipB;
  uint16_t portA;
  uint16_t portB;
  bool isIPv6;

  // 3 bytes of invisible padding are added here automatically by alignas(8)

  FlowKey() { std::memset(this, 0, sizeof(FlowKey)); }

  bool operator==(const FlowKey &other) const {
    return std::memcmp(this, &other, sizeof(FlowKey)) == 0;
  }
};
// --- 1. The Key Struct ---
struct alignas(8) UserKey {
  std::array<uint8_t, 16> ip;
  bool isIPv6;

  // 3 bytes of invisible padding are added here automatically by alignas(8)

  UserKey() { std::memset(this, 0, sizeof(UserKey)); }

  bool operator==(const UserKey &other) const {
    return std::memcmp(this, &other, sizeof(UserKey)) == 0;
  }
};
// --- 2. Standard Hash Specialization ---
// This allows you to use std::unordered_set<FlowKey> directly.
// 2. High-Performance Block Hash
namespace std {
template <> struct hash<UserKey> {
  std::size_t operator()(const UserKey &k) const {
    // We read the struct as 3 chunks of 64-bit integers.
    // Using memcpy is the "Strict Aliasing Safe" way to do this.
    // The compiler optimizes this memcpy away completely into register loads.

    uint64_t buffer[3];
    std::memcpy(buffer, &k, sizeof(UserKey)); // Copy 24 bytes

    // MurmurHash3-style mixing constants
    uint64_t h = 0;
    const uint64_t kMul = 0x9ddfea08eb382d69ULL;

    // Unrolled loop for the 3 blocks
    auto mix = [&](uint64_t block) {
      block *= kMul;
      block ^= (block >> 47);
      block *= kMul;
      h ^= block;
      h *= kMul;
    };

    mix(buffer[0]);
    mix(buffer[1]);
    mix(buffer[2]);

    // Final avalanche
    h ^= (h >> 47);
    h *= kMul;
    h ^= (h >> 47);

    return static_cast<size_t>(h);
  }
};

template <> struct hash<FlowKey> {
  std::size_t operator()(const FlowKey &k) const {
    // We read the struct as 5 chunks of 64-bit integers.
    // Using memcpy is the "Strict Aliasing Safe" way to do this.
    // The compiler optimizes this memcpy away completely into register loads.

    uint64_t buffer[5];
    std::memcpy(buffer, &k, sizeof(FlowKey)); // Copy 40 bytes

    // MurmurHash3-style mixing constants
    uint64_t h = 0;
    const uint64_t kMul = 0x9ddfea08eb382d69ULL;

    // Unrolled loop for the 5 blocks
    auto mix = [&](uint64_t block) {
      block *= kMul;
      block ^= (block >> 47);
      block *= kMul;
      h ^= block;
      h *= kMul;
    };

    mix(buffer[0]); // IP A (first half)
    mix(buffer[1]); // IP A (second half)
    mix(buffer[2]); // IP B (first half)
    mix(buffer[3]); // IP B (second half)
    mix(buffer[4]); // Ports + Bool + Padding

    // Final avalanche
    h ^= (h >> 47);
    h *= kMul;
    h ^= (h >> 47);

    return static_cast<size_t>(h);
  }
};
} // namespace std
struct ConnDistStats {
  uint64_t lastIdx = 0;
  uint64_t sum = 0;
  uint64_t samples = 0;
};

struct ProtocolStats {
  uint64_t packetCount = 0;
  uint64_t totalBytes = 0;
  std::unordered_set<FlowKey>
      connections;                   // Uses std::hash<FlowKey> automatically
  std::unordered_set<UserKey> users; // Uses std::hash<UserKey> automatically
  std::unordered_map<FlowKey, ConnDistStats> connDist;
};

int main(int argc, char *argv[]) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  std::string inputFile = FLAGS_input_file;
  std::string outputCsvFile = FLAGS_output_csv;

  auto pcap_reader(pcpp::IFileReaderDevice::getReader(inputFile));
  if (pcap_reader == nullptr || !pcap_reader->open()) {
    std::cerr << "Error: Cannot open input file" << std::endl;
    return 1;
  }

  pcpp::RawPacket rawPacket;
  std::unordered_map<std::string, ProtocolStats> protocol_data;
  uint64_t globalPacketIndex = 0;

  // Pre-allocate one key to reuse (avoid re-allocating on stack every loop)

  std::cout << "Processing pcap file..." << std::endl;

  uint64_t totalFileBytes = 0;
  struct stat fileStat;
  if (stat(inputFile.c_str(), &fileStat) == 0)
    totalFileBytes = static_cast<uint64_t>(fileStat.st_size);

  uint64_t bytesRead = 0;
  uint64_t packetsRead = 0;
  const uint64_t progressEvery = 10000;
  const bool isTty = isatty(fileno(stderr)) != 0;
  const int barWidth = 40;

  auto renderProgress = [&](bool finalFrame) {
    double pct = totalFileBytes > 0
                     ? 100.0 * static_cast<double>(bytesRead) / totalFileBytes
                     : 0.0;
    if (pct > 100.0)
      pct = 100.0;
    if (finalFrame)
      pct = 100.0;
    int filled = static_cast<int>(pct / 100.0 * barWidth);
    if (filled > barWidth)
      filled = barWidth;
    if (isTty) {
      std::cerr << "\r[";
      for (int i = 0; i < barWidth; ++i)
        std::cerr << (i < filled ? '#' : '-');
      std::cerr << "] " << std::fixed << std::setprecision(1) << pct << "% ("
                << packetsRead << " pkts)" << std::flush;
      if (finalFrame)
        std::cerr << std::endl;
    } else if (finalFrame) {
      std::cerr << "Processed " << packetsRead << " packets (" << std::fixed
                << std::setprecision(1) << pct << "%)" << std::endl;
    } else if (packetsRead % (progressEvery * 10) == 0) {
      std::cerr << "Processed " << packetsRead << " packets (" << std::fixed
                << std::setprecision(1) << pct << "%)" << std::endl;
    }
  };

  while (pcap_reader->getNextPacket(rawPacket)) {
    bytesRead += rawPacket.getRawDataLen() + 16;
    ++packetsRead;
    if (packetsRead % progressEvery == 0)
      renderProgress(false);
    pcpp::Packet parsedPacket(&rawPacket);

    const uint8_t *srcIPBytes = nullptr;
    const uint8_t *dstIPBytes = nullptr;
    bool isV6 = false;
    const char *ipVerPrefix = "IPv4_";

    pcpp::IPv4Address srcAddr4, dstAddr4;
    pcpp::IPv6Address srcAddr6, dstAddr6;
    FlowKey currentConnection;
    UserKey currentUser;

    // --- Layer 3: Network ---
    if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
      auto *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
      srcAddr4 = ipLayer->getSrcIPv4Address();
      dstAddr4 = ipLayer->getDstIPv4Address();
      srcIPBytes = srcAddr4.toBytes();
      dstIPBytes = dstAddr4.toBytes();
      isV6 = false;
      ipVerPrefix = "IPv4_";
    } else if (parsedPacket.isPacketOfType(pcpp::IPv6)) {
      auto *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
      srcAddr6 = ipLayer->getSrcIPv6Address();
      dstAddr6 = ipLayer->getDstIPv6Address();
      srcIPBytes = srcAddr6.toBytes();
      dstIPBytes = dstAddr6.toBytes();
      isV6 = true;
      ipVerPrefix = "IPv6_";
    } else {
      continue;
    }

    // --- Layer 4: Transport ---
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    std::string protocolName;

    auto get_proto_name = [&](uint16_t s, uint16_t d, const char *ver,
                              const std::string &type) {
      uint16_t minPort = std::min(s, d);
      std::string name = ver;
      if (minPort == 443) {
        name += (type == "TCP" ? "HTTPS/2" : "HTTPS/3");
      } else {
        name += "Unknown_" + type + "_" + std::to_string(minPort);
      }
      return name;
    };

    if (auto *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>()) {
      srcPort = tcpLayer->getSrcPort();
      dstPort = tcpLayer->getDstPort();
      protocolName = get_proto_name(srcPort, dstPort, ipVerPrefix, "TCP");
    } else if (auto *udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>()) {
      srcPort = udpLayer->getSrcPort();
      dstPort = udpLayer->getDstPort();
      protocolName = get_proto_name(srcPort, dstPort, ipVerPrefix, "UDP");
    } else {
      continue;
    }

    // --- Canonicalization ---
    currentConnection.isIPv6 = isV6;
    currentUser.isIPv6 = isV6;

    // Compare IPs to decide order (canonical direction)
    int cmp = std::memcmp(srcIPBytes, dstIPBytes, isV6 ? 16 : 4);

    if (cmp < 0 || (cmp == 0 && srcPort > dstPort)) {
      std::memcpy(currentConnection.ipA.data(), srcIPBytes, isV6 ? 16 : 4);
      std::memcpy(currentConnection.ipB.data(), dstIPBytes, isV6 ? 16 : 4);
      currentConnection.portA = srcPort;
      currentConnection.portB = dstPort;
    } else {
      std::memcpy(currentConnection.ipA.data(), dstIPBytes, isV6 ? 16 : 4);
      std::memcpy(currentConnection.ipB.data(), srcIPBytes, isV6 ? 16 : 4);
      currentConnection.portA = dstPort;
      currentConnection.portB = srcPort;
    }
    if (srcPort > dstPort) {
      // Src is likely the Client (User)
      std::memcpy(currentUser.ip.data(), srcIPBytes, isV6 ? 16 : 4);
    } else {
      // Dst is likely the Client (User)
      std::memcpy(currentUser.ip.data(), dstIPBytes, isV6 ? 16 : 4);
    }

    // --- Stats Update ---
    auto &stats = protocol_data[protocolName];
    stats.packetCount++;
    stats.totalBytes += rawPacket.getRawDataLen();
    stats.connections.insert(currentConnection);
    stats.users.insert(currentUser);

    ++globalPacketIndex;
    if (FLAGS_compute_packet_distance) {
      auto &cd = stats.connDist[currentConnection];
      if (cd.lastIdx != 0) {
        cd.sum += (globalPacketIndex - cd.lastIdx);
        cd.samples++;
      }
      cd.lastIdx = globalPacketIndex;
    }
  }

  renderProgress(true);
  pcap_reader->close();

  // --- Post-Processing: Calculate Grand Totals ---
  uint64_t grandTotalBytes = 0;
  uint64_t grandTotalPackets = 0;
  uint64_t grandTotalConnections = 0;
  uint64_t grandTotalUsers = 0;

  for (const auto &kv : protocol_data) {
    grandTotalBytes += kv.second.totalBytes;
    grandTotalPackets += kv.second.packetCount;
    grandTotalConnections += kv.second.connections.size();
    grandTotalUsers += kv.second.users.size();
  }

  // Sort Results (Sorting by Volume)
  std::vector<std::pair<std::string, ProtocolStats>> sorted_results(
      protocol_data.begin(), protocol_data.end());
  std::sort(sorted_results.begin(), sorted_results.end(),
            [](const auto &a, const auto &b) {
              return a.second.totalBytes > b.second.totalBytes;
            });

  // --- Output CSV ---
  std::ofstream csvFile(outputCsvFile);
  if (csvFile.is_open()) {
    csvFile << "Protocol,Packet_Count,Pct_Packets,Total_Bytes,Pct_Bytes,"
               "Distinct_Connections,Pct_Connections,Distinct_Users,"
               "Pct_Users";
    if (FLAGS_compute_packet_distance)
      csvFile << ",Conns_With_Samples,Mean_Conn_Avg_Dist,Median_Conn_Avg_Dist";
    csvFile << "\n";
    csvFile << std::fixed << std::setprecision(4);

    for (const auto &item : sorted_results) {
      double pctBytes = 0.0;
      double pctPackets = 0.0;
      double pctConns = 0.0;
      double pctUsers = 0.0;

      if (grandTotalBytes > 0)
        pctBytes =
            (static_cast<double>(item.second.totalBytes) / grandTotalBytes) *
            100.0;

      if (grandTotalPackets > 0)
        pctPackets =
            (static_cast<double>(item.second.packetCount) / grandTotalPackets) *
            100.0;

      if (grandTotalConnections > 0)
        pctConns = (static_cast<double>(item.second.connections.size()) /
                    grandTotalConnections) *
                   100.0;
      if (grandTotalUsers > 0)
        pctUsers =
            (static_cast<double>(item.second.users.size()) / grandTotalUsers) *
            100.0;

      csvFile << item.first << "," << item.second.packetCount << ","
              << pctPackets << "," << item.second.totalBytes << "," << pctBytes
              << "," << item.second.connections.size() << "," << pctConns << ","
              << item.second.users.size() << "," << pctUsers;
      if (FLAGS_compute_packet_distance) {
        std::vector<double> connAvgs;
        connAvgs.reserve(item.second.connDist.size());
        for (const auto &ckv : item.second.connDist) {
          if (ckv.second.samples > 0)
            connAvgs.push_back(static_cast<double>(ckv.second.sum) /
                               ckv.second.samples);
        }
        double meanOfAvgs = 0.0;
        double medianOfAvgs = 0.0;
        if (!connAvgs.empty()) {
          double s = 0.0;
          for (double v : connAvgs)
            s += v;
          meanOfAvgs = s / connAvgs.size();
          size_t mid = connAvgs.size() / 2;
          std::nth_element(connAvgs.begin(), connAvgs.begin() + mid,
                           connAvgs.end());
          medianOfAvgs = connAvgs[mid];
          if ((connAvgs.size() & 1u) == 0u) {
            double lower = *std::max_element(connAvgs.begin(),
                                             connAvgs.begin() + mid);
            medianOfAvgs = 0.5 * (medianOfAvgs + lower);
          }
        }
        csvFile << "," << connAvgs.size() << "," << meanOfAvgs << ","
                << medianOfAvgs;
      }
      csvFile << "\n";
    }
    csvFile.close();
    std::cout << "CSV written to " << outputCsvFile << std::endl;
  } else {
    std::cerr << "Error writing CSV." << std::endl;
    return 1;
  }

  if (FLAGS_compute_packet_distance && !FLAGS_output_connections_csv.empty()) {
    std::ofstream connCsv(FLAGS_output_connections_csv);
    if (!connCsv.is_open()) {
      std::cerr << "Error writing per-connection CSV." << std::endl;
      return 1;
    }
    connCsv << "Protocol,IpA,PortA,IpB,PortB,Packet_Count,Gap_Samples,"
               "Avg_Packet_Distance\n";
    connCsv << std::fixed << std::setprecision(4);
    for (const auto &item : sorted_results) {
      for (const auto &ckv : item.second.connDist) {
        const FlowKey &fk = ckv.first;
        const ConnDistStats &cd = ckv.second;
        std::string ipAStr;
        std::string ipBStr;
        if (fk.isIPv6) {
          ipAStr = pcpp::IPv6Address(fk.ipA.data()).toString();
          ipBStr = pcpp::IPv6Address(fk.ipB.data()).toString();
        } else {
          ipAStr = pcpp::IPv4Address(fk.ipA.data()).toString();
          ipBStr = pcpp::IPv4Address(fk.ipB.data()).toString();
        }
        uint64_t pktCount = cd.samples + 1;
        double avg = cd.samples > 0
                         ? static_cast<double>(cd.sum) / cd.samples
                         : 0.0;
        connCsv << item.first << "," << ipAStr << "," << fk.portA << ","
                << ipBStr << "," << fk.portB << "," << pktCount << ","
                << cd.samples << "," << avg << "\n";
      }
    }
    connCsv.close();
    std::cout << "Per-connection CSV written to "
              << FLAGS_output_connections_csv << std::endl;
  }

  return 0;
}

