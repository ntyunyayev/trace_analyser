#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>

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

struct alignas(8) UserKey {
  std::array<uint8_t, 16> ip;
  bool isIPv6;

  UserKey() { std::memset(this, 0, sizeof(UserKey)); }

  bool operator==(const UserKey &other) const {
    return std::memcmp(this, &other, sizeof(UserKey)) == 0;
  }
};

namespace std {
template <> struct hash<UserKey> {
  std::size_t operator()(const UserKey &k) const {
    uint64_t buffer[3];
    std::memcpy(buffer, &k, sizeof(UserKey));

    uint64_t h = 0;
    const uint64_t kMul = 0x9ddfea08eb382d69ULL;

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

    h ^= (h >> 47);
    h *= kMul;
    h ^= (h >> 47);

    return static_cast<size_t>(h);
  }
};

template <> struct hash<FlowKey> {
  std::size_t operator()(const FlowKey &k) const {
    uint64_t buffer[5];
    std::memcpy(buffer, &k, sizeof(FlowKey));

    uint64_t h = 0;
    const uint64_t kMul = 0x9ddfea08eb382d69ULL;

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
  std::unordered_set<FlowKey> connections;
  std::unordered_set<UserKey> users;
  std::unordered_map<FlowKey, ConnDistStats> connDist;
  std::unordered_map<uint16_t, uint64_t> ipHeaderSizes;
  std::unordered_map<uint16_t, uint64_t> tcpHeaderSizes;
};

struct ProcessingContext {
  std::unordered_map<std::string, ProtocolStats> protocolData;
  uint64_t globalPacketIndex = 0;
  uint64_t packetsProcessed = 0;
};

struct L3Info {
  std::array<uint8_t, 16> srcBytes{}; // IPv4 uses only the first 4 bytes
  std::array<uint8_t, 16> dstBytes{};
  bool isV6 = false;
  const char *ipVerPrefix = "IPv4_";
  uint16_t headerLen = 0;
};

struct L4Info {
  uint16_t srcPort = 0;
  uint16_t dstPort = 0;
  std::string protocolName;
  uint16_t headerLen = 0;
  bool isTcp = false;
};
