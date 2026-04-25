#include "processing.h"
#include "helper.h"

#include <algorithm>
#include <cstring>
#include <string>

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>

static bool extractL3(pcpp::Packet &pkt, L3Info &out) {
    if (pkt.isPacketOfType(pcpp::IPv4)) {
        auto *ipLayer = pkt.getLayerOfType<pcpp::IPv4Layer>();
        auto srcAddr = ipLayer->getSrcIPv4Address();
        auto dstAddr = ipLayer->getDstIPv4Address();
        std::memcpy(out.srcBytes.data(), srcAddr.toBytes(), 4);
        std::memcpy(out.dstBytes.data(), dstAddr.toBytes(), 4);
        out.isV6 = false;
        out.ipVerPrefix = "IPv4_";
        out.headerLen = static_cast<uint16_t>(ipLayer->getHeaderLen());
        return true;
    }
    if (pkt.isPacketOfType(pcpp::IPv6)) {
        auto *ipLayer = pkt.getLayerOfType<pcpp::IPv6Layer>();
        auto srcAddr = ipLayer->getSrcIPv6Address();
        auto dstAddr = ipLayer->getDstIPv6Address();
        std::memcpy(out.srcBytes.data(), srcAddr.toBytes(), 16);
        std::memcpy(out.dstBytes.data(), dstAddr.toBytes(), 16);
        out.isV6 = true;
        out.ipVerPrefix = "IPv6_";
        out.headerLen = static_cast<uint16_t>(ipLayer->getHeaderLen());
        return true;
    }
    return false;
}

static bool extractL4(pcpp::Packet &pkt, const char *ipVerPrefix, L4Info &out) {
    auto protoName = [ipVerPrefix](uint16_t s, uint16_t d, bool isTcp) {
        uint16_t minPort = std::min(s, d);
        std::string name = ipVerPrefix;
        if (minPort == 443) {
            name += (isTcp ? "HTTPS/2" : "HTTPS/3");
        } else {
            name += isTcp ? "Unknown_TCP_" : "Unknown_UDP_";
            name += std::to_string(minPort);
        }
        return name;
    };

    if (auto *tcpLayer = pkt.getLayerOfType<pcpp::TcpLayer>()) {
        out.srcPort = tcpLayer->getSrcPort();
        out.dstPort = tcpLayer->getDstPort();
        out.protocolName = protoName(out.srcPort, out.dstPort, true);
        out.headerLen = static_cast<uint16_t>(tcpLayer->getHeaderLen());
        out.isTcp = true;
        return true;
    }
    if (auto *udpLayer = pkt.getLayerOfType<pcpp::UdpLayer>()) {
        out.srcPort = udpLayer->getSrcPort();
        out.dstPort = udpLayer->getDstPort();
        out.protocolName = protoName(out.srcPort, out.dstPort, false);
        out.headerLen = static_cast<uint16_t>(udpLayer->getHeaderLen());
        out.isTcp = false;
        return true;
    }
    return false;
}

static void canonicalizeFlow(const L3Info &l3, const L4Info &l4, FlowKey &conn, UserKey &user) {
    conn.isIPv6 = l3.isV6;
    user.isIPv6 = l3.isV6;

    const size_t ipLen = l3.isV6 ? 16 : 4;
    const uint8_t *srcBytes = l3.srcBytes.data();
    const uint8_t *dstBytes = l3.dstBytes.data();

    int cmp = std::memcmp(srcBytes, dstBytes, ipLen);
    if (cmp < 0 || (cmp == 0 && l4.srcPort > l4.dstPort)) {
        std::memcpy(conn.ipA.data(), srcBytes, ipLen);
        std::memcpy(conn.ipB.data(), dstBytes, ipLen);
        conn.portA = l4.srcPort;
        conn.portB = l4.dstPort;
    } else {
        std::memcpy(conn.ipA.data(), dstBytes, ipLen);
        std::memcpy(conn.ipB.data(), srcBytes, ipLen);
        conn.portA = l4.dstPort;
        conn.portB = l4.srcPort;
    }

    // Higher-port side is heuristically the client.
    if (l4.srcPort > l4.dstPort)
        std::memcpy(user.ip.data(), srcBytes, ipLen);
    else
        std::memcpy(user.ip.data(), dstBytes, ipLen);
}

static void updateStats(ProcessingContext &ctx, const L3Info &l3, const L4Info &l4, uint64_t bytes,
                        const FlowKey &conn, const UserKey &user) {
    auto &stats = ctx.protocolData[l4.protocolName];
    stats.packetCount++;
    stats.totalBytes += bytes;
    stats.connections.insert(conn);
    stats.users.insert(user);

    ++ctx.globalPacketIndex;
    ++ctx.packetsProcessed;
    if (FLAGS_compute_packet_distance) {
        auto &cd = stats.connDist[conn];
        if (cd.lastIdx != 0) {
            cd.sum += (ctx.globalPacketIndex - cd.lastIdx);
            cd.samples++;
        }
        cd.lastIdx = ctx.globalPacketIndex;
    }
    if (FLAGS_compute_header_sizes) {
        ++stats.ipHeaderSizes[l3.headerLen];
        if (l4.isTcp)
            ++stats.tcpHeaderSizes[l4.headerLen];
    }
}

void processPacket(pcpp::RawPacket &rawPacket, ProcessingContext &ctx) {
    pcpp::Packet parsedPacket(&rawPacket);

    L3Info l3;
    if (!extractL3(parsedPacket, l3))
        return;

    L4Info l4;
    if (!extractL4(parsedPacket, l3.ipVerPrefix, l4))
        return;

    FlowKey conn;
    UserKey user;
    canonicalizeFlow(l3, l4, conn, user);

    updateStats(ctx, l3, l4, rawPacket.getRawDataLen(), conn, user);
}
