#include "core_types.h"
#include "dpdk_backend.h"
#include "helper.h"
#include "processing.h"

#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Logger.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/RawPacket.h>

static int runFileReader(ProcessingContext &ctx) {
    const std::string &inputFile = FLAGS_input_file;

    auto pcap_reader(pcpp::IFileReaderDevice::getReader(inputFile));
    if (pcap_reader == nullptr || !pcap_reader->open()) {
        std::cerr << "Error: Cannot open input file" << std::endl;
        return 1;
    }

    pcpp::RawPacket rawPacket;

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
        double pct =
            totalFileBytes > 0 ? 100.0 * static_cast<double>(bytesRead) / totalFileBytes : 0.0;
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
            std::cerr << "] " << std::fixed << std::setprecision(1) << pct << "% (" << packetsRead
                      << " pkts)" << std::flush;
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
        processPacket(rawPacket, ctx);
    }

    renderProgress(true);
    pcap_reader->close();
    return 0;
}

int main(int argc, char *argv[]) {
    parseArgs(argc, argv);
    // Silence pcpp's DnsLayer parser errors. We don't consume the DNS layer,
    // but pcpp's Packet ctor auto-parses every UDP/53 payload and logs an
    // error per malformed-looking name pointer — at line rate that's pure
    // overhead. Set to Off to short-circuit at the cheap shouldLog() check.
    pcpp::Logger::getInstance().setLogLevel(pcpp::PacketLogModuleDnsLayer,
                                            pcpp::LogLevel::Off);

    const std::string outputCsvFile = FLAGS_output_csv;

    ProcessingContext ctx;

    if (FLAGS_dpdk_port >= 0) {
        if (run_dpdk_capture(ctx) != 0)
            return 1;
    } else {
        if (runFileReader(ctx) != 0)
            return 1;
    }

    // --- Post-Processing: Calculate Grand Totals ---
    uint64_t grandTotalBytes = 0;
    uint64_t grandTotalPackets = 0;
    uint64_t grandTotalConnections = 0;
    uint64_t grandTotalUsers = 0;

    for (const auto &kv : ctx.protocolData) {
        grandTotalBytes += kv.second.totalBytes;
        grandTotalPackets += kv.second.packetCount;
        grandTotalConnections += kv.second.connections.size();
        grandTotalUsers += kv.second.users.size();
    }

    // Sort Results (Sorting by Volume)
    std::vector<std::pair<std::string, ProtocolStats>> sorted_results(ctx.protocolData.begin(),
                                                                      ctx.protocolData.end());
    std::sort(sorted_results.begin(), sorted_results.end(), [](const auto &a, const auto &b) {
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
                pctBytes = (static_cast<double>(item.second.totalBytes) / grandTotalBytes) * 100.0;

            if (grandTotalPackets > 0)
                pctPackets =
                    (static_cast<double>(item.second.packetCount) / grandTotalPackets) * 100.0;

            if (grandTotalConnections > 0)
                pctConns =
                    (static_cast<double>(item.second.connections.size()) / grandTotalConnections) *
                    100.0;
            if (grandTotalUsers > 0)
                pctUsers =
                    (static_cast<double>(item.second.users.size()) / grandTotalUsers) * 100.0;

            csvFile << item.first << "," << item.second.packetCount << "," << pctPackets << ","
                    << item.second.totalBytes << "," << pctBytes << ","
                    << item.second.connections.size() << "," << pctConns << ","
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
                    std::nth_element(connAvgs.begin(), connAvgs.begin() + mid, connAvgs.end());
                    medianOfAvgs = connAvgs[mid];
                    if ((connAvgs.size() & 1u) == 0u) {
                        double lower = *std::max_element(connAvgs.begin(), connAvgs.begin() + mid);
                        medianOfAvgs = 0.5 * (medianOfAvgs + lower);
                    }
                }
                csvFile << "," << connAvgs.size() << "," << meanOfAvgs << "," << medianOfAvgs;
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
                double avg = cd.samples > 0 ? static_cast<double>(cd.sum) / cd.samples : 0.0;
                connCsv << item.first << "," << ipAStr << "," << fk.portA << "," << ipBStr << ","
                        << fk.portB << "," << pktCount << "," << cd.samples << "," << avg << "\n";
            }
        }
        connCsv.close();
        std::cout << "Per-connection CSV written to " << FLAGS_output_connections_csv << std::endl;
    }

    if (FLAGS_compute_header_sizes && !FLAGS_output_header_sizes_csv.empty()) {
        std::ofstream hdrCsv(FLAGS_output_header_sizes_csv);
        if (!hdrCsv.is_open()) {
            std::cerr << "Error writing header-sizes CSV." << std::endl;
            return 1;
        }
        hdrCsv << "Protocol,Header,Size_Bytes,Count\n";
        for (const auto &item : sorted_results) {
            for (const auto &kv : item.second.ipHeaderSizes)
                hdrCsv << item.first << ",IP," << kv.first << "," << kv.second << "\n";
            for (const auto &kv : item.second.tcpHeaderSizes)
                hdrCsv << item.first << ",TCP," << kv.first << "," << kv.second << "\n";
        }
        hdrCsv.close();
        std::cout << "Header-sizes CSV written to " << FLAGS_output_header_sizes_csv << std::endl;
    }

    return 0;
}
