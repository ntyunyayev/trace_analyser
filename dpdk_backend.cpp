#include "dpdk_backend.h"
#include "helper.h"
#include "processing.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <pcapplusplus/DpdkDevice.h>
#include <pcapplusplus/DpdkDeviceList.h>
#include <pcapplusplus/MBufRawPacket.h>

namespace {

std::atomic<bool> g_stop{false};
void onSigint(int /*sig*/) {
    g_stop.store(true);
}

// Per-worker state, indexed by DPDK lcore id (the threadId passed by pcpp into
// the callback). MAX_NUM_OF_CORES is pcpp's compile-time cap (= 32).
struct DpdkSharedState {
    std::array<ProcessingContext, MAX_NUM_OF_CORES> contexts{};
};

void onDpdkPacketsArrive(pcpp::MBufRawPacket *packets, uint32_t numOfPackets, uint8_t threadId,
                         pcpp::DpdkDevice * /*device*/, void *userCookie) {
    auto *shared = static_cast<DpdkSharedState *>(userCookie);
    ProcessingContext &ctx = shared->contexts[threadId];
    for (uint32_t i = 0; i < numOfPackets; ++i) {
        processPacket(packets[i], ctx);
    }
}

// Tokenize a space-separated EAL-args string. Extracts "-c <hex>" (and
// "-c<hex>") into the returned coreMask and leaves every other token in
// `argvOut`. Storage for argv C-strings lives in `storage`, which must
// outlive the argv.
uint64_t extractCoreMask(const std::string &raw, std::vector<std::string> &storage,
                         std::vector<char *> &argvOut) {
    uint64_t coreMask = 0;
    bool haveMask = false;
    std::istringstream iss(raw);
    std::string tok;
    while (iss >> tok) {
        if (tok == "-c") {
            std::string next;
            if (!(iss >> next)) {
                std::cerr << "--dpdk_eal_args: \"-c\" needs an argument\n";
                std::exit(1);
            }
            coreMask = std::stoull(next, nullptr, 0);
            haveMask = true;
            continue;
        }
        if (tok.rfind("-c", 0) == 0 && tok.size() > 2) {
            coreMask = std::stoull(tok.substr(2), nullptr, 0);
            haveMask = true;
            continue;
        }
        if (tok == "-l" || tok.rfind("-l", 0) == 0) {
            std::cerr << "--dpdk_eal_args: core-list (\"-l ...\") not supported; "
                         "use \"-c <hex_mask>\"\n";
            std::exit(1);
        }
        storage.push_back(std::move(tok));
    }
    for (auto &s : storage)
        argvOut.push_back(&s[0]);
    if (!haveMask) {
        std::cerr << "--dpdk_eal_args must specify cores via \"-c <hex_mask>\"\n";
        std::exit(1);
    }
    return coreMask;
}

// RSS shards flows across workers, so connDist keys are disjoint per thread.
// On collision (asymmetric RSS / fragments) we keep the first; per-thread
// distance values are not meaningful to sum.
void mergeInto(ProcessingContext &dst, const ProcessingContext &src) {
    for (const auto &kv : src.protocolData) {
        auto &out = dst.protocolData[kv.first];
        out.packetCount += kv.second.packetCount;
        out.totalBytes += kv.second.totalBytes;
        out.connections.insert(kv.second.connections.begin(), kv.second.connections.end());
        out.users.insert(kv.second.users.begin(), kv.second.users.end());
        for (const auto &ck : kv.second.connDist)
            out.connDist.emplace(ck.first, ck.second);
        for (const auto &hk : kv.second.ipHeaderSizes)
            out.ipHeaderSizes[hk.first] += hk.second;
        for (const auto &hk : kv.second.tcpHeaderSizes)
            out.tcpHeaderSizes[hk.first] += hk.second;
    }
    dst.globalPacketIndex += src.globalPacketIndex;
    dst.packetsProcessed += src.packetsProcessed;
}

uint64_t totalProcessed(const DpdkSharedState &shared) {
    uint64_t total = 0;
    for (const auto &c : shared.contexts)
        total += c.packetsProcessed;
    return total;
}

} // namespace

int run_dpdk_capture(ProcessingContext &ctx) {
    std::vector<std::string> ealStorage;
    std::vector<char *> ealArgv;
    pcpp::CoreMask coreMask = extractCoreMask(FLAGS_dpdk_eal_args, ealStorage, ealArgv);

    if (!pcpp::DpdkDeviceList::initDpdk(coreMask, static_cast<uint32_t>(FLAGS_dpdk_mbuf_pool_size),
                                        /*mBufDataSize*/ 0, /*masterCore*/ 0,
                                        static_cast<uint32_t>(ealArgv.size()),
                                        ealArgv.empty() ? nullptr : ealArgv.data(),
                                        /*appName*/ "trace_analyser")) {
        std::cerr << "DPDK EAL init failed" << std::endl;
        return 1;
    }

    auto *dev = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(FLAGS_dpdk_port);
    if (dev == nullptr) {
        std::cerr << "No DPDK device found for port " << FLAGS_dpdk_port << std::endl;
        return 1;
    }

    // Worker mask = all cores in the EAL mask except the master (core 0, set in
    // initDpdk above). Single-thread fast path when only one worker bit is set.
    pcpp::CoreMask workerMask = coreMask & ~static_cast<pcpp::CoreMask>(1ULL << 0);
    int numWorkers = __builtin_popcountll(workerMask);

    DpdkSharedState shared;

    if (numWorkers <= 1) {
        if (!dev->open()) {
            std::cerr << "Cannot open DPDK port " << FLAGS_dpdk_port << std::endl;
            return 1;
        }
        if (!dev->startCaptureSingleThread(onDpdkPacketsArrive, &shared)) {
            std::cerr << "DPDK startCaptureSingleThread failed" << std::endl;
            dev->close();
            return 1;
        }
    } else {
        if (!dev->openMultiQueues(static_cast<uint16_t>(numWorkers), 1)) {
            std::cerr << "Cannot open " << numWorkers << " RX queues on port " << FLAGS_dpdk_port
                      << " (NIC may not support that many / RSS)" << std::endl;
            return 1;
        }
        if (!dev->startCaptureMultiThreads(onDpdkPacketsArrive, &shared, workerMask)) {
            std::cerr << "DPDK startCaptureMultiThreads failed" << std::endl;
            dev->close();
            return 1;
        }
    }

    std::signal(SIGINT, onSigint);

    std::cout << "Capturing from DPDK port " << FLAGS_dpdk_port << " on "
              << (numWorkers <= 1 ? 1 : numWorkers) << " worker(s) (Ctrl-C to stop)" << std::endl;

    const auto start = std::chrono::steady_clock::now();
    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (FLAGS_duration_sec > 0 &&
            std::chrono::steady_clock::now() - start >= std::chrono::seconds(FLAGS_duration_sec))
            break;
        if (FLAGS_max_packets > 0 && totalProcessed(shared) >= FLAGS_max_packets)
            break;
    }

    dev->stopCapture();
    dev->close();

    for (const auto &c : shared.contexts) {
        if (c.packetsProcessed == 0)
            continue;
        mergeInto(ctx, c);
    }

    std::cerr << "Captured " << ctx.packetsProcessed << " packets" << std::endl;
    return 0;
}
