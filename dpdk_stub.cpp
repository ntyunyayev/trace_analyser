#include "dpdk_backend.h"

#include <iostream>

int run_dpdk_capture(ProcessingContext & /*ctx*/) {
  std::cerr << "Built without DPDK support. Rebuild PcapPlusPlus with "
               "PCAPPP_USE_DPDK=ON, then ./build.sh dpdk"
            << std::endl;
  return 1;
}
