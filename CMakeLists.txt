cmake_minimum_required(VERSION 3.12)
project(analyser)

# Set C++14
set(CMAKE_CXX_STANDARD 14)
# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)

find_package(gflags REQUIRED)
find_package(PcapPlusPlus REQUIRED)

add_executable("analyser" main.cpp)
target_link_libraries("analyser" PUBLIC PcapPlusPlus::Pcap++ gflags)
set_target_properties("analyser" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

# Enable the DPDK backend only if the installed PcapPlusPlus was built with
# DPDK support (DpdkDevice.h is present) AND libdpdk is discoverable via
# pkg-config. Otherwise build exactly as before; passing --dpdk_port at
# runtime then fails with a clear message.
find_path(PCPP_DPDK_HEADER
  NAMES DpdkDevice.h
  PATH_SUFFIXES pcapplusplus)
if(PCPP_DPDK_HEADER)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(DPDK REQUIRED libdpdk)
  target_compile_definitions("analyser" PRIVATE USE_DPDK)
  target_compile_options("analyser" PRIVATE ${DPDK_CFLAGS_OTHER})
  target_include_directories("analyser" PRIVATE ${DPDK_INCLUDE_DIRS})
  target_link_directories("analyser" PRIVATE ${DPDK_LIBRARY_DIRS})
  target_link_libraries("analyser" PUBLIC ${DPDK_LIBRARIES})
  message(STATUS "DPDK backend: ENABLED (libdpdk ${DPDK_VERSION})")
else()
  message(STATUS "DPDK backend: DISABLED (install PcapPlusPlus with PCAPPP_USE_DPDK=ON to enable)")
endif()
