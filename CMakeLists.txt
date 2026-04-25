cmake_minimum_required(VERSION 3.12)
project(analyser)

# Set C++14
set(CMAKE_CXX_STANDARD 14)
# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)

find_package(gflags REQUIRED)
find_package(PcapPlusPlus REQUIRED)

set(ANALYSER_NAME "analyser" CACHE STRING "Output name of the analyser binary")

add_executable("analyser"
  main.cpp
  helper.cpp
  processing.cpp
)
target_link_libraries("analyser" PUBLIC PcapPlusPlus::Pcap++ gflags)
set_target_properties("analyser" PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  OUTPUT_NAME "${ANALYSER_NAME}")

# DPDK backend selection.
#   -DWITH_DPDK=AUTO (default): enable iff PcapPlusPlus has DpdkDevice.h
#   -DWITH_DPDK=ON              require DPDK; fail at configure time otherwise
#   -DWITH_DPDK=OFF             never link DPDK (analyser will error at runtime
#                               if --dpdk_port is passed)
set(WITH_DPDK "AUTO" CACHE STRING "DPDK backend: AUTO|ON|OFF")
set_property(CACHE WITH_DPDK PROPERTY STRINGS AUTO ON OFF)

# Detect whether the installed PcapPlusPlus has DPDK support.
# When it does, pcpp's INTERFACE deps drag DPDK into our link line whether
# we want it or not — so we always need the DPDK -L path below.
find_path(PCPP_DPDK_HEADER
  NAMES DpdkDevice.h
  PATH_SUFFIXES pcapplusplus)

set(_use_dpdk OFF)
if(NOT WITH_DPDK STREQUAL "OFF")
  if(PCPP_DPDK_HEADER)
    set(_use_dpdk ON)
  elseif(WITH_DPDK STREQUAL "ON")
    message(FATAL_ERROR
      "WITH_DPDK=ON but DpdkDevice.h not found. "
      "Rebuild PcapPlusPlus with PCAPPP_USE_DPDK=ON and reinstall.")
  endif()
endif()

# When the installed PcapPlusPlus was built with DPDK, its imported
# Pcap++ target drags DPDK::DPDK into our link line transitively — so we
# need the DPDK -L path even in the nodpdk build flavour. We let WITH_DPDK
# decide whether OUR sources (dpdk_backend.cpp vs dpdk_stub.cpp) are added.
if(PCPP_DPDK_HEADER)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(DPDK REQUIRED libdpdk)
  target_link_directories("analyser" PRIVATE ${DPDK_LIBRARY_DIRS})
endif()

if(_use_dpdk)
  target_sources("analyser" PRIVATE dpdk_backend.cpp)
  target_compile_options("analyser" PRIVATE ${DPDK_CFLAGS_OTHER})
  target_include_directories("analyser" PRIVATE ${DPDK_INCLUDE_DIRS})
  target_link_libraries("analyser" PUBLIC ${DPDK_LIBRARIES})
  message(STATUS "DPDK backend: ENABLED (libdpdk ${DPDK_VERSION}) [WITH_DPDK=${WITH_DPDK}]")
else()
  target_sources("analyser" PRIVATE dpdk_stub.cpp)
  message(STATUS "DPDK backend: DISABLED [WITH_DPDK=${WITH_DPDK}]")
endif()
