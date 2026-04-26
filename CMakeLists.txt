cmake_minimum_required(VERSION 3.16)
project(analyser)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_EXTENSIONS ON)

# DPDK backend selection.
#   -DWITH_DPDK=AUTO (default): enable iff vendored pcpp-with-DPDK is built
#   -DWITH_DPDK=ON              require DPDK; fail at configure if pcpp-dpdk is missing
#   -DWITH_DPDK=OFF             never link DPDK
set(WITH_DPDK "AUTO" CACHE STRING "DPDK backend: AUTO|ON|OFF")
set_property(CACHE WITH_DPDK PROPERTY STRINGS AUTO ON OFF)

# Vendored prefixes (build.sh populates these via meson + cmake).
set(_dpdk_install "${CMAKE_SOURCE_DIR}/external/dpdk/install")
set(_dpdk_libdir  "${_dpdk_install}/lib/x86_64-linux-gnu")
set(_pcpp_install_dpdk   "${CMAKE_SOURCE_DIR}/external/PcapPlusPlus/install-dpdk")
set(_pcpp_install_nodpdk "${CMAKE_SOURCE_DIR}/external/PcapPlusPlus/install-nodpdk")

# Pick the appropriate pcpp install based on WITH_DPDK + which install exists.
set(_use_dpdk OFF)
set(_pcpp_install "${_pcpp_install_nodpdk}")
if(NOT WITH_DPDK STREQUAL "OFF")
    if(EXISTS "${_pcpp_install_dpdk}/include/pcapplusplus/DpdkDevice.h")
        set(_pcpp_install "${_pcpp_install_dpdk}")
        set(_use_dpdk ON)
    elseif(WITH_DPDK STREQUAL "ON")
        message(FATAL_ERROR
            "WITH_DPDK=ON but ${_pcpp_install_dpdk}/include/pcapplusplus/DpdkDevice.h missing.\n"
            "Run: ./build.sh dpdk")
    endif()
endif()

list(PREPEND CMAKE_PREFIX_PATH "${_pcpp_install}")
if(_use_dpdk)
    set(ENV{PKG_CONFIG_PATH} "${_dpdk_libdir}/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endif()

find_package(PcapPlusPlus REQUIRED)

set(ANALYSER_NAME "analyser" CACHE STRING "Output name of the analyser binary")

add_executable(analyser
    main.cpp
    helper.cpp
    processing.cpp
)
target_link_libraries(analyser PUBLIC PcapPlusPlus::Pcap++)
set_target_properties(analyser PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_NAME "${ANALYSER_NAME}"
    # Find DPDK .so's at runtime without LD_LIBRARY_PATH: rpath is relative
    # to the binary location ($ORIGIN = the directory of the binary), pointing
    # at the vendored DPDK install under external/dpdk/install/.
    BUILD_WITH_INSTALL_RPATH TRUE
    INSTALL_RPATH "$ORIGIN/external/dpdk/install/lib/x86_64-linux-gnu"
)

if(_use_dpdk)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DPDK REQUIRED libdpdk)
    target_sources(analyser PRIVATE dpdk_backend.cpp)
    target_compile_options(analyser PRIVATE ${DPDK_CFLAGS_OTHER})
    target_include_directories(analyser PRIVATE ${DPDK_INCLUDE_DIRS})
    # pcpp's INTERFACE_LINK_LIBRARIES drags DPDK::DPDK in but the upstream
    # FindDPDK.cmake doesn't set INTERFACE_LINK_DIRECTORIES — supply the -L
    # explicitly so -lrte_* resolves.
    target_link_directories(analyser PRIVATE ${DPDK_LIBRARY_DIRS})
    target_link_libraries(analyser PUBLIC ${DPDK_LIBRARIES})
    message(STATUS "DPDK backend: ENABLED [vendored libdpdk @ ${_dpdk_install}]")
else()
    target_sources(analyser PRIVATE dpdk_stub.cpp)
    message(STATUS "DPDK backend: DISABLED [WITH_DPDK=${WITH_DPDK}]")
endif()
