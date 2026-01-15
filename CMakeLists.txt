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
