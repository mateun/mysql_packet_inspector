cmake_minimum_required(VERSION 3.5)
project (mysql_packet_sniffer)

file(GLOB sources src/*.cpp)

add_executable(app ${sources})
target_link_libraries(app pcap)
