cmake_minimum_required(VERSION 3.20)
project(DNS LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(dns
    src/BytePacketBuffer.cxx
    src/DnsHeader.cxx
    src/DnsQuestion.cxx
    src/DnsRecord.cxx
    src/DnsPacket.cxx
    src/DnsCache.cxx
    src/IPv4Address.cxx
    src/IPv6Address.cxx
    src/SocketAddress.cxx
    src/DnsResolver.cxx
    src/DnsServer.cxx
    src/RootServerManager.cxx
)

add_executable(dns_main
    src/main.cxx
)

target_link_libraries(dns_main
    PRIVATE
    dns
)

target_include_directories(dns PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

enable_testing()

include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_MakeAvailable(googletest)

add_executable(BytePacketBuffer_tests
    tests/test_BytePacketBuffer.cxx)


target_link_libraries(BytePacketBuffer_tests
    PRIVATE
    dns
    GTest::gtest_main
)

add_executable(dns_header_tests
    tests/test_DNSHeader.cxx)

target_link_libraries(dns_header_tests
    PRIVATE
    dns
    GTest::gtest_main
)

add_executable(dns_question_tests
    tests/test_DnsQuestion.cxx)

target_link_libraries(dns_question_tests
PRIVATE
dns
GTest::gtest_main)    

add_executable(dns_record_tests
    tests/test_DnsRecord.cxx)

target_link_libraries(dns_record_tests
PRIVATE
dns
GTest::gtest_main)

add_executable(dns_packet_tests
    tests/test_DnsPacket.cxx)

target_link_libraries(dns_packet_tests
PRIVATE
dns
GTest::gtest_main)

target_compile_definitions(dns_packet_tests
PRIVATE
RESPONSE_PACKET_PATH="${CMAKE_CURRENT_SOURCE_DIR}/response_packet.txt")

add_executable(dns_cache_tests
    tests/test_DnsCache.cxx)

target_link_libraries(dns_cache_tests
PRIVATE
dns
GTest::gtest_main)

add_executable(dns_resolver_tests
    tests/test_DnsResolver.cxx)

target_link_libraries(dns_resolver_tests
PRIVATE
dns
GTest::gtest_main)

target_compile_definitions(dns
PRIVATE
ROOT_SERVERS_CONFIG_PATH="${CMAKE_CURRENT_SOURCE_DIR}/config/root_servers.csv")
include(GoogleTest)

gtest_discover_tests(BytePacketBuffer_tests)
gtest_discover_tests(dns_header_tests)
gtest_discover_tests(dns_question_tests)
gtest_discover_tests(dns_record_tests)
gtest_discover_tests(dns_packet_tests)
gtest_discover_tests(dns_cache_tests)
gtest_discover_tests(dns_resolver_tests)

