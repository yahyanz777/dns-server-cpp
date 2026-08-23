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
)

target_include_directories(dns PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

enable_testing()

include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip
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

include(GoogleTest)

gtest_discover_tests(BytePacketBuffer_tests)
gtest_discover_tests(dns_header_tests)
gtest_discover_tests(dns_question_tests)
gtest_discover_tests(dns_record_tests)
gtest_discover_tests(dns_packet_tests)
