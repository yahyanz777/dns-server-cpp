#include <DnsHeader.hpp>
#include <gtest/gtest.h>

TEST(DNSHeaderTest,READ){
    BytePacketBuffer buffer{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44};
    BytePacketBuffer buffer_2{0x12, 0x34, 0x56, 0x73, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44};
    BytePacketBuffer buffer_3{0x12, 0x34, 0x56, 0x70, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44};
    BytePacketBuffer buffer_4{0x12, 0x34, 0x56, 0x77, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44};
    DnsHeader header = DnsHeader::read(buffer);
    DnsHeader header_2 = DnsHeader::read(buffer_2);
    DnsHeader header_3 = DnsHeader::read(buffer_3);
    DnsHeader header_4 = DnsHeader::read(buffer_4);

    EXPECT_EQ(header.ID, 0x1234);
    EXPECT_EQ(header.FLAGS, 0x5678);
    EXPECT_EQ(header.QDCOUNT, 0x9ABC);
    EXPECT_EQ(header.ANCOUNT, 0xDEF0);
    EXPECT_EQ(header.NSCOUNT, 0x1122);
    EXPECT_EQ(header.ARCOUNT, 0x3344);

    EXPECT_EQ(header_2.DnsHeader::get_result_code(), ResultCode::NXDOMAIN);
    EXPECT_EQ(header_3.DnsHeader::get_result_code(), ResultCode::NOERROR);
    EXPECT_EQ(header_4.DnsHeader::get_result_code(), ResultCode::UNKNOWN);
}
