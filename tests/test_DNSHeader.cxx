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

TEST(DNSHeaderTest, WriteAndReadRoundTrip)
{
    DnsHeader header{0xABCD, 0x8180, 1, 2, 3, 4};
    BytePacketBuffer buffer;
    header.write(buffer);

    EXPECT_EQ(buffer.get_length(), 12U);

    buffer.seek(0);
    DnsHeader decoded = DnsHeader::read(buffer);

    EXPECT_EQ(decoded.ID, 0xABCD);
    EXPECT_EQ(decoded.FLAGS, 0x8180);
    EXPECT_EQ(decoded.QDCOUNT, 1);
    EXPECT_EQ(decoded.ANCOUNT, 2);
    EXPECT_EQ(decoded.NSCOUNT, 3);
    EXPECT_EQ(decoded.ARCOUNT, 4);
    EXPECT_TRUE(decoded.is_response());
    EXPECT_TRUE(decoded.recursion_desired());
    EXPECT_TRUE(decoded.recursion_available());
    EXPECT_EQ(decoded.get_result_code(), ResultCode::NOERROR);
}

TEST(DNSHeaderTest, FlagManipulation)
{
    DnsHeader header;

    header.set_response(true);
    EXPECT_TRUE(header.is_response());
    header.set_response(false);
    EXPECT_FALSE(header.is_response());

    header.set_recursion_desired(true);
    EXPECT_TRUE(header.recursion_desired());
    header.set_recursion_desired(false);
    EXPECT_FALSE(header.recursion_desired());

    header.set_recursion_available(true);
    EXPECT_TRUE(header.recursion_available());
    header.set_recursion_available(false);
    EXPECT_FALSE(header.recursion_available());

    header.set_authoritative(true);
    EXPECT_TRUE(header.is_authoritative());
    header.set_authoritative(false);
    EXPECT_FALSE(header.is_authoritative());

    header.set_result_code(ResultCode::SERVFAIL);
    EXPECT_EQ(header.get_result_code(), ResultCode::SERVFAIL);

    header.set_result_code(ResultCode::NXDOMAIN);
    EXPECT_EQ(header.get_result_code(), ResultCode::NXDOMAIN);

    header.set_result_code(ResultCode::NOERROR);
    EXPECT_EQ(header.get_result_code(), ResultCode::NOERROR);
}
