#include <gtest/gtest.h>

#include "BytePacketBuffer.hpp"
#include "DnsPacket.hpp"

#include <fstream>
#include <iterator>
#include <stdexcept>
#include <vector>

TEST(DnsPacketTest, ParsesResponsePacketFixture)
{
    std::ifstream input(RESPONSE_PACKET_PATH, std::ios::binary);
    ASSERT_TRUE(input) << "Could not open " << RESPONSE_PACKET_PATH;

    const std::vector<uint8_t> response_bytes{
        std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
    ASSERT_FALSE(response_bytes.empty());

    BytePacketBuffer buffer{response_bytes};
     EXPECT_NO_THROW({ auto packet = DnsPacket::read(buffer); });
     EXPECT_EQ(buffer.remaining(), 0U);
}

TEST(DnsPacketTest, RejectsMultipleQuestions)
{
    // Header with QDCOUNT = 2. No question bytes are needed because rejection
    // happens immediately after the header is decoded.
    BytePacketBuffer buffer{0x12, 0x34, 0x01, 0x00, 0x00, 0x02,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    EXPECT_THROW(DnsPacket::read(buffer), std::runtime_error);
}
