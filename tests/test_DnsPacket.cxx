#include <gtest/gtest.h>

#include "BytePacketBuffer.hpp"
#include "DnsPacket.hpp"

#include <fstream>
#include <iterator>
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
