#include "BytePacketBuffer.hpp"

#include <gtest/gtest.h>

TEST(BytePacketBufferTest, ReadU8)
{
    BytePacketBuffer buffer{0x12, 0x34, 0x56, 0x78};

    EXPECT_EQ(buffer.read_u8(), 0x12);
    EXPECT_EQ(buffer.get(), 0x34);
    EXPECT_EQ(buffer.read_u8(), 0x34);
}

TEST(BytePacketBufferTest, RejectsInvalidLabelTag)
{
    BytePacketBuffer buffer{0x40};

    EXPECT_THROW(buffer.read_qname(), std::runtime_error);
}

TEST(BytePacketBufferTest, RejectsCompressionPointerLoop)
{
    BytePacketBuffer buffer{0xC0, 0x00};

    EXPECT_THROW(buffer.read_qname(), std::runtime_error);
}

TEST(BytePacketBufferTest, RejectsOutOfBoundsStep)
{
    BytePacketBuffer buffer{0x12};

    EXPECT_THROW(buffer.step(2), std::out_of_range);
}
