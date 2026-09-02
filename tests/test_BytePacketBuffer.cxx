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

TEST(BytePacketBufferTest, WritesAndReadsPrimitives)
{
    BytePacketBuffer buffer;
    buffer.write_u8(0x42);
    buffer.write_u16(0x1234);
    buffer.write_u32(0x89ABCDEF);

    EXPECT_EQ(buffer.get_length(), 7U);
    EXPECT_EQ(buffer.remaining(), 0U); // At end of written buffer

    buffer.seek(0);
    EXPECT_EQ(buffer.remaining(), 7U); // 7 bytes remaining to read
    EXPECT_EQ(buffer.read_u8(), 0x42);
    EXPECT_EQ(buffer.read_u16(), 0x1234);
    EXPECT_EQ(buffer.read_u32(), 0x89ABCDEF);
    EXPECT_EQ(buffer.remaining(), 0U);
}

TEST(BytePacketBufferTest, WritesAndReadsQNames)
{
    BytePacketBuffer buffer;
    buffer.write_qname("example.com");
    buffer.write_qname(".");
    buffer.write_qname("sub.domain.org");

    buffer.seek(0);
    EXPECT_EQ(buffer.read_qname(), "example.com");
    EXPECT_EQ(buffer.read_qname(), ".");
    EXPECT_EQ(buffer.read_qname(), "sub.domain.org");
}

TEST(BytePacketBufferTest, RejectsInvalidLabelLength)
{
    BytePacketBuffer buffer;
    std::string long_label(64, 'a');
    EXPECT_THROW(buffer.write_qname(long_label + ".com"), std::invalid_argument);
}

TEST(BytePacketBufferTest, RejectsEmptyLabelInMiddle)
{
    BytePacketBuffer buffer;
    EXPECT_THROW(buffer.write_qname("foo..bar"), std::invalid_argument);
}

TEST(BytePacketBufferTest, RejectsWriteExceedingCapacity)
{
    BytePacketBuffer buffer;
    for (size_t i = 0; i < 512; ++i)
    {
        buffer.write_u8(0xAA);
    }
    EXPECT_THROW(buffer.write_u8(0xBB), std::length_error);
}
