#include <gtest/gtest.h>

#include "BytePacketBuffer.hpp"
#include "DnsRecord.hpp"

TEST(DnsRecordTest, RejectsRdataThatIsNotPresent)
{

    BytePacketBuffer buffer{0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0};

    EXPECT_THROW(DnsRecord::read(buffer), std::out_of_range);
    
}

TEST(DnsRecordTest, PreservesUnsupportedRecordData)
{

    BytePacketBuffer buffer{0, 0, 16, 0, 1, 0, 0, 0, 0, 0, 2, 1, 2};

    EXPECT_NO_THROW(DnsRecord::read(buffer));

}
