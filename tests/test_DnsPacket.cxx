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

TEST(DnsPacketTest, RoundTripsCompletePacket)
{
    DnsPacket packet;
    packet.get_header().ID = 0x5432;
    packet.get_header().set_response(true);
    packet.get_header().set_recursion_desired(true);
    packet.get_header().set_recursion_available(true);

    packet.set_question(DnsQuestion("example.com", QuestionType::A, 1));
    packet.add_answer(DnsRecord("example.com", QuestionType::A, 1, 300, 4, ARecord{IPv4Address("93.184.216.34")}));
    packet.add_authority(DnsRecord("example.com", QuestionType::NS, 1, 86400, 17, NSRecord{"ns1.example.com"}));
    packet.add_additional(DnsRecord("ns1.example.com", QuestionType::AAAA, 1, 3600, 16, AAAARecord{IPv6Address("2001:db8::1")}));

    BytePacketBuffer buffer;
    packet.write(buffer);

    buffer.seek(0);
    DnsPacket decoded = DnsPacket::read(buffer);

    EXPECT_EQ(decoded.get_header().ID, 0x5432);
    EXPECT_TRUE(decoded.get_header().is_response());
    EXPECT_TRUE(decoded.get_header().recursion_desired());
    EXPECT_TRUE(decoded.get_header().recursion_available());

    ASSERT_NE(decoded.get_question(), nullptr);
    EXPECT_EQ(decoded.get_question()->getName(), "example.com");
    EXPECT_EQ(decoded.get_question()->getType(), QuestionType::A);

    ASSERT_EQ(decoded.get_answers().size(), 1U);
    EXPECT_EQ(decoded.get_answers()[0].get_name(), "example.com");
    ASSERT_TRUE(decoded.get_answers()[0].get_ip_address().has_value());
    EXPECT_EQ(address_to_string(*decoded.get_answers()[0].get_ip_address()), "93.184.216.34");

    ASSERT_EQ(decoded.get_authorities().size(), 1U);
    ASSERT_NE(decoded.get_authorities()[0].get_ns_record(), nullptr);
    EXPECT_EQ(decoded.get_authorities()[0].get_ns_record()->name_server, "ns1.example.com");

    ASSERT_EQ(decoded.get_additionals().size(), 1U);
    ASSERT_NE(decoded.get_additionals()[0].get_aaaa_record(), nullptr);
    EXPECT_EQ(decoded.get_additionals()[0].get_aaaa_record()->address.to_string(), "2001:db8::1");
}

TEST(DnsPacketTest, AutomaticallySynchronizesHeaderCounts)
{
    DnsPacket packet;
    packet.set_question(DnsQuestion("test.org", QuestionType::AAAA));
    packet.add_answer(DnsRecord("test.org", QuestionType::AAAA, 1, 60, 16, AAAARecord{IPv6Address("::1")}));
    packet.add_answer(DnsRecord("test.org", QuestionType::AAAA, 1, 60, 16, AAAARecord{IPv6Address("::2")}));

    BytePacketBuffer buffer;
    packet.write(buffer);

    EXPECT_EQ(packet.get_header().get_QDCOUNT(), 1);
    EXPECT_EQ(packet.get_header().get_ACOUNT(), 2);
    EXPECT_EQ(packet.get_header().get_NSCOUNT(), 0);
    EXPECT_EQ(packet.get_header().get_ARCOUNT(), 0);
}

TEST(DnsPacketTest, CreatesAndExtractsEdnsInfo)
{
    DnsPacket packet;
    EXPECT_FALSE(packet.get_edns_info().has_value());

    packet.create_additional_opt_record(1232, 0, 0, true);
    auto edns = packet.get_edns_info();
    ASSERT_TRUE(edns.has_value());
    EXPECT_TRUE(edns->edns_present);
    EXPECT_EQ(edns->max_payload_size, 1232);
    EXPECT_TRUE(edns->dnssec_ok);
    EXPECT_EQ(edns->version, 0);

    BytePacketBuffer buffer(1232);
    packet.write(buffer);

    buffer.seek(0);
    DnsPacket decoded = DnsPacket::read(buffer);
    auto decoded_edns = decoded.get_edns_info();
    ASSERT_TRUE(decoded_edns.has_value());
    EXPECT_EQ(decoded_edns->max_payload_size, 1232);
    EXPECT_TRUE(decoded_edns->dnssec_ok);
}
