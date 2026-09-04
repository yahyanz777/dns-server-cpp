#include <gtest/gtest.h>

#include "BytePacketBuffer.hpp"
#include "DnsRecord.hpp"
#include "SocketAddress.hpp"

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

TEST(DnsRecordTest, FormatsAndStoresIPv6Endpoints)
{
    const IPv6Address address("2001:db8::53");
    EXPECT_EQ(address.to_string(), "2001:db8::53");

    const SocketAddress endpoint = SocketAddress::from_ip(IPAddress{address}, 53);
    EXPECT_EQ(endpoint.family(), AF_INET6);
    EXPECT_EQ(endpoint, SocketAddress::from_ip(IPAddress{IPv6Address("2001:db8:0:0:0:0:0:53")}, 53));
}

TEST(DnsRecordTest, RoundTripsARecord)
{
    DnsRecord original("example.com", QuestionType::A, 1, 300, 4, ARecord{IPv4Address("93.184.216.34")});
    BytePacketBuffer buffer;
    original.write(buffer);

    buffer.seek(0);
    DnsRecord decoded = DnsRecord::read(buffer);

    EXPECT_EQ(decoded.get_name(), "example.com");
    EXPECT_EQ(decoded.get_type(), QuestionType::A);
    EXPECT_EQ(decoded.get_class(), 1);
    EXPECT_EQ(decoded.get_ttl(), 300);
    EXPECT_EQ(decoded.get_rdlength(), 4);
    ASSERT_NE(decoded.get_a_record(), nullptr);
    EXPECT_EQ(decoded.get_a_record()->address.to_string(), "93.184.216.34");
    ASSERT_TRUE(decoded.get_ip_address().has_value());
    EXPECT_EQ(address_to_string(*decoded.get_ip_address()), "93.184.216.34");
}

TEST(DnsRecordTest, RoundTripsAAAARecord)
{
    DnsRecord original("example.com", QuestionType::AAAA, 1, 600, 16, AAAARecord{IPv6Address("2001:db8::1")});
    BytePacketBuffer buffer;
    original.write(buffer);

    buffer.seek(0);
    DnsRecord decoded = DnsRecord::read(buffer);

    EXPECT_EQ(decoded.get_name(), "example.com");
    EXPECT_EQ(decoded.get_type(), QuestionType::AAAA);
    EXPECT_EQ(decoded.get_class(), 1);
    EXPECT_EQ(decoded.get_ttl(), 600);
    EXPECT_EQ(decoded.get_rdlength(), 16);
    ASSERT_NE(decoded.get_aaaa_record(), nullptr);
    EXPECT_EQ(decoded.get_aaaa_record()->address.to_string(), "2001:db8::1");
    ASSERT_TRUE(decoded.get_ip_address().has_value());
    EXPECT_EQ(address_to_string(*decoded.get_ip_address()), "2001:db8::1");
}

TEST(DnsRecordTest, RoundTripsCNAMERecord)
{
    DnsRecord original("alias.example.com", QuestionType::CNAME, 1, 300, 13, CNAMERecord{"example.com"});
    BytePacketBuffer buffer;
    original.write(buffer);

    buffer.seek(0);
    DnsRecord decoded = DnsRecord::read(buffer);

    EXPECT_EQ(decoded.get_name(), "alias.example.com");
    EXPECT_EQ(decoded.get_type(), QuestionType::CNAME);
    ASSERT_NE(decoded.get_cname_record(), nullptr);
    EXPECT_EQ(decoded.get_cname_record()->canonical_name, "example.com");
}

TEST(DnsRecordTest, RoundTripsMXRecord)
{
    DnsRecord original("example.com", QuestionType::MX, 1, 300, 18, MXRecord{10, "mail.example.com"});
    BytePacketBuffer buffer;
    original.write(buffer);

    buffer.seek(0);
    DnsRecord decoded = DnsRecord::read(buffer);

    EXPECT_EQ(decoded.get_name(), "example.com");
    EXPECT_EQ(decoded.get_type(), QuestionType::MX);
    ASSERT_NE(decoded.get_mx_record(), nullptr);
    EXPECT_EQ(decoded.get_mx_record()->preference, 10);
    EXPECT_EQ(decoded.get_mx_record()->exchange, "mail.example.com");
}

TEST(DnsRecordTest, RoundTripsNSRecord)
{
    DnsRecord original("example.com", QuestionType::NS, 1, 86400, 17, NSRecord{"ns1.example.com"});
    BytePacketBuffer buffer;
    original.write(buffer);

    buffer.seek(0);
    DnsRecord decoded = DnsRecord::read(buffer);

    EXPECT_EQ(decoded.get_name(), "example.com");
    EXPECT_EQ(decoded.get_type(), QuestionType::NS);
    ASSERT_NE(decoded.get_ns_record(), nullptr);
    EXPECT_EQ(decoded.get_ns_record()->name_server, "ns1.example.com");
}

TEST(DnsRecordTest, RoundTripsSOARecord)
{
    DnsRecord original("example.com", QuestionType::SOA, 1, 3600, 40,
                       SOARecord{"ns.example.com", "admin.example.com", 2026090201, 7200, 3600, 1209600, 300});
    BytePacketBuffer buffer;
    original.write(buffer);

    buffer.seek(0);
    DnsRecord decoded = DnsRecord::read(buffer);

    EXPECT_EQ(decoded.get_name(), "example.com");
    EXPECT_EQ(decoded.get_type(), QuestionType::SOA);
    ASSERT_NE(decoded.get_soa_record(), nullptr);
    EXPECT_EQ(decoded.get_soa_record()->primary_name_server, "ns.example.com");
    EXPECT_EQ(decoded.get_soa_record()->responsible_authority_mailbox, "admin.example.com");
    EXPECT_EQ(decoded.get_soa_record()->serial_number, 2026090201U);
    EXPECT_EQ(decoded.get_soa_record()->refresh_interval, 7200U);
    EXPECT_EQ(decoded.get_soa_record()->retry_interval, 3600U);
    EXPECT_EQ(decoded.get_soa_record()->expire_limit, 1209600U);
    EXPECT_EQ(decoded.get_soa_record()->minimum_ttl, 300U);
}

TEST(DnsRecordTest, RoundTripsUnknownRecord)
{
    std::vector<uint8_t> payload{0xDE, 0xAD, 0xBE, 0xEF};
    DnsRecord original("example.com", static_cast<QuestionType>(99), 1, 300, 4, UnknownRecord{payload});
    BytePacketBuffer buffer;
    original.write(buffer);

    buffer.seek(0);
    DnsRecord decoded = DnsRecord::read(buffer);

    EXPECT_EQ(decoded.get_name(), "example.com");
    EXPECT_EQ(static_cast<uint16_t>(decoded.get_type()), 99);
    ASSERT_NE(decoded.get_unknown_record(), nullptr);
    EXPECT_EQ(decoded.get_unknown_record()->data, payload);
}

TEST(DnsRecordTest, RejectsInvalidARecordLength)
{
    // Name: . (0), Type: 1, Class: 1, TTL: 0, RDLength: 3 (invalid, must be 4)
    BytePacketBuffer buffer{0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 3, 1, 2, 3};
    EXPECT_THROW(DnsRecord::read(buffer), std::runtime_error);
}

TEST(DnsRecordTest, RejectsInvalidAAAARecordLength)
{
    // Name: . (0), Type: 28, Class: 1, TTL: 0, RDLength: 4 (invalid, must be 16)
    BytePacketBuffer buffer{0, 0, 28, 0, 1, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4};
    EXPECT_THROW(DnsRecord::read(buffer), std::runtime_error);
}

TEST(DnsRecordTest, RoundTripsOPTRecord)
{
    std::vector<uint8_t> options = {0x00, 0x08, 0x00, 0x02, 0x00, 0x00}; // example option
    OPTRecord opt{1232, 0, 0, true, options};
    uint32_t ttl = 0x00008000; // DO bit set
    DnsRecord original("", QuestionType::OPT, 1232, ttl, static_cast<uint16_t>(options.size()), opt);

    BytePacketBuffer buffer(1232);
    original.write(buffer);

    buffer.seek(0);
    DnsRecord decoded = DnsRecord::read(buffer);

    EXPECT_EQ(decoded.get_type(), QuestionType::OPT);
    EXPECT_EQ(decoded.get_class(), 1232);
    EXPECT_EQ(decoded.get_ttl(), ttl);
    ASSERT_NE(decoded.get_opt_record(), nullptr);
    EXPECT_EQ(decoded.get_opt_record()->udp_payload_size, 1232);
    EXPECT_EQ(decoded.get_opt_record()->extended_rcode, 0);
    EXPECT_EQ(decoded.get_opt_record()->version, 0);
    EXPECT_TRUE(decoded.get_opt_record()->dnssec_ok);
    EXPECT_EQ(decoded.get_opt_record()->options_raw, options);
}
