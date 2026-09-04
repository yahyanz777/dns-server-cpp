#include <gtest/gtest.h>

#include "DnsResolver.hpp"
#include "DnsPacket.hpp"
#include "QuestionType.hpp"

TEST(DnsResolverTest, ReturnsEmptyPacketOnEmptyQuestion)
{
    DnsResolver resolver;
    DnsPacket empty_packet;
    DnsPacket result = resolver.lookup(empty_packet);
    EXPECT_EQ(result.get_question(), nullptr);
}

TEST(DnsResolverTest, ServesCachedResponsesForAnyQuestionType)
{
    DnsResolver resolver;

    // Construct a query for MX
    DnsPacket query;
    query.get_header().ID = 0x5678;
    query.get_header().set_recursion_desired(true);
    query.set_question(DnsQuestion("example.com", QuestionType::MX));

    EXPECT_FALSE(resolver.is_cached(query).has_value());

    // Pre-populate cache with MX record
    DnsRecord mx_rec("example.com", QuestionType::MX, 1, 300, 15, MXRecord{10, "mail.example.com"});
    resolver.get_cache().put(DnsCacheKey{"example.com", QuestionType::MX}, mx_rec);

    EXPECT_TRUE(resolver.is_cached(query).has_value());
    DnsPacket response = resolver.lookup(query);
    EXPECT_TRUE(response.get_header().is_response());
    EXPECT_EQ(response.get_header().get_result_code(), ResultCode::NOERROR);
    ASSERT_EQ(response.get_answers().size(), 1U);
    EXPECT_EQ(response.get_answers()[0].get_type(), QuestionType::MX);
}

TEST(DnsResolverTest, ServesCachedNXDOMAIN)
{
    DnsResolver resolver;

    DnsPacket query;
    query.get_header().ID = 0x1234;
    query.get_header().set_recursion_desired(true);
    query.set_question(DnsQuestion("nonexistent.example.com", QuestionType::A));

    resolver.get_cache().put(DnsCacheKey{"nonexistent.example.com", QuestionType::A}, CacheResult::NXDOMAIN, 300);

    EXPECT_TRUE(resolver.is_cached(query).has_value());
    DnsPacket response = resolver.lookup(query);

    EXPECT_TRUE(response.get_header().is_response());
    EXPECT_EQ(response.get_header().ID, 0x1234);
    EXPECT_EQ(response.get_header().get_result_code(), ResultCode::NXDOMAIN);
    EXPECT_TRUE(response.get_answers().empty());
}

TEST(DnsResolverTest, ServesCachedNODATA)
{
    DnsResolver resolver;

    DnsPacket query;
    query.get_header().ID = 0x4321;
    query.get_header().set_recursion_desired(true);
    query.set_question(DnsQuestion("example.com", QuestionType::AAAA));

    resolver.get_cache().put(DnsCacheKey{"example.com", QuestionType::AAAA}, CacheResult::NODATA, 300);

    EXPECT_TRUE(resolver.is_cached(query).has_value());
    DnsPacket response = resolver.lookup(query);

    EXPECT_TRUE(response.get_header().is_response());
    EXPECT_EQ(response.get_header().ID, 0x4321);
    EXPECT_EQ(response.get_header().get_result_code(), ResultCode::NOERROR);
    EXPECT_TRUE(response.get_answers().empty());
}
TEST(DnsResolverTest, ServesCachedDualStackRecords)
{
    DnsResolver resolver;

    DnsPacket query_a;
    query_a.get_header().ID = 0x1111;
    query_a.get_header().set_recursion_desired(true);
    query_a.set_question(DnsQuestion("dualstack.example.com", QuestionType::A));

    DnsPacket query_aaaa;
    query_aaaa.get_header().ID = 0x2222;
    query_aaaa.get_header().set_recursion_desired(true);
    query_aaaa.set_question(DnsQuestion("dualstack.example.com", QuestionType::AAAA));

    DnsRecord a_rec("dualstack.example.com", QuestionType::A, 1, 300, 4, ARecord{IPv4Address("192.0.2.1")});
    DnsRecord aaaa_rec("dualstack.example.com", QuestionType::AAAA, 1, 300, 16, AAAARecord{IPv6Address("2001:db8::1")});

    resolver.get_cache().put(DnsCacheKey{"dualstack.example.com", QuestionType::A}, a_rec);
    resolver.get_cache().put(DnsCacheKey{"dualstack.example.com", QuestionType::AAAA}, aaaa_rec);

    DnsPacket resp_a = resolver.lookup(query_a);
    EXPECT_EQ(resp_a.get_answers().size(), 1U);
    EXPECT_EQ(resp_a.get_answers()[0].get_type(), QuestionType::A);

    DnsPacket resp_aaaa = resolver.lookup(query_aaaa);
    EXPECT_EQ(resp_aaaa.get_answers().size(), 1U);
    EXPECT_EQ(resp_aaaa.get_answers()[0].get_type(), QuestionType::AAAA);
}

TEST(DnsResolverTest, HandlesReferralWithoutGlueGracefully)
{
    DnsResolver resolver;

    // Test that resolver properly executes negative caching / empty response when candidate NS fails
    DnsPacket query;
    query.get_header().ID = 0x9999;
    query.get_header().set_recursion_desired(true);
    query.set_question(DnsQuestion("unknown.invalid", QuestionType::A));

    // When queried against unreachable/unresolvable root/NS, response is handled safely
    // (returns packet without crashing)
    DnsPacket resp = resolver.lookup(query);
    EXPECT_TRUE(resp.get_answers().empty());
}

TEST(DnsResolverTest, ResolvesCNAMEFromCache)
{
    DnsResolver resolver;

    DnsRecord cname_rec("alias.example.com", QuestionType::CNAME, 1, 300, 18, CNAMERecord{"target.example.com"});
    DnsRecord a_rec("target.example.com", QuestionType::A, 1, 300, 4, ARecord{IPv4Address("192.0.2.1")});

    resolver.get_cache().put(DnsCacheKey{"alias.example.com", QuestionType::A}, cname_rec);
    resolver.get_cache().put(DnsCacheKey{"target.example.com", QuestionType::A}, a_rec);

    DnsPacket query;
    query.get_header().ID = 0x3333;
    query.set_question(DnsQuestion("alias.example.com", QuestionType::A));

    DnsPacket response = resolver.lookup(query);
    EXPECT_TRUE(response.get_header().is_response());
    ASSERT_FALSE(response.get_answers().empty());
}

TEST(DnsResolverTest, ProtectsAgainstCNAMELoop)
{
    DnsResolver resolver;

    DnsRecord loop1_rec("loop1.example.com", QuestionType::CNAME, 1, 300, 17, CNAMERecord{"loop2.example.com"});
    DnsRecord loop2_rec("loop2.example.com", QuestionType::CNAME, 1, 300, 17, CNAMERecord{"loop1.example.com"});

    resolver.get_cache().put(DnsCacheKey{"loop1.example.com", QuestionType::A}, loop1_rec);
    resolver.get_cache().put(DnsCacheKey{"loop2.example.com", QuestionType::A}, loop2_rec);

    DnsPacket query;
    query.get_header().ID = 0x4444;
    query.set_question(DnsQuestion("loop1.example.com", QuestionType::A));

    // Must terminate gracefully without an infinite loop
    DnsPacket response = resolver.lookup(query);
    EXPECT_TRUE(response.get_header().is_response());
}

TEST(DnsResolverTest, EnforcesRecursiveResolverHeaderInvariants)
{
    DnsResolver resolver;

    // Cache a record to test resolver response formatting
    DnsRecord a_rec("example.com", QuestionType::A, 1, 300, 4, ARecord{IPv4Address("93.184.216.34")});
    resolver.get_cache().put(DnsCacheKey{"example.com", QuestionType::A}, a_rec);

    DnsPacket query;
    query.get_header().ID = 0xABCD;
    query.get_header().set_recursion_desired(true);
    query.set_question(DnsQuestion("example.com", QuestionType::A));

    DnsPacket response = resolver.lookup(query);
    EXPECT_TRUE(response.get_header().is_response());
    EXPECT_EQ(response.get_header().ID, 0xABCD);
    EXPECT_TRUE(response.get_header().recursion_desired());
    EXPECT_TRUE(response.get_header().recursion_available());
    EXPECT_FALSE(response.get_header().is_authoritative());
}

TEST(DnsResolverTest, FailedLookupDoesNotPolluteCache)
{
    DnsResolver resolver;

    DnsPacket query;
    query.get_header().ID = 0x8888;
    query.get_header().set_recursion_desired(true);
    query.set_question(DnsQuestion("offline.test.invalid", QuestionType::A));

    DnsPacket resp = resolver.lookup(query);
    if (!resp.get_header().is_response())
    {
        EXPECT_TRUE(resp.get_answers().empty());
        EXPECT_FALSE(resolver.get_cache().contains(DnsCacheKey{"offline.test.invalid", QuestionType::A}));
    }
    else
    {
        EXPECT_EQ(resp.get_header().get_result_code(), ResultCode::NXDOMAIN);
    }
}

