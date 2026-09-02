#include <gtest/gtest.h>

#include "DnsCache.hpp"
#include "DnsRecord.hpp"
#include "QuestionType.hpp"
#include <thread>

TEST(DnsCacheTest, CachesAndRetrievesVariousRecordTypes)
{
    DnsCache cache;

    // A Record
    DnsCacheKey a_key{"example.com", QuestionType::A};
    DnsRecord a_rec("example.com", QuestionType::A, 1, 300, 4, ARecord{IPv4Address("93.184.216.34")});
    cache.put(a_key, a_rec);

    EXPECT_TRUE(cache.contains(a_key));
    auto a_entry = cache.get(a_key);
    ASSERT_TRUE(a_entry.has_value());
    ASSERT_EQ(a_entry->records.size(), 1U);
    EXPECT_EQ(a_entry->records[0].get_name(), "example.com");
    EXPECT_EQ(a_entry->records[0].get_type(), QuestionType::A);
    ASSERT_TRUE(a_entry->records[0].get_ip_address().has_value());
    EXPECT_EQ(address_to_string(*a_entry->records[0].get_ip_address()), "93.184.216.34");

    // AAAA Record
    DnsCacheKey aaaa_key{"example.com", QuestionType::AAAA};
    DnsRecord aaaa_rec("example.com", QuestionType::AAAA, 1, 300, 16, AAAARecord{IPv6Address("2606:2800:220:1:248:1893:25c8:1946")});
    cache.put(aaaa_key, aaaa_rec);

    EXPECT_TRUE(cache.contains(aaaa_key));
    auto aaaa_entry = cache.get(aaaa_key);
    ASSERT_TRUE(aaaa_entry.has_value());
    ASSERT_EQ(aaaa_entry->records.size(), 1U);
    EXPECT_EQ(aaaa_entry->records[0].get_type(), QuestionType::AAAA);

    // MX Record
    DnsCacheKey mx_key{"example.com", QuestionType::MX};
    DnsRecord mx_rec("example.com", QuestionType::MX, 1, 300, 15, MXRecord{10, "mail.example.com"});
    cache.put(mx_key, mx_rec);

    EXPECT_TRUE(cache.contains(mx_key));
    auto mx_entry = cache.get(mx_key);
    ASSERT_TRUE(mx_entry.has_value());
    ASSERT_EQ(mx_entry->records.size(), 1U);
    EXPECT_EQ(mx_entry->records[0].get_type(), QuestionType::MX);
    ASSERT_NE(mx_entry->records[0].get_mx_record(), nullptr);
    EXPECT_EQ(mx_entry->records[0].get_mx_record()->preference, 10);
    EXPECT_EQ(mx_entry->records[0].get_mx_record()->exchange, "mail.example.com");

    // NS Record
    DnsCacheKey ns_key{"example.com", QuestionType::NS};
    DnsRecord ns_rec("example.com", QuestionType::NS, 1, 300, 15, NSRecord{"ns1.example.com"});
    cache.put(ns_key, ns_rec);

    EXPECT_TRUE(cache.contains(ns_key));
    auto ns_entry = cache.get(ns_key);
    ASSERT_TRUE(ns_entry.has_value());
    ASSERT_EQ(ns_entry->records.size(), 1U);
    EXPECT_EQ(ns_entry->records[0].get_type(), QuestionType::NS);
    ASSERT_NE(ns_entry->records[0].get_ns_record(), nullptr);
    EXPECT_EQ(ns_entry->records[0].get_ns_record()->name_server, "ns1.example.com");

    // SOA Record
    DnsCacheKey soa_key{"example.com", QuestionType::SOA};
    DnsRecord soa_rec("example.com", QuestionType::SOA, 1, 300, 30, SOARecord{"ns.example.com", "admin.example.com", 1, 7200, 3600, 1209600, 3600});
    cache.put(soa_key, soa_rec);

    EXPECT_TRUE(cache.contains(soa_key));
    auto soa_entry = cache.get(soa_key);
    ASSERT_TRUE(soa_entry.has_value());
    ASSERT_EQ(soa_entry->records.size(), 1U);
    EXPECT_EQ(soa_entry->records[0].get_type(), QuestionType::SOA);
    ASSERT_NE(soa_entry->records[0].get_soa_record(), nullptr);
    EXPECT_EQ(soa_entry->records[0].get_soa_record()->primary_name_server, "ns.example.com");

    // CNAME Record
    DnsCacheKey cname_key{"alias.example.com", QuestionType::CNAME};
    DnsRecord cname_rec("alias.example.com", QuestionType::CNAME, 1, 300, 13, CNAMERecord{"example.com"});
    cache.put(cname_key, cname_rec);

    EXPECT_TRUE(cache.contains(cname_key));
    auto cname_entry = cache.get(cname_key);
    ASSERT_TRUE(cname_entry.has_value());
    ASSERT_NE(cname_entry->records[0].get_cname_record(), nullptr);
    EXPECT_EQ(cname_entry->records[0].get_cname_record()->canonical_name, "example.com");
}

TEST(DnsCacheTest, HandlesMultipleRecordsForSameKey)
{
    DnsCache cache;
    DnsCacheKey key{"example.com", QuestionType::A};
    std::vector<DnsRecord> records = {
        DnsRecord("example.com", QuestionType::A, 1, 300, 4, ARecord{IPv4Address("93.184.216.34")}),
        DnsRecord("example.com", QuestionType::A, 1, 300, 4, ARecord{IPv4Address("93.184.216.35")})
    };
    cache.put(key, records, 300);

    auto entry = cache.get(key);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->records.size(), 2U);
}

TEST(DnsCacheTest, HandlesExpiration)
{
    DnsCache cache;
    DnsCacheKey key{"example.com", QuestionType::A};
    DnsRecord rec("example.com", QuestionType::A, 1, 0, 4, ARecord{IPv4Address("93.184.216.34")});
    DnsCacheEntry entry(rec, std::chrono::seconds{-1}); // expired immediately
    cache.put(key, entry);

    EXPECT_FALSE(cache.contains(key));
    EXPECT_FALSE(cache.get(key).has_value());
}

TEST(DnsCacheTest, CachesAndRetrievesNXDOMAIN)
{
    DnsCache cache;
    DnsCacheKey key{"nonexistent.example.com", QuestionType::A};
    cache.put(key, CacheResult::NXDOMAIN, 300);

    EXPECT_TRUE(cache.contains(key));
    auto entry = cache.get(key);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->result, CacheResult::NXDOMAIN);
    EXPECT_TRUE(entry->records.empty());
}

TEST(DnsCacheTest, CachesAndRetrievesNODATA)
{
    DnsCache cache;
    DnsCacheKey key{"example.com", QuestionType::AAAA};
    cache.put(key, CacheResult::NODATA, 120);

    EXPECT_TRUE(cache.contains(key));
    auto entry = cache.get(key);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->result, CacheResult::NODATA);
    EXPECT_TRUE(entry->records.empty());
}

TEST(DnsCacheTest, HandlesNegativeExpiration)
{
    DnsCache cache;
    DnsCacheKey nx_key{"nx.example.com", QuestionType::A};
    cache.put(nx_key, DnsCacheEntry(CacheResult::NXDOMAIN, std::chrono::seconds{-1}));

    EXPECT_FALSE(cache.contains(nx_key));
    EXPECT_FALSE(cache.get(nx_key).has_value());

    DnsCacheKey nodata_key{"nodata.example.com", QuestionType::AAAA};
    cache.put(nodata_key, DnsCacheEntry(CacheResult::NODATA, std::chrono::seconds{-1}));

    EXPECT_FALSE(cache.contains(nodata_key));
    EXPECT_FALSE(cache.get(nodata_key).has_value());
}

TEST(DnsCacheTest, TracksHitAndMissCounters)
{
    DnsCache cache;
    DnsCacheKey key{"example.com", QuestionType::A};
    DnsRecord rec("example.com", QuestionType::A, 1, 300, 4, ARecord{IPv4Address("93.184.216.34")});

    EXPECT_EQ(cache.hit_count(), 0U);
    EXPECT_EQ(cache.miss_count(), 0U);

    // Miss
    auto miss = cache.get(key);
    EXPECT_FALSE(miss.has_value());
    EXPECT_EQ(cache.miss_count(), 1U);
    EXPECT_EQ(cache.hit_count(), 0U);

    // Put and hit
    cache.put(key, rec);
    auto hit = cache.get(key);
    EXPECT_TRUE(hit.has_value());
    EXPECT_EQ(cache.hit_count(), 1U);
    EXPECT_EQ(cache.miss_count(), 1U);
}

TEST(DnsCacheTest, ClearAndRemove)
{
    DnsCache cache;
    DnsCacheKey k1{"one.example.com", QuestionType::A};
    DnsCacheKey k2{"two.example.com", QuestionType::A};
    DnsRecord r1("one.example.com", QuestionType::A, 1, 300, 4, ARecord{IPv4Address("1.1.1.1")});
    DnsRecord r2("two.example.com", QuestionType::A, 1, 300, 4, ARecord{IPv4Address("2.2.2.2")});

    cache.put(k1, r1);
    cache.put(k2, r2);
    EXPECT_EQ(cache.size(), 2U);

    cache.remove(k1);
    EXPECT_EQ(cache.size(), 1U);
    EXPECT_FALSE(cache.contains(k1));
    EXPECT_TRUE(cache.contains(k2));

    cache.clear();
    EXPECT_EQ(cache.size(), 0U);
    EXPECT_FALSE(cache.contains(k2));
}

TEST(DnsCacheTest, CaseInsensitiveDomainLookup)
{
    DnsCache cache;
    DnsCacheKey upper_key{"Example.COM", QuestionType::A};
    DnsRecord rec("Example.COM", QuestionType::A, 1, 300, 4, ARecord{IPv4Address("93.184.216.34")});
    cache.put(upper_key, rec);

    DnsCacheKey lower_key{"example.com", QuestionType::A};
    EXPECT_TRUE(cache.contains(lower_key));

    auto entry = cache.get(lower_key);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->records.size(), 1U);

    DnsCacheKey mixed_key{"eXaMpLe.CoM", QuestionType::A};
    EXPECT_TRUE(cache.contains(mixed_key));
}

