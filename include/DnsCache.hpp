#pragma once

#include <cctype>
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "DnsRecord.hpp"
#include "QuestionType.hpp"

using Clock = std::chrono::steady_clock;

enum class CacheResult
{
    POSITIVE,
    NXDOMAIN,
    NODATA,
};


struct DnsCacheEntry {
    std::vector<DnsRecord> records;
    CacheResult result{CacheResult::POSITIVE};
    std::chrono::steady_clock::time_point expirationTime;

    DnsCacheEntry() = default;
    explicit DnsCacheEntry(std::vector<DnsRecord> recs,
                           std::chrono::seconds ttl = std::chrono::seconds{60})
        : records(std::move(recs)),
          result(CacheResult::POSITIVE),
          expirationTime(Clock::now() + ttl)
    {
    }

    explicit DnsCacheEntry(DnsRecord rec,
                           std::chrono::seconds ttl = std::chrono::seconds{60})
        : records{std::move(rec)},
          result(CacheResult::POSITIVE),
          expirationTime(Clock::now() + ttl)
    {
    }

    explicit DnsCacheEntry(CacheResult res,
                           std::chrono::seconds ttl = std::chrono::seconds{60})
        : records{},
          result(res),
          expirationTime(Clock::now() + ttl)
    {
    }

    explicit DnsCacheEntry(CacheResult res,
                           std::vector<DnsRecord> recs,
                           std::chrono::seconds ttl = std::chrono::seconds{60})
        : records(std::move(recs)),
          result(res),
          expirationTime(Clock::now() + ttl)
    {
    }

    bool expired() const { return Clock::now() >= expirationTime; }
};

struct DnsCacheKey {
    std::string domain;
    QuestionType type{QuestionType::A};

    DnsCacheKey() = default;
    DnsCacheKey(std::string d, QuestionType t)
        : domain(normalize(std::move(d))), type(t) {}

    bool operator==(const DnsCacheKey& other) const
    {
        return domain == other.domain && type == other.type;
    }

private:
    static std::string normalize(std::string s)
    {
        for (char& c : s)
        {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return s;
    }
};

struct DnsCacheKeyHash {
    std::size_t operator()(const DnsCacheKey& key) const noexcept
    {
        const std::size_t domain_hash = std::hash<std::string>{}(key.domain);
        const std::size_t type_hash = std::hash<int>{}(static_cast<int>(key.type));
        return domain_hash ^ (type_hash + 0x9e3779b97f4a7c15ULL + (domain_hash << 6) + (domain_hash >> 2));
    }
};

class DnsCache {
private:
    std::unordered_map<DnsCacheKey, DnsCacheEntry, DnsCacheKeyHash> cache;

    size_t cachehitCount = 0;
    size_t cachemissCount = 0;

public:
    DnsCache() = default;
    void put(const DnsCacheKey& key, const DnsCacheEntry& entry);
    void put(const DnsCacheKey& key, const std::vector<DnsRecord>& records, uint32_t ttl = 60);
    void put(const DnsCacheKey& key, const DnsRecord& record);
    void put(const DnsCacheKey& key, CacheResult result, uint32_t ttl = 60);
    std::optional<DnsCacheEntry> get(const DnsCacheKey& key);

    void remove(const DnsCacheKey& key);
    bool contains(const DnsCacheKey& key);
    void clear();
    size_t size() const;
    size_t hit_count() const { return cachehitCount; }
    size_t miss_count() const { return cachemissCount; }
};

