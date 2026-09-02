#include "DnsCache.hpp"

void DnsCache::put(const DnsCacheKey& key, const DnsCacheEntry& entry)
{
    if (entry.expired())
    {
        return;
    }
    if (entry.result == CacheResult::POSITIVE && entry.records.empty())
    {
        return;
    }
    cache[key] = entry;
}

void DnsCache::put(const DnsCacheKey& key, const std::vector<DnsRecord>& records, uint32_t ttl)
{
    if (records.empty())
    {
        return;
    }
    uint32_t min_ttl = ttl > 0 ? ttl : 60;
    for (const auto& rec : records)
    {
        if (rec.get_ttl() > 0 && rec.get_ttl() < min_ttl)
        {
            min_ttl = rec.get_ttl();
        }
    }
    put(key, DnsCacheEntry(records, std::chrono::seconds{min_ttl}));
}

void DnsCache::put(const DnsCacheKey& key, const DnsRecord& record)
{
    uint32_t ttl = record.get_ttl() > 0 ? record.get_ttl() : 60;
    put(key, DnsCacheEntry(record, std::chrono::seconds{ttl}));
}

void DnsCache::put(const DnsCacheKey& key, CacheResult result, uint32_t ttl)
{
    uint32_t actual_ttl = ttl > 0 ? ttl : 60;
    put(key, DnsCacheEntry(result, std::chrono::seconds{actual_ttl}));
}


std::optional<DnsCacheEntry> DnsCache::get(const DnsCacheKey& key)
{
    const auto it = cache.find(key);
    if (it == cache.end())
    {
        ++cachemissCount;
        return std::nullopt;
    }

    if (it->second.expired())
    {
        cache.erase(it);
        ++cachemissCount;
        return std::nullopt;
    }

    ++cachehitCount;
    return it->second;
}

void DnsCache::remove(const DnsCacheKey& key)
{
    cache.erase(key);
}

bool DnsCache::contains(const DnsCacheKey& key)
{
    return get(key).has_value();
}

void DnsCache::clear()
{
    cache.clear();
}

size_t DnsCache::size() const
{
    return cache.size();
}