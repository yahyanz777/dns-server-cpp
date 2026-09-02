#pragma once

#include <DnsCache.hpp>
#include <DnsPacket.hpp>
#include <QuestionType.hpp>
#include <RootServerManager.hpp>
#include <optional>
#include <string>

class DnsResolver
{
private:
    RootServerManager root_server_manager;
    DnsCache cache;

public:
    DnsResolver();
    ~DnsResolver() = default;

    DnsResolver(const DnsResolver&) = delete;
    DnsResolver& operator=(const DnsResolver&) = delete;

    DnsPacket lookup(const std::string& domain, QuestionType type = QuestionType::A);
    DnsPacket lookup(const DnsPacket& query);
    std::optional<DnsCacheEntry> is_cached(const DnsPacket& query);
    DnsCache& get_cache() { return cache; }
    const DnsCache& get_cache() const { return cache; }
};
