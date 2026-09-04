#include <DnsResolver.hpp>

#include <algorithm>
#include <cctype>
#include <poll.h>
#include <random>
#include <SocketAddress.hpp>
#include <string_view>
#include <unistd.h>

namespace
{
    constexpr int DNS_PORT = 53;
    constexpr int QUERY_TIMEOUT_MS = 1000;
    constexpr std::size_t MAX_REFERRALS = 16;
    constexpr uint32_t DEFAULT_NEGATIVE_TTL = 60;

    bool EqualsIgnoreCase(std::string_view a, std::string_view b)
    {
        return a.size() == b.size() &&
               std::equal(a.begin(), a.end(), b.begin(), b.end(),
                          [](char ca, char cb)
                          {
                              return std::tolower(static_cast<unsigned char>(ca)) ==
                                     std::tolower(static_cast<unsigned char>(cb));
                          });
    }

    uint32_t ExtractNegativeTtl(const DnsPacket &packet, uint32_t default_ttl = DEFAULT_NEGATIVE_TTL)
    {
        for (const auto &record : packet.get_authorities())
        {
            if (const auto *soa = record.get_soa_record())
            {
                const uint32_t soa_ttl = record.get_ttl();
                const uint32_t min_field = soa->minimum_ttl;
                if (soa_ttl > 0 && min_field > 0)
                {
                    return std::min(soa_ttl, min_field);
                }
                if (soa_ttl > 0)
                {
                    return soa_ttl;
                }
                if (min_field > 0)
                {
                    return min_field;
                }
                return default_ttl;
            }
        }
        return default_ttl;
    }

    DnsPacket QueryNameServer(const DnsPacket &query, const IPAddress &address)
    {
        DnsPacket request;
        if (query.get_question())
        {
            request.set_question(*query.get_question());
        }
        request.get_header().ID = query.get_header().ID;
        request.get_header().set_recursion_desired(false);
        request.create_additional_opt_record(1232, 0, 0, false);

        BytePacketBuffer request_buffer(MAX_BUFFER_SIZE);
        try
        {
            request.write(request_buffer);
        }
        catch (const std::exception &)
        {
            return DnsPacket();
        }

        const SocketAddress server_addr = SocketAddress::from_ip(address, DNS_PORT);
        const int socket_fd = socket(server_addr.family(), SOCK_DGRAM, 0);
        if (socket_fd < 0)
        {
            return DnsPacket();
        }

        const ssize_t sent = sendto(socket_fd, request_buffer.get_buffer().data(), request_buffer.get_length(), 0,
                                    server_addr.sockaddr_ptr(), server_addr.length());
        if (sent != static_cast<ssize_t>(request_buffer.get_length()))
        {

            close(socket_fd);
            return DnsPacket();
        }

        pollfd poll_descriptor{socket_fd, POLLIN, 0};
        if (poll(&poll_descriptor, 1, QUERY_TIMEOUT_MS) <= 0 || !(poll_descriptor.revents & POLLIN))
        {
            close(socket_fd);
            return DnsPacket();
        }

        BytePacketBuffer response_buffer(MAX_BUFFER_SIZE);
        SocketAddress response_addr;
        socklen_t response_addr_len = response_addr.length();
        const ssize_t received = recvfrom(socket_fd, response_buffer.get_buffer().data(), response_buffer.get_buffer().size(), 0,
                                          response_addr.sockaddr_ptr(), &response_addr_len);
        close(socket_fd);
        if (received < 0)
        {
            return DnsPacket();
        }
        response_addr.set_length(response_addr_len);
        if (!(response_addr == server_addr))
        {
            return DnsPacket();
        }

        response_buffer.set_length(static_cast<std::size_t>(received));
        try
        {
            DnsPacket response = DnsPacket::read(response_buffer);
            if (!response.get_header().is_response() || response.get_header().ID != request.get_header().ID)
            {
                return DnsPacket();
            }
            return response;
        }
        catch (const std::exception &)
        {
            return DnsPacket();
        }
    }

    DnsPacket FinalizeResponse(DnsPacket response, const DnsPacket &query)
    {
        if (response.get_header().is_response())
        {
            DnsHeader &header = response.get_header();
            header.ID = query.get_header().ID;
            header.set_response(true);
            header.set_authoritative(false);
            header.set_recursion_available(true);
            header.set_recursion_desired(query.get_header().recursion_desired());
            if (!response.get_question() && query.get_question())
            {
                response.set_question(*query.get_question());
            }
        }
        return response;
    }
}

DnsResolver::DnsResolver() : root_server_manager() {}

DnsPacket DnsResolver::lookup(const std::string &domain, QuestionType type,std::optional<EdnsInfo> edns_info)
{
    DnsPacket packet;

    if(edns_info.has_value())
    {
        packet.create_additional_opt_record(edns_info->max_payload_size, 0, edns_info->version, edns_info->dnssec_ok);
    }
   

    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<uint16_t> dist(0, UINT16_MAX);

    const uint16_t query_id = dist(gen);

    DnsHeader &header = packet.get_header();
    header.ID = query_id;
    header.set_recursion_desired(false);
    header.set_QDCOUNT(1);

    packet.set_question(DnsQuestion(domain, type));
    return lookup(packet);
}

DnsPacket DnsResolver::lookup(const DnsPacket &query)
{
    if (query.get_question() == nullptr)
    {
        return DnsPacket();
    }

    const std::optional<EdnsInfo> edns_info = query.get_edns_info();

    const uint16_t max_payload_size = edns_info.has_value() ? edns_info->max_payload_size : 512;

    std::optional<DnsCacheEntry> cached_entry = is_cached(query);
    if (cached_entry.has_value())
    {
        DnsPacket response;
        response.set_question(*query.get_question());
        DnsHeader &header = response.get_header();
        header.ID = query.get_header().ID;
        header.FLAGS = 0;
        header.set_response(true);
        header.set_recursion_desired(query.get_header().recursion_desired());
        header.set_recursion_available(true);
        if (cached_entry->result == CacheResult::NXDOMAIN)
        {
            header.set_result_code(ResultCode::NXDOMAIN);
        }
        else if (cached_entry->result == CacheResult::NODATA)
        {
            header.set_result_code(ResultCode::NOERROR);
        }
        else
        {
            header.set_result_code(ResultCode::NOERROR);
            response.set_answers(cached_entry->records);
        }
        return response;
    }

    DnsPacket response = root_server_manager.AskRootServer(query);

    std::vector<IPAddress> queried_servers;

    // Follow referrals. A root response normally points to a TLD server, which
    // can in turn refer us to the authoritative server for the requested name.
    for (std::size_t referral_count = 0; referral_count < MAX_REFERRALS; ++referral_count)
    {
        if (!response.get_header().is_response())
        {
            return response;
        }

        if (!response.get_answers().empty())
        {

            const QuestionType requested_type = query.get_question()->get_type();
            if (requested_type != QuestionType::CNAME)
            {
                constexpr std::size_t MAX_CNAME_HOPS = 10;
                for (std::size_t hop = 0; hop < MAX_CNAME_HOPS; ++hop)
                {
                    // If the response already contains an answer matching the requested type, no further CNAME resolution needed
                    const bool has_requested_record = std::any_of(
                        response.get_answers().begin(), response.get_answers().end(),
                        [requested_type](const DnsRecord& rec) {
                            return rec.get_type() == requested_type;
                        });
                    if (has_requested_record)
                    {
                        break;
                    }

                    // Find CNAME record
                    std::string cname_target;
                    for (const auto& rec : response.get_answers())
                    {
                        if (rec.get_type() == QuestionType::CNAME && rec.get_cname_record())
                        {
                            cname_target = rec.get_cname_record()->canonical_name;
                            break;
                        }
                    }

                    if (cname_target.empty())
                    {
                        break;
                    }

                    DnsPacket cname_response = lookup(cname_target, requested_type);
                    if (cname_response.get_answers().empty())
                    {
                        break;
                    }

                    // Append answers from cname_response to response
                    const auto& new_answers = cname_response.get_answers();
                    response.get_answers().insert(response.get_answers().end(),
                                                  new_answers.begin(),
                                                  new_answers.end());
                }
            }

            cache.put(DnsCacheKey{query.get_question()->get_name(), query.get_question()->get_type()},
                      response.get_answers());
            return FinalizeResponse(response, query);
        }

        if (response.get_header().get_result_code() != ResultCode::NOERROR)
        {
            if (response.get_header().get_result_code() == ResultCode::NXDOMAIN)
            {
                const uint32_t neg_ttl = ExtractNegativeTtl(response);
                cache.put(DnsCacheKey{query.get_question()->get_name(), query.get_question()->get_type()},
                          CacheResult::NXDOMAIN, neg_ttl);
            }
            return FinalizeResponse(response, query);
        }

        if (response.get_authorities().empty() && response.get_additionals().empty())
        {
            const uint32_t neg_ttl = ExtractNegativeTtl(response);
            cache.put(DnsCacheKey{query.get_question()->get_name(), query.get_question()->get_type()},
                      CacheResult::NODATA, neg_ttl);
            return FinalizeResponse(response, query);
        }

        // Collect authoritative nameserver hostnames from NS records in authority section
        std::vector<std::string> ns_names;
        for (const DnsRecord &record : response.get_authorities())
        {
            if (const auto *ns = record.get_ns_record())
            {
                ns_names.push_back(ns->name_server);
            }
        }

        // Collect candidate nameserver IP addresses from additionals (glue records)
        std::vector<IPAddress> candidate_nameservers;
        auto add_candidate = [&candidate_nameservers](const IPAddress &ip)
        {
            if (std::find(candidate_nameservers.begin(), candidate_nameservers.end(), ip) == candidate_nameservers.end())
            {
                candidate_nameservers.push_back(ip);
            }
        };

        for (const auto &ns_name : ns_names)
        {
            for (const DnsRecord &record : response.get_additionals())
            {
                if (EqualsIgnoreCase(record.get_name(), ns_name))
                {
                    if (const auto ip = record.get_ip_address(); ip.has_value())
                    {
                        add_candidate(*ip);
                    }
                }
            }
        }

        // If no matching glue record was present in additionals, resolve NS names from authorities
        if (candidate_nameservers.empty())
        {
            for (const auto &ns_name : ns_names)
            {
                DnsPacket ns_packet = lookup(ns_name, QuestionType::A);
                for (const auto &ans : ns_packet.get_answers())
                {
                    if (const auto ip = ans.get_ip_address(); ip.has_value())
                    {
                        add_candidate(*ip);
                    }
                }

                ns_packet = lookup(ns_name, QuestionType::AAAA);
                for (const auto &ans : ns_packet.get_answers())
                {
                    if (const auto ip = ans.get_ip_address(); ip.has_value())
                    {
                        add_candidate(*ip);
                    }
                }
            }
        }

        if (candidate_nameservers.empty())
        {
            const uint32_t neg_ttl = ExtractNegativeTtl(response);
            cache.put(DnsCacheKey{query.get_question()->get_name(), query.get_question()->get_type()},
                      CacheResult::NODATA, neg_ttl);
            return FinalizeResponse(response, query);
        }

        bool queried_successfully = false;
        for (const auto &server_address : candidate_nameservers)
        {
            if (std::find(queried_servers.begin(), queried_servers.end(), server_address) != queried_servers.end())
            {
                continue;
            }
            queried_servers.push_back(server_address);

            DnsPacket current_response = QueryNameServer(query, server_address);
            if (current_response.get_header().is_response() &&
                (current_response.get_header().get_result_code() != ResultCode::NOERROR ||
                 !current_response.get_answers().empty() ||
                 !current_response.get_authorities().empty() ||
                 !current_response.get_additionals().empty()))
            {
                response = std::move(current_response);
                queried_successfully = true;
                break;
            }
        }

        if (!queried_successfully)
        {
            const uint32_t neg_ttl = ExtractNegativeTtl(response);
            cache.put(DnsCacheKey{query.get_question()->get_name(), query.get_question()->get_type()},
                      CacheResult::NODATA, neg_ttl);
            return FinalizeResponse(response, query);
        }
    }

    return FinalizeResponse(response, query);
}

std::optional<DnsCacheEntry> DnsResolver::is_cached(const DnsPacket &query)
{
    if (query.get_question() == nullptr)
    {
        return std::nullopt;
    }
    return cache.get(DnsCacheKey{query.get_question()->get_name(), query.get_question()->get_type()});
}
