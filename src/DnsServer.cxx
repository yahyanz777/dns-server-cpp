#include "DnsServer.hpp"

#include "DnsPacket.hpp"
#include <cstdio>
#include "SocketAddress.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

namespace
{
std::string ResultCodeToString(ResultCode code)
{
    switch (code)
    {
    case ResultCode::NOERROR:  return "NOERROR";
    case ResultCode::FORMERR:  return "FORMERR";
    case ResultCode::SERVFAIL: return "SERVFAIL";
    case ResultCode::NXDOMAIN: return "NXDOMAIN";
    case ResultCode::NOTIMP:   return "NOTIMP";
    case ResultCode::REFUSED:  return "REFUSED";
    default:                   return "UNKNOWN";
    }
}

DnsPacket MakeServerFailure(const DnsPacket& request)
{
    DnsPacket response;
    if (request.get_question())
    {
        response.set_question(*request.get_question());
    }
    DnsHeader& header = response.get_header();
    header.ID = request.get_header().ID;
    header.set_response(true);
    header.set_authoritative(false);
    header.set_recursion_desired(request.get_header().recursion_desired());
    header.set_recursion_available(true);
    header.set_result_code(ResultCode::SERVFAIL);
    return response;
}

int MakeListeningSocket(int family, uint16_t port)
{
    const SocketAddress bind_address = SocketAddress::any(family, port);
    const int fd = socket(bind_address.family(), SOCK_DGRAM, 0);
    if (fd < 0)
    {
        throw std::runtime_error(std::string("Socket creation failed: ") + std::strerror(errno));
    }

    if (family == AF_INET6)
    {
        const int ipv6_only = 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only, sizeof(ipv6_only)) < 0)
        {
            const std::string error = std::strerror(errno);
            close(fd);
            throw std::runtime_error("Unable to configure IPv6 socket: " + error);
        }
    }

    if (bind(fd, bind_address.sockaddr_ptr(), bind_address.length()) < 0)
    {
        const std::string error = std::strerror(errno);
        close(fd);
        throw std::runtime_error("Bind failed: " + error);
    }
    return fd;
}
}

DnsServer::DnsServer(int requested_port)
{
    if (requested_port < 0 || requested_port > UINT16_MAX)
    {
        throw std::invalid_argument("DNS port must be between 0 and 65535");
    }
    port = static_cast<uint16_t>(requested_port);

    try
    {
        server_sockets[0] = MakeListeningSocket(AF_INET, port);
        server_sockets[1] = MakeListeningSocket(AF_INET6, port);
    }
    catch (...)
    {
        for (const int fd : server_sockets)
        {
            if (fd >= 0)
            {
                close(fd);
            }
        }
        throw;
    }
}

DnsServer::~DnsServer()
{
    for (const int fd : server_sockets)
    {
        if (fd >= 0)
        {
            close(fd);
        }
    }
}

void DnsServer::start()
{
    while (true)
    {
        std::array<pollfd, 2> descriptors{};
        for (std::size_t index = 0; index < server_sockets.size(); ++index)
        {
            descriptors[index].fd = server_sockets[index];
            descriptors[index].events = POLLIN;
        }

        const auto ready = poll(descriptors.data(), descriptors.size(), 1000);
        if (ready < 0)
        {
            perror("poll failed");
            continue;
        }

        if(ready == 0)
        {
            continue;
        }
        for (const pollfd& descriptor : descriptors)
        {
            if (!(descriptor.revents & POLLIN))
            {
                continue;
            }

            SocketAddress client_addr;
            socklen_t client_addr_len = client_addr.length();
            BytePacketBuffer rcv_buffer;
            const auto bytes_received = recvfrom(
                descriptor.fd,
                rcv_buffer.get_buffer().data(),
                rcv_buffer.get_buffer().size(),
                0,
                client_addr.sockaddr_ptr(),
                &client_addr_len);
            if (bytes_received < 0)
            {
                perror("recvfrom failed");
                continue;
            }
            client_addr.set_length(client_addr_len);
            rcv_buffer.set_length(static_cast<std::size_t>(bytes_received));

            try
            {
                DnsPacket packet = DnsPacket::read(rcv_buffer);
                if (packet.get_header().is_response() || packet.get_question() == nullptr)
                {
                    continue;
                }

                const auto start_time = std::chrono::steady_clock::now();
                const std::string qname = packet.get_question()->get_name();
                const std::string qtype = GetQuestionTypeName(packet.get_question()->get_type());

                const auto client_edns = packet.get_edns_info();

                DnsPacket response = handle_query(packet);
                if (!response.get_header().is_response() || response.get_question() == nullptr)
                {
                    response = MakeServerFailure(packet);
                }

                // Enforce recursive resolver header invariants
                response.get_header().ID = packet.get_header().ID;
                response.get_header().set_response(true);
                response.get_header().set_authoritative(false);
                response.get_header().set_recursion_available(true);
                response.get_header().set_recursion_desired(packet.get_header().recursion_desired());

                const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start_time).count();
                const std::string rcode_str = ResultCodeToString(response.get_header().get_result_code());
                const std::size_t answers_count = response.get_answers().size();

                std::cout << "[QUERY] " << qname << " (" << qtype << ") -> " 
                          << rcode_str << " (" << answers_count << " answers) [" 
                          << duration_ms << "ms]" << std::endl;

                // Strip any upstream OPT records so they do not leak to the client
                auto& additionals = response.get_additionals();
                additionals.erase(
                    std::remove_if(additionals.begin(), additionals.end(),
                                   [](const DnsRecord& rec) {
                                       return rec.get_type() == QuestionType::OPT;
                                   }),
                    additionals.end());

                if (client_edns.has_value())
                {
                    response.create_additional_opt_record(
                        client_edns->max_payload_size,
                        0,
                        0,
                        client_edns->dnssec_ok);
                }

                std::size_t response_capacity = client_edns.has_value() ? client_edns->max_payload_size : DEFAULT_BUFFER_SIZE;
                BytePacketBuffer response_buffer(response_capacity);
                response.write(response_buffer);
                if (sendto(descriptor.fd, response_buffer.get_buffer().data(), response_buffer.get_length(), 0,
                           client_addr.sockaddr_ptr(), client_addr.length()) < 0)
                {
                    perror("sendto failed");
                }
            }
            catch (const std::exception&)
            {
                // Ignore malformed DNS datagrams and keep serving later requests.
                continue;
            }
        }
    }
}

DnsPacket DnsServer::handle_query(const DnsPacket& request)
{
    return resolver.lookup(request);
}
