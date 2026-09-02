#include "DnsServer.hpp"

#include "DnsPacket.hpp"
#include <cstdio>
#include "SocketAddress.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

namespace
{
DnsPacket MakeServerFailure(const DnsPacket& request)
{
    DnsPacket response = request;
    DnsHeader& header = response.get_header();
    header.set_response(true);             // QR: response
    header.set_recursion_available(false); // RA: this server does not recurse
    header.set_result_code(ResultCode::SERVFAIL); // RCODE: SERVFAIL
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

                DnsPacket response = handle_query(packet);
                if (!response.get_header().is_response() || response.get_question() == nullptr)
                {
                    response = MakeServerFailure(packet);
                }

                BytePacketBuffer response_buffer;
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
