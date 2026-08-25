#include <DnsResolver.hpp>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <random>
#include <stdexcept>

DnsResolver::DnsResolver()
{
    server_socket = socket(AF_INET, SOCK_DGRAM, 0);

    if (server_socket < 0)
    {
        throw std::runtime_error("Failed to create socket");
    }

    server_addr = {};

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);

    if (inet_pton(AF_INET, "8.8.8.8", &server_addr.sin_addr) != 1)
    {
        close(server_socket);
        throw std::runtime_error("Failed to set DNS server address");
    }
}

DnsResolver::~DnsResolver()
{
    close(server_socket);
}

DnsPacket DnsResolver::lookup(const std::string &domain, QuestionType type)
{

    BytePacketBuffer sender_buffer{};
    DnsPacket packet;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dist(0, UINT16_MAX);

    uint16_t query_id = dist(gen);

    packet.get_header().ID = query_id;
    packet.get_header().set_recursion_desired(true);

    packet.add_question(DnsQuestion(domain, type));

    packet.write(sender_buffer);

    const auto& raw_request = sender_buffer.get_buffer();
    const auto sent = sendto(server_socket, raw_request.data(), sender_buffer.position(), 0,
                             reinterpret_cast<const sockaddr*>(&server_addr), sizeof(server_addr));

    if (sent < 0)
    {
        throw std::runtime_error("Failed to send DNS query");
    }

    BytePacketBuffer response_buffer{};
    auto& raw_response = response_buffer.get_buffer();


    const auto received = recvfrom(server_socket, raw_response.data(), raw_response.size(), 0,
                                   nullptr, nullptr);

    if (received < 0)
    {
        throw std::runtime_error("Failed to receive DNS response");
    }

    response_buffer.set_length(static_cast<std::size_t>(received));

    DnsPacket response = DnsPacket::read(response_buffer);

    if (response.get_header().ID != query_id)
    {
        throw std::runtime_error("DNS response ID does not match query ID");
    }

    return response;
}
