#include "DnsServer.hpp"

#include "DnsPacket.hpp"
#include <cstdlib>
#include <cstdio>
#include <sys/socket.h>
#include <unistd.h>

DnsServer::DnsServer(int port) : port(port)
{
    server_socket = socket(AF_INET, SOCK_DGRAM, 0);

    if (server_socket < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    sockaddr_in server_addr{};

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(
            server_socket,
            reinterpret_cast<const sockaddr *>(&server_addr),
            sizeof(server_addr)) < 0)
    {

        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
}

DnsServer::~DnsServer()
{
    close(server_socket);
}

void DnsServer::start()
{
    while (true)
    {
        BytePacketBuffer buffer;

        sockaddr_in client{};
        socklen_t client_length = sizeof(client);

        const auto received = recvfrom(
            server_socket,
            buffer.get_buffer().data(),
            buffer.get_buffer().size(),
            0,
            reinterpret_cast<sockaddr *>(&client),
            &client_length);

        if (received < 0)
        {
            perror("recvfrom failed");
            continue;
        }

        buffer.set_length(static_cast<std::size_t>(received));

        DnsPacket request = DnsPacket::read(buffer);

        if (DnsQuestion *question = request.get_question())
        {
            uint16_t client_id = request.get_header().ID;

            DnsPacket response = handle_query(*question);

            response.get_header().ID = client_id;

            BytePacketBuffer toclientbuff;
            response.write(toclientbuff);

            const auto sent = sendto(
                server_socket,
                toclientbuff.get_buffer().data(),
                toclientbuff.position(),
                0,
                reinterpret_cast<sockaddr *>(&client),
                client_length);

            if (sent < 0)
            {
                perror("sendto failed");
            }
        }
    }
}

DnsPacket DnsServer::handle_query(DnsQuestion &req)
{
    return resolver.lookup(req.getName(), req.getType());
}
