#include "DnsResolver.hpp"

#include <array>
#include <cstdint>

class DnsServer {
    std::array<int, 2> server_sockets{-1, -1};
    uint16_t port{53};
    DnsResolver resolver{};

public:
    DnsServer(int port);

    ~DnsServer();

    void start();

    DnsPacket handle_query(const DnsPacket& request);

};
