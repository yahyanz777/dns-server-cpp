#pragma once

#include "IPAddress.hpp"

#include <cstdint>
#include <sys/socket.h>

// A transport endpoint. sockaddr_storage provides enough room for IPv4 and
// IPv6, while length_ preserves the concrete sockaddr size required by POSIX.
class SocketAddress
{
public:
    SocketAddress();

    static SocketAddress from_ip(const IPAddress& address, uint16_t port);
    static SocketAddress any(int family, uint16_t port);

    int family() const;
    const sockaddr* sockaddr_ptr() const;
    sockaddr* sockaddr_ptr();
    socklen_t length() const;
    void set_length(socklen_t length);

    bool operator==(const SocketAddress& other) const;

private:
    sockaddr_storage storage_{};
    socklen_t length_{};
};
