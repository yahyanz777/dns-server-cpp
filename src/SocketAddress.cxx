#include "SocketAddress.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <type_traits>

SocketAddress::SocketAddress() : length_(sizeof(storage_)) {}

SocketAddress SocketAddress::from_ip(const IPAddress& address, uint16_t port)
{
    SocketAddress result;
    std::visit(
        [&result, port](const auto& value)
        {
            using Address = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<Address, IPv4Address>)
            {
                sockaddr_in endpoint{};
                endpoint.sin_family = AF_INET;
                endpoint.sin_port = htons(port);
                std::memcpy(&endpoint.sin_addr, value.bytes().data(), value.bytes().size());
                std::memcpy(&result.storage_, &endpoint, sizeof(endpoint));
                result.length_ = sizeof(endpoint);
            }
            else
            {
                sockaddr_in6 endpoint{};
                endpoint.sin6_family = AF_INET6;
                endpoint.sin6_port = htons(port);
                std::memcpy(&endpoint.sin6_addr, value.bytes().data(), value.bytes().size());
                std::memcpy(&result.storage_, &endpoint, sizeof(endpoint));
                result.length_ = sizeof(endpoint);
            }
        },
        address);
    return result;
}

SocketAddress SocketAddress::any(int family, uint16_t port)
{
    if (family == AF_INET)
    {
        return from_ip(IPAddress{IPv4Address{}}, port);
    }
    if (family == AF_INET6)
    {
        return from_ip(IPAddress{IPv6Address{}}, port);
    }
    throw std::invalid_argument("Unsupported socket address family");
}

int SocketAddress::family() const
{
    return sockaddr_ptr()->sa_family;
}

const sockaddr* SocketAddress::sockaddr_ptr() const
{
    return reinterpret_cast<const sockaddr*>(&storage_);
}

sockaddr* SocketAddress::sockaddr_ptr()
{
    return reinterpret_cast<sockaddr*>(&storage_);
}

socklen_t SocketAddress::length() const
{
    return length_;
}

void SocketAddress::set_length(socklen_t length)
{
    if (length > sizeof(storage_))
    {
        throw std::invalid_argument("Socket address length is too large");
    }
    length_ = length;
}

bool SocketAddress::operator==(const SocketAddress& other) const
{
    if (family() != other.family())
    {
        return false;
    }

    if (family() == AF_INET)
    {
        const auto& left = *reinterpret_cast<const sockaddr_in*>(&storage_);
        const auto& right = *reinterpret_cast<const sockaddr_in*>(&other.storage_);
        return left.sin_port == right.sin_port &&
               std::memcmp(&left.sin_addr, &right.sin_addr, sizeof(left.sin_addr)) == 0;
    }

    if (family() == AF_INET6)
    {
        const auto& left = *reinterpret_cast<const sockaddr_in6*>(&storage_);
        const auto& right = *reinterpret_cast<const sockaddr_in6*>(&other.storage_);
        return left.sin6_port == right.sin6_port && left.sin6_scope_id == right.sin6_scope_id &&
               std::memcmp(&left.sin6_addr, &right.sin6_addr, sizeof(left.sin6_addr)) == 0;
    }

    return false;
}
