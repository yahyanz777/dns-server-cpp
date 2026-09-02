#include "IPv6Address.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

IPv6Address::IPv6Address(const std::string& text)
{
    in6_addr parsed{};
    if (inet_pton(AF_INET6, text.c_str(), &parsed) != 1)
    {
        throw std::invalid_argument("Invalid IPv6 address");
    }
    std::memcpy(address.data(), &parsed, address.size());
}

std::string IPv6Address::to_string() const
{
    char text[INET6_ADDRSTRLEN]{};
    if (inet_ntop(AF_INET6, address.data(), text, sizeof(text)) == nullptr)
    {
        throw std::runtime_error("Unable to format IPv6 address");
    }
    return text;
}
