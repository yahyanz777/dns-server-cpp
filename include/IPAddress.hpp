#pragma once

#include "IPv4Address.hpp"
#include "IPv6Address.hpp"

#include <sys/socket.h>
#include <variant>

// An address in DNS/configuration data.  It intentionally does not contain a
// port or other socket-specific state.
using IPAddress = std::variant<IPv4Address, IPv6Address>;

inline int address_family(const IPAddress& address)
{
    return std::holds_alternative<IPv4Address>(address) ? AF_INET : AF_INET6;
}

inline std::string address_to_string(const IPAddress& address)
{
    return std::visit([](const auto& value) { return value.to_string(); }, address);
}
