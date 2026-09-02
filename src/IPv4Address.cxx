#include "IPv4Address.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

IPv4Address::IPv4Address()
    : octets{0, 0, 0, 0}
{
}

IPv4Address::IPv4Address(const std::string &IP)
{
    in_addr parsed{};
    if (inet_pton(AF_INET, IP.c_str(), &parsed) != 1)
    {
        throw std::invalid_argument("Invalid IPv4 address");
    }
    std::memcpy(octets.data(), &parsed, octets.size());
}

IPv4Address::IPv4Address(const std::array<uint8_t, 4> &octs)
    : octets(octs)
{
}

IPv4Address::IPv4Address(uint32_t ip)
{
    octets[0] = static_cast<uint8_t>((ip >> 24) & 0xFF);
    octets[1] = static_cast<uint8_t>((ip >> 16) & 0xFF);
    octets[2] = static_cast<uint8_t>((ip >> 8) & 0xFF);
    octets[3] = static_cast<uint8_t>(ip & 0xFF);
}

uint32_t IPv4Address::to_uint32() const
{
    return (static_cast<uint32_t>(octets[0]) << 24) |
           (static_cast<uint32_t>(octets[1]) << 16) |
           (static_cast<uint32_t>(octets[2]) << 8) |
           static_cast<uint32_t>(octets[3]);
}

std::string IPv4Address::to_string() const
{
    return std::to_string(octets[0]) + "." +
           std::to_string(octets[1]) + "." +
           std::to_string(octets[2]) + "." +
           std::to_string(octets[3]);
}
