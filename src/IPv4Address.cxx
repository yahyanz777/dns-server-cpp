#include "IPv4Address.hpp"
#include <sstream>
#include <stdexcept>

IPv4Address::IPv4Address()
    : octets{0, 0, 0, 0}
{
}

IPv4Address::IPv4Address(const std::string &IP)
{
    std::array<uint8_t, 4> octs{};

    size_t it = 0;

    std::stringstream ss(IP);
    std::string octet;

    while (std::getline(ss, octet, '.'))
    {
        if (it >= 4)
        {
            throw std::invalid_argument("Invalid IP address format");
        }

        if (octet.empty() || octet.length() > 3)
        {
            throw std::invalid_argument("Invalid octet in IP address");
        }

        int value;

        try
        {
            value = std::stoi(octet);
        }
        catch (const std::exception &)
        {
            throw std::invalid_argument("Invalid octet in IP address");
        }

        if (value < 0 || value > 255)
        {
            throw std::invalid_argument("Invalid octet in IP address");
        }

        octs[it] = static_cast<uint8_t>(value);
        ++it;
    }

    if (it != 4)
    {
        throw std::invalid_argument("Invalid IP address format");
    }

    octets = octs;
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