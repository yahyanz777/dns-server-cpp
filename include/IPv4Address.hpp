#pragma once

#include <array>
#include <cstdint>
#include <string>

class IPv4Address
{
private:
    std::array<uint8_t, 4> octets;

public:
    IPv4Address();
    IPv4Address(const std::array<uint8_t, 4> &octets);
    IPv4Address(const std::string &IP);
    IPv4Address(uint32_t ip);
    std::string to_string() const;
    uint32_t to_uint32() const;
    const std::array<uint8_t, 4>& bytes() const { return octets; }
    bool operator==(const IPv4Address&) const = default;
};
