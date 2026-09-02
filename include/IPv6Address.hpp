#pragma once

#include <array>
#include <cstdint>
#include <string>

class IPv6Address {
    std::array<uint8_t, 16> address;

public:
    IPv6Address() : address{} {}

    explicit IPv6Address(const std::string& text);

    IPv6Address(const std::array<uint8_t, 16>& addr)
        : address(addr) {}

    IPv6Address(std::array<uint8_t, 16>&& addr)
        : address(std::move(addr)) {}

    std::string to_string() const;

    const std::array<uint8_t, 16>& bytes() const {
        return address;
    }

    bool operator==(const IPv6Address&) const = default;
};
