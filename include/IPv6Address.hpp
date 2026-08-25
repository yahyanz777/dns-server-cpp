#include <cstdint>
#include <array>
#include <string>

class IPv6Address {
    std::array<uint8_t, 16> address;

public:
    IPv6Address() = default;

    IPv6Address(const std::array<uint8_t, 16>& addr)
        : address(addr) {}

    IPv6Address(std::array<uint8_t, 16>&& addr)
        : address(std::move(addr)) {}

    std::string to_string() const;

    const std::array<uint8_t, 16>& bytes() const {
        return address;
    }
};
    