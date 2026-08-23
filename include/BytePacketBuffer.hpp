#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>
#include <iostream>

class BytePacketBuffer {
public:
    BytePacketBuffer() = default;
    BytePacketBuffer(std::initializer_list<uint8_t> bytes);
    explicit BytePacketBuffer(const std::vector<uint8_t>& bytes);

    

    uint8_t read_u8();
    uint8_t get();
    uint16_t read_u16();
    uint32_t read_u32();
    void step(std::size_t steps);
    void seek(std::size_t pos);
    std::string read_qname();
    std::vector<uint8_t> read_bytes(std::size_t count);

    [[nodiscard]] std::size_t position() const noexcept;
    [[nodiscard]] std::size_t remaining() const noexcept;

private:
    std::array<uint8_t, 512> buff{};
    std::size_t pos{};
    std::size_t len{};
};
