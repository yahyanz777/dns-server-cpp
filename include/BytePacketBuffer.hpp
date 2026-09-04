#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>
#include <iostream>

static constexpr std::size_t MAX_BUFFER_SIZE = 1232;
static constexpr std::size_t DEFAULT_BUFFER_SIZE = 512;

class BytePacketBuffer
{
public:
    explicit BytePacketBuffer(std::size_t capacity = DEFAULT_BUFFER_SIZE);

    BytePacketBuffer(std::initializer_list<uint8_t> bytes, std::size_t capacity = DEFAULT_BUFFER_SIZE);
    explicit BytePacketBuffer(const std::vector<uint8_t> &bytes, std::size_t capacity = DEFAULT_BUFFER_SIZE);

    uint8_t read_u8();
    uint8_t get();
    uint16_t read_u16();
    uint32_t read_u32();
    void step(std::size_t steps);
    void seek(std::size_t pos);
    std::string read_qname();
    std::vector<uint8_t> read_bytes(std::size_t count);

    std::size_t position() const noexcept;
    std::size_t remaining() const noexcept;

    void write_u8(uint8_t);
    void write_u16(uint16_t);
    void write_u32(uint32_t);
    void write_qname(const std::string &domain);

    std::array<uint8_t, MAX_BUFFER_SIZE> &get_buffer() noexcept;
    const std::array<uint8_t, MAX_BUFFER_SIZE> &get_buffer() const noexcept;
    void set_length(std::size_t length);
    void set_max_capacity(std::size_t capacity) noexcept;
    std::size_t get_length() const noexcept { return len; }
    std::size_t get_max_capacity() const noexcept { return max_capacity; }

private:
    std::array<uint8_t, MAX_BUFFER_SIZE> buff{};
    std::size_t pos{};
    std::size_t len{};
    std::size_t max_capacity{DEFAULT_BUFFER_SIZE};
};
