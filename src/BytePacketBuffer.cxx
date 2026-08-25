#include <BytePacketBuffer.hpp>

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace
{
    void require_available(std::size_t pos, std::size_t need, std::size_t len)
    {
        if (pos > len || need > len - pos)
        {
            throw std::out_of_range("BytePacketBuffer read out of bounds");
        }
    }
}

BytePacketBuffer::BytePacketBuffer(std::initializer_list<uint8_t> bytes)
{
    if (bytes.size() > buff.size())
    {
        throw std::length_error("DNS packet exceeds the 512-byte buffer capacity");
    }

    len = bytes.size();
    std::copy_n(bytes.begin(), len, buff.begin());
    pos = 0;
}

BytePacketBuffer::BytePacketBuffer(const std::vector<uint8_t> &bytes)
{
    if (bytes.size() > buff.size())
    {
        throw std::length_error("DNS packet exceeds the 512-byte buffer capacity");
    }

    len = bytes.size();
    std::copy_n(bytes.begin(), len, buff.begin());
    pos = 0;
}

uint8_t BytePacketBuffer::read_u8()
{
    require_available(pos, 1, len);
    return buff[pos++];
}

uint8_t BytePacketBuffer::get()
{
    require_available(pos, 1, len);
    return buff[pos];
}

uint16_t BytePacketBuffer::read_u16()
{
    const uint16_t high = read_u8();
    const uint16_t low = read_u8();
    return static_cast<uint16_t>((high << 8) | low);
}

uint32_t BytePacketBuffer::read_u32()
{
    const uint32_t high = read_u16();
    const uint32_t low = read_u16();

    return (high << 16) | low;
}

void BytePacketBuffer::step(std::size_t steps)
{
    require_available(pos, steps, len);
    pos += steps;
}

void BytePacketBuffer::seek(std::size_t next_pos)
{
    if (next_pos > len)
    {
        throw std::out_of_range("BytePacketBuffer seek out of bounds");
    }
    pos = next_pos;
}

std::string BytePacketBuffer::read_qname()
{
    std::string name;
    std::size_t cursor = pos;
    bool jumped = false;
    std::size_t jumps = 0;

    while (true)
    {
        require_available(cursor, 1, len);

        uint8_t length = buff[cursor];

        if ((length & 0xC0) == 0xC0)
        {
            require_available(cursor, 2, len);

            uint16_t offset =
                ((length & 0x3F) << 8) | buff[cursor + 1];

            if (!jumped)
                pos = cursor + 2;

            cursor = offset;
            jumped = true;

            if (++jumps > len)
                throw std::runtime_error("DNS compression pointer loop detected");

            continue;
        }

        if (length == 0)
        {
            if (!jumped)
                pos = cursor + 1;

            break;
        }

        if ((length & 0xC0) != 0)
        {
            throw std::runtime_error("Invalid DNS label length or compression tag");
        }

        ++cursor;

        require_available(cursor, length, len);

        if (!name.empty())
            name += '.';

        for (std::size_t i = 0; i < length; ++i)
            name += static_cast<char>(buff[cursor + i]);

        cursor += length;

        if (name.size() + 1 > 255)
        {
            throw std::runtime_error("DNS name exceeds the 255-byte limit");
        }

        if (!jumped)
            pos = cursor;
    }

    if (name.empty())
    {
        return ".";
    }

    return name;
}

std::vector<uint8_t> BytePacketBuffer::read_bytes(std::size_t count)
{
    require_available(pos, count, len);
    std::vector<uint8_t> bytes(buff.begin() + static_cast<std::ptrdiff_t>(pos),
                               buff.begin() + static_cast<std::ptrdiff_t>(pos + count));
    pos += count;
    return bytes;
}

std::size_t BytePacketBuffer::position() const noexcept
{
    return pos;
}

std::size_t BytePacketBuffer::remaining() const noexcept
{
    return len - pos;
}

void BytePacketBuffer::write_u8(uint8_t byte)
{
    if (pos >= buff.size())
    {
        throw std::length_error("DNS packet exceeds buffer capacity");
    }

    buff[pos++] = byte;
    len = std::max(len, pos);
}

void BytePacketBuffer::write_u16(uint16_t value)
{
    write_u8(value >> 8);
    write_u8(value & 0xFF);
}

void BytePacketBuffer::write_u32(uint32_t value)
{
    write_u16(value >> 16);
    write_u16(value & 0xFFFF);
}

void BytePacketBuffer::write_qname(const std::string &domain)
{
    if (domain.empty() || domain == ".")
    {
        write_u8(0);
        return;
    }

    std::size_t label_start = 0;
    while (label_start < domain.size())
    {
        const std::size_t label_end = domain.find('.', label_start);
        const std::size_t label_length =
            (label_end == std::string::npos ? domain.size() : label_end) - label_start;

        if (label_length == 0 || label_length > 63)
        {
            throw std::invalid_argument("DNS labels must contain 1 to 63 bytes");
        }

        write_u8(static_cast<uint8_t>(label_length));
        for (std::size_t i = label_start; i < label_start + label_length; ++i)
        {
            write_u8(static_cast<uint8_t>(domain[i]));
        }

        if (label_end == std::string::npos)
        {
            break;
        }

        label_start = label_end + 1;
    }

    write_u8(0);
}

std::array<uint8_t, 512>& BytePacketBuffer::get_buffer() noexcept
{
    return buff;
}

const std::array<uint8_t, 512>& BytePacketBuffer::get_buffer() const noexcept
{
    return buff;
}

void BytePacketBuffer::set_length(std::size_t length)
{
    if (length > buff.size())
    {
        throw std::length_error("DNS packet exceeds buffer capacity");
    }

    len = length;
    pos = 0;
}
