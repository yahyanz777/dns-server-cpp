#pragma once
#include <cstdint>
#include <result_code.hpp>
#include <BytePacketBuffer.hpp>
class DnsHeader
{
public:
    DnsHeader() = default;
    DnsHeader(uint16_t id, uint16_t flags, uint16_t qdcount,
              uint16_t ancount, uint16_t nscount, uint16_t arcount)
        : ID{id}, FLAGS{flags}, QDCOUNT{qdcount}, ANCOUNT{ancount},
          NSCOUNT{nscount}, ARCOUNT{arcount} {}

    uint16_t ID{};
    uint16_t FLAGS{};
    uint16_t QDCOUNT{};
    uint16_t ANCOUNT{};
    uint16_t NSCOUNT{};
    uint16_t ARCOUNT{};

    static DnsHeader read(BytePacketBuffer &buffer);
    void write(BytePacketBuffer& buffer) const;

    bool is_response() const;
    bool is_authoritative() const;
    bool is_truncated() const;
    bool recursion_desired() const;
    bool recursion_available() const;
    uint16_t get_QDCOUNT() const;
    uint16_t get_ACOUNT() const;
    uint16_t get_NSCOUNT() const;
    uint16_t get_ARCOUNT() const;

    void set_QDCOUNT(uint16_t count) { QDCOUNT = count; }
    void set_ACOUNT(uint16_t count) { ANCOUNT = count; }
    void set_NSCOUNT(uint16_t count) { NSCOUNT = count; }
    void set_ARCOUNT(uint16_t count) { ARCOUNT = count; }
    void set_recursion_desired(bool value);

    void print() const;

    ResultCode get_result_code() const
    {
        return result_code_from_num(FLAGS & 0x000F);
    }
};