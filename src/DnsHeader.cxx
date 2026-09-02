#include "DnsHeader.hpp"
#include <iostream>

DnsHeader DnsHeader::read(BytePacketBuffer& buff){
    uint16_t ID = buff.read_u16();
    uint16_t FLAGS = buff.read_u16();
    uint16_t QDCOUNT = buff.read_u16();
    uint16_t ANCOUNT = buff.read_u16();
    uint16_t NSCOUNT = buff.read_u16();
    uint16_t ARCOUNT = buff.read_u16();
    return DnsHeader{ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT};
}

bool DnsHeader::is_authoritative() const
{
    return (FLAGS & 0x0400) != 0;
}

bool DnsHeader::is_response() const
{
    return (FLAGS & 0x8000) != 0;
}

bool DnsHeader::is_truncated() const
{
    return (FLAGS & 0x0200) != 0;
}

bool DnsHeader::recursion_desired() const
{
    return (FLAGS & 0x0100) != 0;
}

bool DnsHeader::recursion_available() const
{
    return (FLAGS & 0x0080) != 0;
}

uint16_t DnsHeader::get_QDCOUNT()const{
    return QDCOUNT;
}

uint16_t DnsHeader::get_ACOUNT()const{
    return ANCOUNT;
}

uint16_t DnsHeader::get_NSCOUNT()const{
    return NSCOUNT;
}

uint16_t DnsHeader::get_ARCOUNT()const{
    return ARCOUNT;
}

void DnsHeader::set_recursion_desired(bool value)
{
    if (value)
        FLAGS |= (1 << 8);
    else
        FLAGS &= ~(1 << 8);
}

void DnsHeader::set_response(bool value)
{
    if (value)
        FLAGS |= (1 << 15);
    else
        FLAGS &= ~(1 << 15);
}

void DnsHeader::set_recursion_available(bool value)
{
    if (value)
        FLAGS |= (1 << 7);
    else
        FLAGS &= ~(1 << 7);
}

void DnsHeader::set_result_code(ResultCode rcode)
{
    FLAGS = (FLAGS & 0xFFF0) | (static_cast<uint16_t>(rcode) & 0x000F);
}

void DnsHeader::print() const
{
    std::cout << "ID: " << ID << std::endl;
    std::cout << "Response: " << is_response() << std::endl;
    std::cout << "Authoritative: " << is_authoritative() << std::endl;
    std::cout << "Truncated: " << is_truncated() << std::endl;
    std::cout << "Recursion Desired: " << recursion_desired() << std::endl;
    std::cout << "Recursion Available: " << recursion_available() << std::endl;
    std::cout << "QDCOUNT: " << QDCOUNT << std::endl;
    std::cout << "ANCOUNT: " << ANCOUNT << std::endl;
    std::cout << "NSCOUNT: " << NSCOUNT << std::endl;
    std::cout << "ARCOUNT: " << ARCOUNT << std::endl;
}

void DnsHeader::write(BytePacketBuffer& buffer) const
{
    buffer.write_u16(ID);
    buffer.write_u16(FLAGS);
    buffer.write_u16(QDCOUNT);
    buffer.write_u16(ANCOUNT);
    buffer.write_u16(NSCOUNT);
    buffer.write_u16(ARCOUNT);
}