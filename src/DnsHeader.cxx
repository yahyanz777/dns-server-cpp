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
