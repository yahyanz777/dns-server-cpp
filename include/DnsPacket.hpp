#pragma once 

#include "DnsHeader.hpp"
#include <vector>
#include "DnsRecord.hpp"
#include "DnsQuestion.hpp"
#include "BytePacketBuffer.hpp"

class DnsPacket
{
    DnsHeader header;
    std::vector<DnsQuestion> questions;
    std::vector<DnsRecord> answers;
    std::vector<DnsRecord> authorities;
    std::vector<DnsRecord> additionals;

public:
    DnsPacket() = default;

    DnsPacket(DnsHeader h, std::vector<DnsQuestion> q, std::vector<DnsRecord> a,
              std::vector<DnsRecord> auth, std::vector<DnsRecord> add)
        : header{h}, questions{std::move(q)}, answers{std::move(a)},
          authorities{std::move(auth)}, additionals{std::move(add)} {}

    static DnsPacket read(BytePacketBuffer& buffer);
    void print() const;
};