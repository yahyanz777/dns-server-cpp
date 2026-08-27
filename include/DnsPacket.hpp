#pragma once 

#include <optional>
#include "DnsHeader.hpp"
#include <vector>
#include "DnsRecord.hpp"
#include "DnsQuestion.hpp"
#include "BytePacketBuffer.hpp"

class DnsPacket
{
    DnsHeader header;
    std::optional<DnsQuestion> question;
    std::vector<DnsRecord> answers;
    std::vector<DnsRecord> authorities;
    std::vector<DnsRecord> additionals;

public:
    DnsPacket() = default;

    DnsPacket(DnsHeader h, std::optional<DnsQuestion> q, std::vector<DnsRecord> a,
              std::vector<DnsRecord> auth, std::vector<DnsRecord> add)
        : header{h}, question{std::move(q)}, answers{std::move(a)},
          authorities{std::move(auth)}, additionals{std::move(add)} {}

    static DnsPacket read(BytePacketBuffer& buffer);
    void print() const;
    void write(BytePacketBuffer& buffer);
    void set_question(const DnsQuestion& new_question);
    DnsHeader& get_header(){return header;}
    const DnsHeader& get_header() const { return header; }
    DnsQuestion* get_question() { return question ? &*question : nullptr; }
    const DnsQuestion* get_question() const { return question ? &*question : nullptr; }
};
