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
    DnsHeader& get_header() { return header; }
    const DnsHeader& get_header() const { return header; }
    DnsQuestion* get_question() { return question ? &*question : nullptr; }
    const DnsQuestion* get_question() const { return question ? &*question : nullptr; }

    const std::vector<DnsRecord>& get_answers() const { return answers; }
    const std::vector<DnsRecord>& get_authorities() const { return authorities; }
    const std::vector<DnsRecord>& get_additionals() const { return additionals; }

    std::vector<DnsRecord>& get_answers() { return answers; }
    std::vector<DnsRecord>& get_authorities() { return authorities; }
    std::vector<DnsRecord>& get_additionals() { return additionals; }

    void add_answer(const DnsRecord& record) { answers.push_back(record); }
    void add_authority(const DnsRecord& record) { authorities.push_back(record); }
    void add_additional(const DnsRecord& record) { additionals.push_back(record); }
    void set_answers(std::vector<DnsRecord> a) { answers = std::move(a); }
};
