#pragma once

#include <optional>
#include "DnsHeader.hpp"
#include <vector>
#include "DnsRecord.hpp"
#include "DnsQuestion.hpp"
#include "BytePacketBuffer.hpp"

struct EdnsInfo
{
    bool edns_present = false;
    uint16_t max_payload_size = 512;
    bool dnssec_ok = false;
    uint8_t version = 0;
};

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

    static DnsPacket read(BytePacketBuffer &buffer);
    void print() const;
    void write(BytePacketBuffer &buffer);
    void set_question(const DnsQuestion &new_question);
    DnsHeader &get_header() { return header; }
    const DnsHeader &get_header() const { return header; }
    DnsQuestion *get_question() { return question ? &*question : nullptr; }
    const DnsQuestion *get_question() const { return question ? &*question : nullptr; }

    const std::vector<DnsRecord> &get_answers() const { return answers; }
    const std::vector<DnsRecord> &get_authorities() const { return authorities; }
    const std::vector<DnsRecord> &get_additionals() const { return additionals; }

    std::vector<DnsRecord> &get_answers() { return answers; }
    std::vector<DnsRecord> &get_authorities() { return authorities; }
    std::vector<DnsRecord> &get_additionals() { return additionals; }
    std::optional<EdnsInfo> get_edns_info() const;

    void add_answer(const DnsRecord &record) { answers.push_back(record); }
    void add_authority(const DnsRecord &record) { authorities.push_back(record); }
    void add_additional(const DnsRecord &record) { additionals.push_back(record); }
    void set_answers(std::vector<DnsRecord> a) { answers = std::move(a); }
    void set_authorities(std::vector<DnsRecord> auth) { authorities = std::move(auth); }
    void set_additionals(std::vector<DnsRecord> add) { additionals = std::move(add); }
    void create_additional_opt_record(uint16_t udp_payload_size = 1232, uint8_t extended_rcode = 0, uint8_t version = 0, bool dnssec_ok = true)
    {

        uint32_t ttl = (static_cast<uint32_t>(extended_rcode) << 24) |
                       (static_cast<uint32_t>(version) << 16) |
                       (dnssec_ok ? 0x8000u : 0u);

        OPTRecord opt_record{udp_payload_size, extended_rcode, version, dnssec_ok};

        DnsRecord record{"", QuestionType::OPT, udp_payload_size, ttl, 0, std::move(opt_record)};

        additionals.push_back(std::move(record));
    }
};
