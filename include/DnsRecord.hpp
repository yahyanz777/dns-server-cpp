#pragma once
#include <string>
#include <cstdint>
#include <variant>
#include <optional>
#include <vector>
#include "IPAddress.hpp"
#include "QuestionType.hpp"

class BytePacketBuffer;

struct ARecord
{
    IPv4Address address;
};

struct AAAARecord
{
    IPv6Address address;
};

struct CNAMERecord
{
    std::string canonical_name;
};

struct MXRecord
{
    uint16_t preference;
    std::string exchange;
};

struct NSRecord
{
    std::string name_server;
};

struct SOARecord
{
    std::string primary_name_server;
    std::string responsible_authority_mailbox;
    uint32_t serial_number;
    uint32_t refresh_interval;
    uint32_t retry_interval;
    uint32_t expire_limit;
    uint32_t minimum_ttl;
};

struct OPTRecord
{

    uint16_t udp_payload_size = 1232;
    uint8_t extended_rcode = 0;
    uint8_t version = 0;
    bool dnssec_ok = false;
    std::vector<uint8_t> options_raw;
};

struct UnknownRecord
{
    std::vector<uint8_t> data;
};

using DnsRecordData = std::variant<ARecord, AAAARecord, CNAMERecord, MXRecord, NSRecord, SOARecord, OPTRecord, UnknownRecord>;

class DnsRecord
{
    std::string name{};
    QuestionType type{QuestionType::A};
    uint16_t class_{1};
    uint32_t ttl{0};
    uint16_t rdlength{0};
    DnsRecordData data{UnknownRecord{}};

public:
    DnsRecord() = default;
    DnsRecord(std::string n, QuestionType t, uint16_t c, uint32_t ttl,
              uint16_t rdlength, DnsRecordData d);
    static DnsRecord read(BytePacketBuffer &buffer);
    void printData() const;
    void print() const;
    void write(BytePacketBuffer &buffer) const;
    void writeData(BytePacketBuffer &buffer) const;

    const std::string &get_name() const { return name; }
    QuestionType get_type() const { return type; }
    uint16_t get_class() const { return class_; }
    uint32_t get_ttl() const { return ttl; }
    uint16_t get_rdlength() const { return rdlength; }
    const DnsRecordData &get_data() const { return data; }

    const ARecord *get_a_record() const { return std::get_if<ARecord>(&data); }
    const AAAARecord *get_aaaa_record() const { return std::get_if<AAAARecord>(&data); }
    const CNAMERecord *get_cname_record() const { return std::get_if<CNAMERecord>(&data); }
    const MXRecord *get_mx_record() const { return std::get_if<MXRecord>(&data); }
    const NSRecord *get_ns_record() const { return std::get_if<NSRecord>(&data); }
    const SOARecord *get_soa_record() const { return std::get_if<SOARecord>(&data); }
    const OPTRecord *get_opt_record() const { return std::get_if<OPTRecord>(&data); }

    const UnknownRecord *get_unknown_record() const { return std::get_if<UnknownRecord>(&data); }

    std::optional<IPAddress> get_ip_address() const
    {
        if (const auto *record = std::get_if<ARecord>(&data))
        {
            return record->address;
        }
        if (const auto *record = std::get_if<AAAARecord>(&data))
        {
            return record->address;
        }
        return std::nullopt;
    }
};
