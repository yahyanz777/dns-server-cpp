#pragma once
#include <string>
#include <cstdint>
#include <variant>
#include <vector>
#include "IPv4Address.hpp"
#include "IPv6Address.hpp"


class BytePacketBuffer;
enum class QuestionType;

struct ARecord {
    IPv4Address address;
};

struct AAAARecord {
    IPv6Address address;
};

struct CNAMERecord {
    std::string canonical_name;
};

struct MXRecord {
    uint16_t preference;
    std::string exchange;
};

struct NSRecord {
    std::string name_server;
};

struct UnknownRecord {
    std::vector<uint8_t> data;
};

using DnsRecordData = std::variant<ARecord, AAAARecord, CNAMERecord, MXRecord, NSRecord, UnknownRecord>;

class DnsRecord {

    std::string name;
    QuestionType type;
    uint16_t class_;
    uint32_t ttl;
    uint16_t rdlength;
    DnsRecordData data;

public:
    DnsRecord(std::string n, QuestionType t, uint16_t c, uint32_t ttl,
              uint16_t rdlength, DnsRecordData d);
    static DnsRecord read(BytePacketBuffer& buffer);
    void printData()const;
    void print() const;
    void write(BytePacketBuffer& buffer) const;
    void writeData(BytePacketBuffer& buffer) const;

};
