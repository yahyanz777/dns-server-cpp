#pragma once
#include <string>
#include <cstdint>
#include <QuestionType.hpp>

class BytePacketBuffer;

class DnsQuestion {

    std::string name;
    QuestionType type;
    uint16_t class_;

public:
    DnsQuestion(const std::string& n, QuestionType t, uint16_t c =1);
    DnsQuestion(const DnsQuestion&) = default;
    const std::string& getName() const;
    QuestionType getType() const;
    uint16_t getClass() const;
    static DnsQuestion read(BytePacketBuffer& buffer);
    void write(BytePacketBuffer& buffer) const;
    void print() const;
};