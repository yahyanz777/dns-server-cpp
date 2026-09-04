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
    const std::string& get_name() const;
    QuestionType get_type() const;
    uint16_t get_class() const;

    // Compatibility aliases
    const std::string& getName() const { return get_name(); }
    QuestionType getType() const { return get_type(); }
    uint16_t getClass() const { return get_class(); }

    static DnsQuestion read(BytePacketBuffer& buffer);
    void write(BytePacketBuffer& buffer) const;
    void print() const;
};