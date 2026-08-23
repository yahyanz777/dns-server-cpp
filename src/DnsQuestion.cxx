#include <BytePacketBuffer.hpp>
#include <DnsQuestion.hpp>

DnsQuestion::DnsQuestion(std::string&& n, QuestionType t, uint16_t c)
    : name(std::move(n)), type(t), class_(c) {}


const std::string& DnsQuestion::getName() const {
    return name;
}    

QuestionType DnsQuestion::getType() const {
    return type;
}

uint16_t DnsQuestion::getClass() const {
    return class_;
}

DnsQuestion DnsQuestion::read(BytePacketBuffer& buffer) {

    std::string name = buffer.read_qname();
    QuestionType type = static_cast<QuestionType>(buffer.read_u16());
    uint16_t class_ = buffer.read_u16();

    return DnsQuestion(std::move(name), type, class_);
}

void DnsQuestion::print() const {
    std::cout << "Name: " << name << ", Type: " << static_cast<uint16_t>(type) << ", Class: " << class_ << std::endl;
}
