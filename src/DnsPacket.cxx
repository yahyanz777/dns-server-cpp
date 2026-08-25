#include "DnsPacket.hpp"



DnsPacket  DnsPacket::read(BytePacketBuffer& buffer){
    DnsHeader header = DnsHeader::read(buffer);
    std::vector<DnsQuestion> questions; 

    for(uint16_t i = 0; i<header.get_QDCOUNT(); i++){
        questions.push_back(DnsQuestion::read(buffer));
    }
    std::vector<DnsRecord> answers;

    for(uint16_t i =0; i<header.get_ACOUNT(); i++){
        answers.push_back(DnsRecord::read(buffer));
    }

    std::vector<DnsRecord> authorities;
    for(uint16_t i =0; i<header.get_NSCOUNT(); i++){
        authorities.push_back(DnsRecord::read(buffer));
    }

    std::vector<DnsRecord> additionals;
    for(uint16_t i =0; i<header.get_ARCOUNT(); i++){
        additionals.push_back(DnsRecord::read(buffer));
    }

    return DnsPacket(header, std::move(questions), std::move(answers), std::move(authorities), std::move(additionals));
    
}

void DnsPacket::print() const {
    std::cout << "DNS Packet:" << std::endl;
    header.print();
    std::cout << "Questions:" << std::endl;
    for (const auto& question : questions) {
        question.print();
    }
    std::cout << "Answers:" << std::endl;
    for (const auto& answer : answers) {
        answer.print();
    }
    std::cout << "Authorities:" << std::endl;
    for (const auto& authority : authorities) {
        authority.print();
    }
    std::cout << "Additionals:" << std::endl;
    for (const auto& additional : additionals) {
        additional.print();
    }
}

void DnsPacket::add_question(const DnsQuestion& question)
{
    questions.push_back(question);
}

DnsHeader& DnsPacket::get_header()
{
    return header;
}

void DnsPacket::write(BytePacketBuffer& buffer){

    uint16_t QDCOUNT = static_cast<uint16_t>(questions.size());
    uint16_t ANCOUNT = static_cast<uint16_t>(answers.size());
    uint16_t NSCOUNT = static_cast<uint16_t>(authorities.size());
    uint16_t ARCOUNT = static_cast<uint16_t>(additionals.size());

    header.set_QDCOUNT(QDCOUNT);
    header.set_ACOUNT(ANCOUNT);
    header.set_NSCOUNT(NSCOUNT);
    header.set_ARCOUNT(ARCOUNT);

    header.write(buffer);

    for (const auto& question : questions) {
        question.write(buffer);
    }
    for (const auto& answer : answers) {
        answer.write(buffer);
    }
    for (const auto& authority : authorities) {
        authority.write(buffer);
    }
    for (const auto& additional : additionals) {
        additional.write(buffer);
    }

}