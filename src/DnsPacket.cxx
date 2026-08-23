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