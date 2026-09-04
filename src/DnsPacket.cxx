#include "DnsPacket.hpp"

#include <stdexcept>

DnsPacket DnsPacket::read(BytePacketBuffer& buffer){
    DnsHeader header = DnsHeader::read(buffer);

    if (header.get_QDCOUNT() > 1) {
        throw std::runtime_error("DNS packets with more than one question are not supported");
    }

    std::optional<DnsQuestion> question;
    if (header.get_QDCOUNT() == 1) {
        question = DnsQuestion::read(buffer);
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

    return DnsPacket(header, std::move(question), std::move(answers), std::move(authorities), std::move(additionals));
    
}

void DnsPacket::print() const {
    std::cout << "DNS Packet:" << std::endl;
    header.print();
    std::cout << "Question:" << std::endl;
    if (question) {
        question->print();
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

void DnsPacket::set_question(const DnsQuestion& new_question)
{
    question = new_question;
}



void DnsPacket::write(BytePacketBuffer& buffer){

    uint16_t QDCOUNT = question ? 1 : 0;
    uint16_t ANCOUNT = static_cast<uint16_t>(answers.size());
    uint16_t NSCOUNT = static_cast<uint16_t>(authorities.size());
    uint16_t ARCOUNT = static_cast<uint16_t>(additionals.size());

    header.set_QDCOUNT(QDCOUNT);
    header.set_ACOUNT(ANCOUNT);
    header.set_NSCOUNT(NSCOUNT);
    header.set_ARCOUNT(ARCOUNT);

    header.write(buffer);

    if (question) {
        question->write(buffer);
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


std::optional<EdnsInfo> DnsPacket::get_edns_info() const {
    for (const auto &record : additionals) {
        if (const auto *opt = record.get_opt_record()) {
            EdnsInfo info;
            info.edns_present = true;
            uint16_t client_size = std::max<uint16_t>(512, opt->udp_payload_size);
            info.max_payload_size = std::min<uint16_t>(client_size, 1232);
            info.dnssec_ok = opt->dnssec_ok;
            info.version = opt->version;
            return info;
        }
    }
    return std::nullopt; // Zero heap allocation, fully type-safe
}


