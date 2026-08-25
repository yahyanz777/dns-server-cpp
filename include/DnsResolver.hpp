#pragma once

#include <cstdint>
#include <netinet/in.h>
#include <DnsPacket.hpp>

class DnsResolver
{
private:
    int server_socket;
    sockaddr_in server_addr;

public:
    DnsResolver();

    ~DnsResolver();

    DnsResolver(const DnsResolver&) = delete;
    DnsResolver& operator=(const DnsResolver&) = delete;
    DnsPacket lookup(const std::string& domain, QuestionType type);

};