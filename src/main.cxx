#include "DnsResolver.hpp"

int main()
{
    DnsResolver resolver;

    DnsPacket response =
        resolver.lookup("google.com.", QuestionType::A);

    response.print();
}