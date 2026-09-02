#include "DnsServer.hpp"

int main()
{
    DnsServer server(53);
    server.start();
    return 0;
}