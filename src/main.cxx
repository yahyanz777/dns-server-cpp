#include "DnsServer.hpp"

int main()
{
    DnsServer server(2053);
    server.start();
    return 0;
}