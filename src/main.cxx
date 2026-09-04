#include "DnsServer.hpp"
#include <iostream>

int main()
{
    constexpr int port = 2053;
    std::cout << "====================================================\n";
    std::cout << "  Custom C++ Recursive DNS Server\n";
    std::cout << "  Listening on 0.0.0.0:" << port << " & [::]:" << port << " (UDP)\n";
    std::cout << "  Test with: dig @127.0.0.1 -p " << port << " google.com A\n";
    std::cout << "====================================================\n" << std::endl;

    DnsServer server(port);
    server.start();
    return 0;
}