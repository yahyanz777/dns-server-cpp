#include "DnsResolver.hpp"

class DnsServer{

int server_socket;
short port;
DnsResolver resolver{}; 
public:
    DnsServer(int port);

    ~DnsServer();

    void start();

    DnsPacket handle_query(DnsQuestion& req);

};