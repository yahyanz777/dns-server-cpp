#include "IPv4Address.hpp"
#include <deque>

enum class ServerStatus{
    UNKNOWN=0,
    SUCCESS,
    FAIL
};

struct QueryResult
{
    double latency_ms;
    bool success;
};


struct RootServer{

    IPv4Address address;
    ServerStatus status;

    std::deque<QueryResult> recent_results;
    uint32_t consecutive_failures;


    size_t unpersisted_results = 0;

    size_t recent_successes = 0;
    double recent_total_latency = 0.0;
    
    
    size_t total_samples;
    size_t total_successes;
    double total_average_latency;

};

class RootServerManager{

    

};