#pragma once

#include "IPAddress.hpp"
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

class DnsPacket;

using Clock = std::chrono::steady_clock;

constexpr int UNKNOWN_RANGE = 10;
constexpr int SLOWBAND_RANGE = 20;

enum class ServerStatus
{
    UNKNOWN,
    SUCCESS,
    FAIL
};

enum class SelectionCategory
{
    UNKNOWN,
    SLOW_BAND,
    FAST_BAND
};

struct RootServer
{
    IPAddress address;
    ServerStatus status{ServerStatus::UNKNOWN};
    uint32_t consecutive_failures{};
    std::size_t srtt_ms{};

    explicit RootServer(IPAddress addr) : address(std::move(addr)) {}
    void update_srtt(std::size_t measured_rtt_ms);
};

class RootServerManager
{
public:
    RootServerManager();
    ~RootServerManager();

    RootServerManager(const RootServerManager&) = delete;
    RootServerManager& operator=(const RootServerManager&) = delete;

    SelectionCategory SelectCategory();
    
    // Sends a complete DNS query directly to a configured root server.  The
    // returned packet is the root server's response (normally an NS referral
    // for the queried top-level domain).
    DnsPacket AskRootServer(const DnsPacket& question_packet);
    void StartProbing();

private:
    std::vector<RootServer> servers;
    std::mutex mtx;
    std::jthread probing_thread;
    std::condition_variable_any cv;

    SelectionCategory _select_category() const;
    void ProbeLoop(std::stop_token stop_token);
    void ProbeFailedServers();
    std::size_t GetLeastSRTT() const;
    void GetCandidates(SelectionCategory category, std::size_t least_srtt,
                       std::vector<RootServer*>& candidates);
};
