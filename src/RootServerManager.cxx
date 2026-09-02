#include "RootServerManager.hpp"

#include "CSVReader.hpp"
#include "DnsPacket.hpp"
#include "SocketAddress.hpp"

#include <algorithm>
#include <limits>
#include <poll.h>
#include <random>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

void RootServer::update_srtt(std::size_t measured_rtt_ms)
{
    if (srtt_ms == 0)
    {
        srtt_ms = measured_rtt_ms;
        return;
    }

    srtt_ms = (7 * srtt_ms + measured_rtt_ms) / 8;
}

RootServerManager::RootServerManager()
{
    CSVReader csv_reader(ROOT_SERVERS_CONFIG_PATH);
    std::vector<std::string> row;

    if (!csv_reader.readRow(row))
    {
        throw std::runtime_error("Root server configuration is empty");
    }

    while (csv_reader.readRow(row))
    {
        if (row.size() < 2 || (row[1].empty() && (row.size() < 3 || row[2].empty())))
        {
            throw std::runtime_error("Invalid root server configuration row");
        }
        if (!row[1].empty())
        {
            servers.emplace_back(IPv4Address(row[1]));
        }
        if (row.size() >= 3 && !row[2].empty())
        {
            servers.emplace_back(IPv6Address(row[2]));
        }
    }

    if (servers.empty())
    {
        throw std::runtime_error("Root server configuration contains no servers");
    }
}

RootServerManager::~RootServerManager()
{
    probing_thread.request_stop();
    cv.notify_all();
}

SelectionCategory RootServerManager::SelectCategory()
{
    std::lock_guard lock(mtx);
    return _select_category();
}

SelectionCategory RootServerManager::_select_category() const
{
    const bool has_unknown = std::any_of(servers.begin(), servers.end(), [](const RootServer &server)
                                         { return server.status == ServerStatus::UNKNOWN; });
    const bool has_success = std::any_of(servers.begin(), servers.end(), [](const RootServer &server)
                                         { return server.status == ServerStatus::SUCCESS; });

    if (!has_success && has_unknown)
    {
        return SelectionCategory::UNKNOWN;
    }

    static thread_local std::mt19937 generator(std::random_device{}());
    std::uniform_int_distribution<int> distribution(1, 100);
    const int roll = distribution(generator);

    if (has_unknown && roll <= UNKNOWN_RANGE)
    {
        return SelectionCategory::UNKNOWN;
    }
    return roll <= SLOWBAND_RANGE ? SelectionCategory::SLOW_BAND : SelectionCategory::FAST_BAND;
}

DnsPacket RootServerManager::AskRootServer(const DnsPacket& question_packet)
{
    RootServer* selected_server = nullptr;
    IPAddress selected_address;
    {
        std::lock_guard lock(mtx);
        const SelectionCategory category = _select_category();
        const std::size_t least_srtt = GetLeastSRTT();
        std::vector<RootServer *> candidates;
        GetCandidates(category, least_srtt, candidates);

        // A category may be empty when all known servers are in a different
        // latency band.  In that case, any non-failed root is preferable to
        // failing the lookup without making a network request.
        if (candidates.empty())
        {
            for (auto& server : servers)
            {
                if (server.status != ServerStatus::FAIL)
                {
                    candidates.push_back(&server);
                }
            }
        }
        if (candidates.empty())
        {
            return DnsPacket();
        }

        static thread_local std::mt19937 generator(std::random_device{}());
        std::uniform_int_distribution<std::size_t> distribution(0, candidates.size() - 1);
        selected_server = candidates[distribution(generator)];
        selected_address = selected_server->address;
    }

    const SocketAddress server_addr = SocketAddress::from_ip(selected_address, 53);
    int fd = socket(server_addr.family(), SOCK_DGRAM, 0);
    if (fd < 0)
    {
        return DnsPacket();
    }

    DnsPacket request = question_packet;
    request.get_header().set_recursion_desired(false);
    BytePacketBuffer request_buffer;
    try
    {
        request.write(request_buffer);
    }
    catch (const std::exception&)
    {
        close(fd);
        return DnsPacket();
    }

    using Clock = std::chrono::steady_clock;

    auto start_time = Clock::now();
    const ssize_t sent = sendto(fd, request_buffer.get_buffer().data(), request_buffer.get_length(), 0,
                                server_addr.sockaddr_ptr(), server_addr.length());
    if (sent != static_cast<ssize_t>(request_buffer.get_length()))
    {
        close(fd);
        return DnsPacket();
    }

    pollfd poll_descriptor{fd, POLLIN, 0};
    if (poll(&poll_descriptor, 1, 1000) <= 0 || !(poll_descriptor.revents & POLLIN))
    {
        close(fd);
        std::lock_guard lock(mtx);
        ++selected_server->consecutive_failures;
        selected_server->status = ServerStatus::FAIL;
        return DnsPacket();
    }

    BytePacketBuffer response_buffer;
    SocketAddress response_addr;
    socklen_t response_addr_len = response_addr.length();
    const ssize_t received = recvfrom(fd, response_buffer.get_buffer().data(), response_buffer.get_buffer().size(), 0,
                                      response_addr.sockaddr_ptr(), &response_addr_len);
    close(fd);
    if (received < 0)
    {
        return DnsPacket();
    }
    response_addr.set_length(response_addr_len);
    if (!(response_addr == server_addr))
    {
        return DnsPacket();
    }

    response_buffer.set_length(static_cast<std::size_t>(received));
    try
    {
        DnsPacket response = DnsPacket::read(response_buffer);
        if (!response.get_header().is_response() || response.get_header().ID != request.get_header().ID)
        {
            return DnsPacket();
        }

        const auto rtt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start_time).count();
        std::lock_guard lock(mtx);
        selected_server->update_srtt(static_cast<std::size_t>(rtt_ms));
        selected_server->status = ServerStatus::SUCCESS;
        selected_server->consecutive_failures = 0;
        return response;
    }
    catch (const std::exception&)
    {
        return DnsPacket();
    }
}

void RootServerManager::StartProbing()
{
    std::lock_guard lock(mtx);
    if (!probing_thread.joinable())
    {
        probing_thread = std::jthread([this](std::stop_token stop_token)
                                      { ProbeLoop(stop_token); });
    }
}

void RootServerManager::ProbeLoop(std::stop_token stop_token)
{
    std::unique_lock lock(mtx);
    while (!stop_token.stop_requested())
    {
        cv.wait_for(lock, stop_token, std::chrono::seconds(5), []
                    { return false; });
        if (stop_token.stop_requested())
        {
            break;
        }

        lock.unlock();
        ProbeFailedServers();
        lock.lock();
    }
}

void RootServerManager::ProbeFailedServers()
{
    static thread_local std::mt19937 generator(std::random_device{}());
    std::uniform_int_distribution<uint16_t> id_distribution(0, std::numeric_limits<uint16_t>::max());

    for (auto &server : servers)
    {
        IPAddress address;
        {
            std::lock_guard lock(mtx);
            if (server.status != ServerStatus::FAIL)
            {
                continue;
            }
            address = server.address;
        }

        const SocketAddress destination = SocketAddress::from_ip(address, 53);
        const int probe_socket = socket(destination.family(), SOCK_DGRAM, 0);
        if (probe_socket < 0)
        {
            continue;
        }

        DnsPacket packet;
        const uint16_t id = id_distribution(generator);
        packet.get_header().ID = id;
        packet.get_header().set_recursion_desired(false);
        packet.set_question(DnsQuestion(".", QuestionType::SOA));

        BytePacketBuffer request_buffer;
        packet.write(request_buffer);
        const auto start_time = Clock::now();
        if (sendto(probe_socket, request_buffer.get_buffer().data(), request_buffer.get_length(), 0,
                   destination.sockaddr_ptr(), destination.length()) < 0)
        {
            close(probe_socket);
            continue;
        }

        pollfd poll_descriptor{probe_socket, POLLIN, 0};
        if (poll(&poll_descriptor, 1, 1000) <= 0 || !(poll_descriptor.revents & POLLIN))
        {
            close(probe_socket);
            continue;
        }

        BytePacketBuffer response_buffer;
        SocketAddress responder;
        socklen_t responder_length = responder.length();
        const ssize_t received = recvfrom(probe_socket, response_buffer.get_buffer().data(),
                                          response_buffer.get_buffer().size(), 0,
                                          responder.sockaddr_ptr(), &responder_length);
        if (received < 0)
        {
            close(probe_socket);
            continue;
        }
        close(probe_socket);
        responder.set_length(responder_length);
        if (!(responder == destination))
        {
            continue;
        }
        response_buffer.set_length(static_cast<std::size_t>(received));

        try
        {
            const DnsPacket response = DnsPacket::read(response_buffer);
            if (response.get_header().ID != id || !response.get_header().is_response())
            {
                continue;
            }
        }
        catch (const std::exception &)
        {
            continue;
        }

        const std::size_t rtt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start_time).count();
        std::lock_guard lock(mtx);
        server.update_srtt(rtt_ms);
        server.status = ServerStatus::SUCCESS;
        server.consecutive_failures = 0;
    }

}

std::size_t RootServerManager::GetLeastSRTT() const
{
    std::size_t least_srtt = std::numeric_limits<std::size_t>::max();
    for (const auto &server : servers)
    {
        if (server.status == ServerStatus::SUCCESS)
        {
            least_srtt = std::min(least_srtt, server.srtt_ms);
        }
    }
    return least_srtt;
}

void RootServerManager::GetCandidates(SelectionCategory category, std::size_t least_srtt,
                                      std::vector<RootServer *> &candidates)
{
    const std::size_t fast_band = least_srtt == std::numeric_limits<std::size_t>::max()
                                      ? 0
                                      : least_srtt + least_srtt / 4;
    for (auto &server : servers)
    {
        if (category == SelectionCategory::UNKNOWN && server.status == ServerStatus::UNKNOWN)
        {
            candidates.push_back(&server);
        }
        else if (category == SelectionCategory::FAST_BAND && server.status == ServerStatus::SUCCESS &&
                 server.srtt_ms <= fast_band)
        {
            candidates.push_back(&server);
        }
        else if (category == SelectionCategory::SLOW_BAND && server.status == ServerStatus::SUCCESS &&
                 server.srtt_ms > fast_band)
        {
            candidates.push_back(&server);
        }
    }
}
