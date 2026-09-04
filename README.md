# DNS Server

A DNS server I built from scratch in C++20. No libraries — just raw sockets and parsing packets by hand.

The goal was to understand how DNS actually works: parsing wire format, following delegations from root servers, handling caching.

## Features

- **Packet Parsing**: Custom buffer for reading/writing DNS packets. Handles compression pointers and doesn't crash on malformed input.
- **DNS Resolution**: Recursively resolves domains by asking root servers, then TLD servers, then the actual nameserver. Follows CNAME chains (max 10 hops).
- **Caching**: Thread-safe cache with TTL. Also caches negative responses (NXDOMAIN) so we don't spam upstream.
- **IPv4/IPv6**: Dual-stack UDP server using `poll()`.
- **Record Types**: Supports A, AAAA, CNAME, MX, NS, SOA, OPT.
- **Tests**: 52 test cases covering the basics.

---

## How It Works

Client sends a query → Server checks cache → If not cached, recursively asks root servers → Gets the answer → Caches it → Sends back to client.

---

## Quick Start

```bash
# Build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure

# Start the server
./build/dns_main
```

Test it with `dig`:
```bash
dig @127.0.0.1 -p 2053 google.com A
dig @127.0.0.1 -p 2053 google.com AAAA
```

## Files

- `include/` - Header files (BytePacketBuffer, DnsResolver, DnsCache, DnsServer, etc.)
- `src/` - Implementation
- `tests/` - 52 test cases
- `config/root_servers.csv` - Root server hints

---

## Future Work

- **TCP Fallback**: Handle responses that are too big for UDP (RFC 7766). Right now everything goes over UDP.
- **Thread Pool**: Offload DNS resolution to worker threads so the main event loop doesn't block.
- **DNSSEC**: Verify chain of trust with RRSIG and DNSKEY records. Currently ignores these.
- **Metrics**: Track cache hit rate, query latency, error counts.
- **Recursive Protection**: Add rate limiting to prevent being used as an amplifier in DDoS attacks.
