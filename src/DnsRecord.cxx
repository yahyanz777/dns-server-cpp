#include <BytePacketBuffer.hpp>
#include <DnsRecord.hpp>
#include <QuestionType.hpp>
#include <limits>
#include <stdexcept>

namespace
{
uint16_t qname_wire_length(const std::string& name)
{
    if (name.empty() || name == ".")
    {
        return 1;
    }

    const std::size_t length = name.size() + (name.back() == '.' ? 1 : 2);
    if (length > std::numeric_limits<uint16_t>::max())
    {
        throw std::length_error("DNS name is too large for an RDATA field");
    }
    return static_cast<uint16_t>(length);
}
}

DnsRecord::DnsRecord(
    std::string n,
    QuestionType t,
    uint16_t c,
    uint32_t ttl,
    uint16_t rdlength,
    DnsRecordData d)
    : name(std::move(n)),
      type(t),
      class_(c),
      ttl(ttl),
      rdlength(rdlength),
      data(std::move(d))
{
}

DnsRecord DnsRecord::read(BytePacketBuffer &buffer)
{

    std::string name = buffer.read_qname();
    QuestionType type = static_cast<QuestionType>(buffer.read_u16());
    uint16_t class_ = buffer.read_u16();
    uint32_t ttl = buffer.read_u32();
    uint16_t rdlength = buffer.read_u16();
    if (rdlength > buffer.remaining())
    {
        throw std::out_of_range("DNS record RDATA exceeds the remaining packet");
    }

    const std::size_t rdata_start = buffer.position();
    DnsRecordData data;
    switch (type)
    {
    case QuestionType::A:
    {

        if (rdlength != 4)
            throw std::runtime_error("Invalid A record length");
        
        uint32_t ip = buffer.read_u32();
        IPv4Address address(ip);
        data = ARecord{address};
    }
    break;

    case QuestionType::AAAA:
    {
        if (rdlength != 16)
            throw std::runtime_error("Invalid AAAA record length");
        
        std::array<uint8_t, 16> addr_bytes;
        for (size_t i = 0; i < 16; ++i)
        {
            addr_bytes[i] = buffer.read_u8();
        }
        IPv6Address address(addr_bytes);
        data = AAAARecord{address};
    }
    break;

    case QuestionType::CNAME:
    {
        std::string canonical_name = buffer.read_qname();
        data = CNAMERecord{canonical_name};
    }
    break;

    case QuestionType::MX:
    {
        uint16_t preference = buffer.read_u16();
        std::string exchange = buffer.read_qname();
        data = MXRecord{preference, exchange};
    }
    break;

    case QuestionType::NS:
    {
        std::string name_server = buffer.read_qname();
        data = NSRecord{name_server};
    }
    break;

    case QuestionType::SOA:
    {
        std::string mname = buffer.read_qname();
        std::string rname = buffer.read_qname();
        uint32_t serial = buffer.read_u32();
        uint32_t refresh = buffer.read_u32();
        uint32_t retry = buffer.read_u32();
        uint32_t expire = buffer.read_u32();
        uint32_t minimum = buffer.read_u32();
        data = SOARecord{mname, rname, serial, refresh, retry, expire, minimum};
    }
    break;

    default:
        data = UnknownRecord{buffer.read_bytes(rdlength)};
        break;
    }

    if (buffer.position() - rdata_start != rdlength)
    {
        throw std::runtime_error("DNS record RDATA length does not match its contents");
    }

    return DnsRecord{
        std::move(name),
        type,
        class_,
        ttl,
        rdlength,
        std::move(data)};
}

void DnsRecord::printData() const
{
    std::visit([](const auto &record)
               {
                   using T = std::decay_t<decltype(record)>;
                   if constexpr (std::is_same_v<T, ARecord>)
                   {
                       std::cout << "A Record:" << record.address.to_string();
                   }
                   else if constexpr (std::is_same_v<T, AAAARecord>)
                   {
                       std::cout << "AAAA Record:" << record.address.to_string();
                   }
                   else if constexpr (std::is_same_v<T, CNAMERecord>)
                   {
                       std::cout << "CNAME Record:" << record.canonical_name;
                   }
                   else if constexpr (std::is_same_v<T, MXRecord>)
                   {
                       std::cout << "MX Record: Preference: " << record.preference << ", Exchange: " << record.exchange;
                   }
                   else if constexpr (std::is_same_v<T, NSRecord>)
                   {
                       std::cout << "NS Record:" << record.name_server;
                   }
                   else if constexpr (std::is_same_v<T, SOARecord>)
                   {
                       std::cout << "SOA Record: " << record.primary_name_server
                                 << ", " << record.responsible_authority_mailbox;
                   }
                   else if constexpr (std::is_same_v<T, UnknownRecord>)
                   {
                       std::cout << "Unknown Record: Data size: " << record.data.size();
                   }
               },
               data);
}

void DnsRecord::print() const
{
    std::cout << "Name: " << name << ", Type: " << static_cast<uint16_t>(type) << ", Class: " << class_ << ", TTL: " << ttl << ", RDLength: " << rdlength << ", RData: ";
    printData();
    std::cout << std::endl;
}

void DnsRecord::writeData(BytePacketBuffer &buffer) const
{

    std::visit([&buffer](const auto& record){
        using T = std::decay_t<decltype(record)>;
        if constexpr (std::is_same_v<T,ARecord>){
            buffer.write_u16(4);
            buffer.write_u32(record.address.to_uint32());
        }
        else if constexpr (std::is_same_v<T,AAAARecord>){
            buffer.write_u16(16);
            for (uint8_t c : record.address.bytes()){
                buffer.write_u8(c);
            }
        }
        else if constexpr (std::is_same_v<T,CNAMERecord>){
            buffer.write_u16(qname_wire_length(record.canonical_name));
            buffer.write_qname(record.canonical_name);
        }
        else if constexpr (std::is_same_v<T,MXRecord>){
            buffer.write_u16(static_cast<uint16_t>(2 + qname_wire_length(record.exchange)));
            buffer.write_u16(record.preference);
            buffer.write_qname(record.exchange);
        }
        else if constexpr (std::is_same_v<T,NSRecord>){
            buffer.write_u16(qname_wire_length(record.name_server));
            buffer.write_qname(record.name_server);
        }
        else if constexpr (std::is_same_v<T,SOARecord>){
            const uint32_t total_length = qname_wire_length(record.primary_name_server) +
                                          qname_wire_length(record.responsible_authority_mailbox) + 20;
            if (total_length > std::numeric_limits<uint16_t>::max())
            {
                throw std::length_error("SOA RDATA is too large");
            }
            buffer.write_u16(total_length);
            buffer.write_qname(record.primary_name_server);
            buffer.write_qname(record.responsible_authority_mailbox);
            buffer.write_u32(record.serial_number);
            buffer.write_u32(record.refresh_interval);
            buffer.write_u32(record.retry_interval);
            buffer.write_u32(record.expire_limit);
            buffer.write_u32(record.minimum_ttl);
        }
        else if constexpr (std::is_same_v<T,UnknownRecord>){
            buffer.write_u16(static_cast<uint16_t>(record.data.size()));
            for (uint8_t byte : record.data){
                buffer.write_u8(byte);
            }
        }
    },data);
}

void DnsRecord::write(BytePacketBuffer &buffer) const
{

    buffer.write_qname(name);
    buffer.write_u16(static_cast<uint16_t>(type));
    buffer.write_u16(class_);
    buffer.write_u32(ttl);

    writeData(buffer);

}
