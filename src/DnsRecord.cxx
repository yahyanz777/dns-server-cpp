#include <BytePacketBuffer.hpp>
#include <DnsRecord.hpp>
#include <QuestionType.hpp>
#include <stdexcept>

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
            uint16_t len =record.canonical_name.length(); 
            if (record.canonical_name[len-1] == '.'){
               buffer.write_u16(static_cast<uint16_t>(record.canonical_name.length() + 1));
            }else{
                buffer.write_u16(static_cast<uint16_t>(record.canonical_name.length() + 2));
            }
            buffer.write_qname(record.canonical_name);
        }
        else if constexpr (std::is_same_v<T,MXRecord>){
            uint16_t len = record.exchange.length();
            if (record.exchange[len-1] == '.'){
                buffer.write_u16(2 + static_cast<uint16_t>(record.exchange.length() + 1)); // RDLength for MX is 2 bytes for preference + qname length
            }else{
                buffer.write_u16(2 + static_cast<uint16_t>(record.exchange.length() + 2)); // RDLength for MX is 2 bytes for preference + qname length
            }
            buffer.write_u16(record.preference);
            buffer.write_qname(record.exchange);
        }
        else if constexpr (std::is_same_v<T,NSRecord>){
            uint16_t len = record.name_server.length();
            if (record.name_server[len-1] == '.'){
                buffer.write_u16(static_cast<uint16_t>(record.name_server.length() + 1)); // RDLength for NS is qname length
            }else{
                buffer.write_u16(static_cast<uint16_t>(record.name_server.length() + 2)); // RDLength for NS is qname length
            }
            buffer.write_qname(record.name_server);
        }
        else if constexpr (std::is_same_v<T,UnknownRecord>){
            buffer.write_u16(record.data.size());
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