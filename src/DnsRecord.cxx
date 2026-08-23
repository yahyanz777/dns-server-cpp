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

        std::string address = std::to_string(buffer.read_u8()) + "." +
                              std::to_string(buffer.read_u8()) + "." +
                              std::to_string(buffer.read_u8()) + "." +
                              std::to_string(buffer.read_u8());
        data = ARecord{address};
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
   std::visit([](const auto& record){
    using T = std::decay_t<decltype(record)>;
    if constexpr (std::is_same_v<T,ARecord>){
        std::cout << "A Record:" <<record.address;
    }
    else if constexpr (std::is_same_v<T,AAAARecord>){
        std::cout << "AAAA Record:" <<record.address;
    }
    else if constexpr (std::is_same_v<T,CNAMERecord>){
        std::cout << "CNAME Record:" <<record.canonical_name;
    }
    else if constexpr (std::is_same_v<T,MXRecord>){
        std::cout << "MX Record: Preference: " << record.preference << ", Exchange: " << record.exchange;
    }
    else if constexpr (std::is_same_v<T,NSRecord>){
        std::cout << "NS Record:" <<record.name_server;
    }
    else if constexpr (std::is_same_v<T,UnknownRecord>){
        std::cout << "Unknown Record: Data size: " << record.data.size();
    }

   },data);
}

void DnsRecord::print() const
{
    std::cout << "Name: " << name << ", Type: " << static_cast<uint16_t>(type) << ", Class: " << class_ << ", TTL: " << ttl << ", RDLength: " << rdlength << ", RData: ";
    printData();
    std::cout << std::endl;
}