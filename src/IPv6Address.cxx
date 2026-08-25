#include "IPv6Address.hpp"

std::string IPv6Address::to_string() const {
    std::string result;
    for (size_t i = 0; i < address.size(); ++i) {
        if (i > 0) {
            result += ":";
        }
        result += std::to_string(static_cast<int>(address[i]));
    }
    return result;
} 