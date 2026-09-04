#pragma once
#include <string>

enum class QuestionType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    MX = 15,
    AAAA = 28,
    OPT = 41
};

inline std::string GetQuestionTypeName(QuestionType type) {
    switch (type) {
        case QuestionType::A: return "A";
        case QuestionType::NS: return "NS";
        case QuestionType::CNAME: return "CNAME";
        case QuestionType::SOA: return "SOA";
        case QuestionType::MX: return "MX";
        case QuestionType::AAAA: return "AAAA";
        case QuestionType::OPT: return "OPT";
        default: return "Unknown";
    }
}
