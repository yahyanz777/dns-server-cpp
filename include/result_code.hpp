#pragma once

#include <cstdint>

enum class ResultCode : uint8_t
{
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
    UNKNOWN = 6
};

inline ResultCode result_code_from_num(uint8_t num)
{
    switch (num)
    {
    case 0:
        return ResultCode::NOERROR;
    case 1:
        return ResultCode::FORMERR;
    case 2:
        return ResultCode::SERVFAIL;
    case 3: 
        return ResultCode::NXDOMAIN;
    case 4: 
        return ResultCode::NOTIMP;
    case 5:
        return ResultCode::REFUSED;
    default:
        return ResultCode::UNKNOWN;
    }
}