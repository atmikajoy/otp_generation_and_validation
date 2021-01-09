#ifndef HOTP_H_INCLUDED
#define HOTP_H_INCLUDED

#include<string>
#include"byte_stream.h"
#include"hmac.h"
#include<sstream>
#include <stdexcept>

namespace hotp
{
    static constexpr unsigned int min_code_length = 5;
    static constexpr unsigned max_code_length = 9;

    static inline constexpr unsigned long long ten_pow(unsigned int n)
    {
        if (n == 0) return 1;
        else return 10U * ten_pow(n - 1);
    }


    template <typename HASH_ALGO>
    std::string calculate(const util::byte_sequence& secret_key,
        const util::byte_sequence& counter, unsigned int code_len) {


        if (code_len < min_code_length || code_len > max_code_length)
            throw std::invalid_argument("Invalid number of digits");

        auto hash = hmac<HASH_ALGO>::compute(secret_key, counter);

        // Dynamically truncate the hash value
        int offset = hash.back() & 0xF;
        unsigned long val = 0;
        for (int i = 0; i < 4; i++)
            val |= static_cast<unsigned long>(hash.at(offset + i)) << ((3 - i) * 8);
        val &= 0x7FFFFFFFUL;

        // Extract and format base-10 digits
        std::string result = std::to_string(val % ten_pow(code_len));
        while (result.size() < code_len) result = '0' + result;
        return result;
    }

    template <typename HASH_ALGO>
    std::string calculate(const std::string& secret_key_hex_str,
        const std::string& counter_hex_str, unsigned int code_len)
    {
        return calculate<HASH_ALGO>(util::hex_string_to_bytes(secret_key_hex_str),
            util::hex_string_to_bytes(counter_hex_str),
            code_len);
    }
}


#endif // HOTP_H_INCLUDED
