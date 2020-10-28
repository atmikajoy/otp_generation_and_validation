#ifndef TOTP_H_INCLUDED
#define TOTP_H_INCLUDED

#include<string>
#include"byte_strean.h"
#include"hmac.h"
#include"hotp.h"
#include <stdexcept>
#include <algorithm>
#include <ctime>

namespace totp
{
    static inline bool time_is_in_seconds()
    {
        static const auto t = std::time(nullptr);
        static const unsigned int N = 1000;
        static const auto diff = std::difftime(t+ N, t );

        return diff > (N - 1) && diff < (N + 1);
    }

    // return true if we are on a little-endian architecture
    static inline bool is_little_endian()
    {
        static const std::uint32_t n = 0x12345678;
        static const util::byte* pb = 
            reinterpret_cast<const util::byte*>(std::addressof(n));

        // note: we check only the last byte as we don't deal with 
        //       the esoteric middle-endian architectire
        return *pb == 0x78;
    }

    static inline util::byte_sequence bytes_big_endian(std::uint64_t n)
    {
        static constexpr std::size_t NBYTES = 8;
        static const bool little_endian = is_little_endian();

        const util::byte* pb = reinterpret_cast<const util::byte*>(std::addressof(n));
        
        util::byte_sequence bytes{ pb, pb+NBYTES };
        
        // reverse the bytes if we are on a little-endian architecture
        if (little_endian) std::reverse(bytes.begin(), bytes.end());

        return bytes;
    }

    template <typename HASH_ALGO>
    std::string calculate( const util::byte_sequence& secret_key, 
                                std::int64_t epoch, std::int64_t timeStep,
                                std::int64_t timestamp, unsigned int code_len )
    {

        // Calculate counter and HOTP
        const int64_t temp = timestamp - epoch;
        if (temp < 0) std::invalid_argument("invalid timestamp");
        const uint64_t timeCounter = static_cast<uint64_t>(temp / timeStep);
        const util::byte_sequence counter = bytes_big_endian(timeCounter);
        return hotp::calculate<HASH_ALGO>(secret_key,counter,code_len);
    }
}





#endif // TOTP_H_INCLUDED