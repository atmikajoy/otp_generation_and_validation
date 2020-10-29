#ifndef TOTP_H_INCLUDED
#define TOTP_H_INCLUDED

#define _CRT_SECURE_NO_WARNINGS

#include<string>
#include"byte_stream.h"
#include"hmac.h"
#include"hotp.h"
#include <stdexcept>
#include <algorithm>
#include <ctime>
#include <cctype>
#include "users.h"

namespace totp
{
    namespace
    {
        static const std::uint64_t SYS_EPOCH = 0;
        static const unsigned int OTP_LEN = 6;

        #ifdef TEST_TOTP
           // for testing: small time step
           static const std::uint64_t SYS_TIME_STEP = 1 ;
           static const std::uint64_t SYS_VALID_TIME_NUM_INTERVALS = 5;
#else
           // production time step is 30 seconds
        static const std::uint64_t SYS_TIME_STEP = 30;
        static const std::uint64_t SYS_VALID_TIME_NUM_INTERVALS = 300 / SYS_TIME_STEP;
#endif // TEST_TOTP


        static inline bool time_is_in_seconds()
        {
            static const auto t = std::time(nullptr);
            static const unsigned int N = 1000;
            static const auto diff = std::difftime(t + N, t);

            return diff > (N - 1) && diff < (N + 1);
        }

        std::uint64_t curr_time()
        {
            if (time_is_in_seconds()) return std::time(nullptr);

            else throw std::runtime_error("non-unix time is not yet supported");
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

            util::byte_sequence bytes{ pb, pb + NBYTES };

            // reverse the bytes if we are on a little-endian architecture
            if (little_endian) std::reverse(bytes.begin(), bytes.end());

            return bytes;
        }
    }
    template <typename HASH_ALGO>
    std::string calculate( const util::byte_sequence& secret_key, 
                                std::int64_t epoch, std::int64_t timeStep,
                                std::int64_t timestamp, unsigned int code_len )
    {
        const int64_t temp = timestamp - epoch;
        if (temp < 0) std::invalid_argument("invalid timestamp");
        const uint64_t timeCounter = static_cast<uint64_t>(temp / timeStep);
        const util::byte_sequence counter = bytes_big_endian(timeCounter);
        return hotp::calculate<HASH_ALGO>(secret_key,counter,code_len);
    }

    template <typename HASH_ALGO>
    std::string generate(const util::byte_sequence& secret_key)
    {
        return calculate<HASH_ALGO>(secret_key, SYS_EPOCH, SYS_TIME_STEP,
            curr_time(), OTP_LEN);
    }

    template <typename HASH_ALGO>
    bool validate(const util::byte_sequence& secret_key, const std::string& otp)
    {
        static const auto is_digit = [](unsigned char u)
        { return std::isdigit(u); };

        if ( otp.size() != OTP_LEN || 
             !std::all_of( otp.begin(), otp.end(), is_digit )
           ) return false;

        const auto now = curr_time();
        for ( std::uint64_t i = 0; i < SYS_VALID_TIME_NUM_INTERVALS ; ++i )
        {
            if ( calculate<HASH_ALGO>( secret_key, SYS_EPOCH, SYS_TIME_STEP,
                                        now - i* SYS_TIME_STEP, OTP_LEN ) == otp )
                return true;
        }

        return false;
    }

    // throws an invalid user id if not found 
    template <typename HASH_ALGO>
    std::string generate(unsigned int user_id)
    {
        return generate<HASH_ALGO>(users::secret_key(user_id));
    }

    template <typename HASH_ALGO>
    bool validate(unsigned int user_id, const std::string& otp)
    {
        try
        {
            return validate<HASH_ALGO>( users::secret_key(user_id), otp );
        }
        catch ( const std::domain_error& )
        {
            return false; // invalid user id
        }
    }
}





#endif // TOTP_H_INCLUDED