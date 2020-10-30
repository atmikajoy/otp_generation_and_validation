#ifndef BYTE_STREAM_H
#define BYTE_STREAM_H

#include <cstddef>
#include <vector>
#include <string_view>
#include <limits>
#include <string>
#include <array>
#include <sstream>
#include <iomanip>

namespace util
{
    // our byte is an octet
    using byte = std::uint8_t;
    using byte_sequence = std::vector<byte>;
    template < std::size_t N > using byte_array = std::array< byte, N >;

    inline byte_sequence str_to_bytes(std::string_view str)
    {
        static_assert(std::numeric_limits<unsigned char>::digits == 8);
        return { str.begin(), str.end() };
    }

    namespace detail
    {
        template < typename ITERATOR >
        std::string bytes_to_hex_string(ITERATOR begin, ITERATOR end)
        {
            std::ostringstream stm;
            stm << std::hex << std::setfill('0');

            using uint = unsigned int;
            for (auto iter = begin; iter != end; ++iter)
                stm << std::setw(2) << uint(*iter);

            return stm.str();
        }
    }

    inline std::string bytes_to_hex_string(const byte_sequence& bytes)
    {
        return detail::bytes_to_hex_string(bytes.begin(), bytes.end());
    }

    template < std::size_t N >
    inline std::string bytes_to_hex_string(const byte_array<N>& bytes)
    {
        return detail::bytes_to_hex_string(bytes.begin(), bytes.end());
    }

    byte_sequence hex_string_to_bytes(std::string_view hex_str);

    byte_sequence bytes_in_file(const std::string& file_name);

}

#endif // BYTE_STREAM_H