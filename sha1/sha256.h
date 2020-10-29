#ifndef SHA256_H
#define SHA256_H
#include <string>
#include"byte_stream.h"
#include <array>

struct sha256_base
{
    static constexpr std::size_t BLOCK_SIZE = (512 / 8) ;

    static constexpr std::size_t DIGEST_SIZE = (256 / 8);

    using digest_type = util::byte_array<DIGEST_SIZE>;
};

std::string sha256_str(std::string input);
util::byte_sequence sha256_vec(const std::string& input);
sha256_base::digest_type sha256_digest(const std::string& input);

template < typename ITERATOR >
sha256_base::digest_type sha256_digest(ITERATOR begin, ITERATOR end)
{
    static_assert(sizeof(*begin) == sizeof(util::byte));
    return sha256_digest(std::string{ begin, end } );
}

template < typename ITERATOR >
std::string sha256_str(ITERATOR begin, ITERATOR end)
{
    static_assert(sizeof(*begin) == sizeof(util::byte));
    return sha256_str(std::string{ begin, end });
}

struct sha256 : sha256_base
{
    static inline std::string hash_str(std::string input) 
    {
        return sha256_str(input);
    }

    static inline util::byte_sequence hash_to_vec(const std::string& input) 
    {
        return sha256_vec(input);
    }

    static inline digest_type hash(const std::string& input)
    {
        return sha256_digest(input);
    }

    template < typename ITERATOR >
    static inline digest_type hash(ITERATOR begin, ITERATOR end)
    {
        static_assert(sizeof(*begin) == sizeof(util::byte));
        return hash(std::string{ begin, end });
    }

    template < typename ITERATOR >
    static inline std::string hash_str(ITERATOR begin, ITERATOR end)
    {
        static_assert(sizeof(*begin) == sizeof(util::byte));
        return hash_str(std::string{ begin, end });
    }
};

#endif