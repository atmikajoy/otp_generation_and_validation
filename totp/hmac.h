#ifndef HMAC_H_INCLUDED
#define HMAC_H_INCLUDED


#include <string>
#include <cstring> // memcpy
#include "byte_stream.h"
#include"sha256.h"
#include <algorithm>
#include <cassert>

/// compute HMAC hash of data and key using MD5, SHA1 or SHA256
template <typename hash_method>
struct hmac
{
    using digest_type = typename hash_method::digest_type;

    template < typename DATA_RANGE, typename KEY_RANGE >
    static digest_type compute(const DATA_RANGE& data, const KEY_RANGE& key);

    static std::string compute_str(const std::string& data, const std::string& key);

private:
    static constexpr std::size_t BLOCK_SIZE = hash_method::BLOCK_SIZE;
    static constexpr util::byte ipad_byte = 0x36;
    static constexpr util::byte opad_byte = 0x5c;

    template <typename ITERATOR >
    static util::byte_array<BLOCK_SIZE> make_hmac_key(ITERATOR begin, ITERATOR end)
    {
        // sanity check: the ITERATOR iterates over byte sized items
        static_assert(sizeof(*begin) == sizeof(util::byte));

        const std::size_t SZ = std::distance(begin, end);

        util::byte_array<BLOCK_SIZE> result;
        result.fill(0); // initialize with all zeroes

        if (SZ <= result.size())
            std::copy(begin, end, result.begin());
        else
        {
            auto hash = hash_method::hash(begin, end);
            std::copy(hash.begin(), hash.end(), result.begin());
        }

        return result;

    }

    static void apply_xor_pad(util::byte_array<BLOCK_SIZE>& bytes, util::byte pad);

    void test_make_key();
};


template<typename hash_method>
void hmac<hash_method>::apply_xor_pad(util::byte_array<BLOCK_SIZE>& bytes, util::byte pad)
{
    for (util::byte& b : bytes)
    {
        unsigned int u = b;
        u ^= pad;
        b = static_cast<util::byte>(u);
    }
}

namespace
{
    template < typename ITER1, typename ITER2 >
    util::byte_sequence cat(ITER1 begin1, ITER1 end1,
        ITER2 begin2, ITER2 end2)
    {
        util::byte_sequence result(begin1, end1);
        result.insert(result.end(), begin2, end2);

        // sanity checks
        const auto SZ1 = std::distance(begin1, end1);
        const auto SZ2 = std::distance(begin2, end2);
        assert(result.size() == std::size_t(SZ1 + SZ2));
        if (SZ1) assert(result.front() == *begin1);
        if (SZ2) assert(result[SZ1] == *begin2);
        if (SZ1) assert(result[SZ1 - 1] == *--end1);
        if (SZ2) assert(result.back() == *--end2);

        return result;
    }

    template < typename RANGE1, typename RANGE2 >
    util::byte_sequence cat_ranges(const RANGE1& a, const RANGE2& b)
    {
        return cat(std::begin(a), std::end(a), std::begin(b), std::end(b));
    }
}

template<typename hash_method>
template < typename DATA_RANGE, typename KEY_RANGE >
typename hmac<hash_method>::digest_type
hmac<hash_method>::compute(const DATA_RANGE& data, const KEY_RANGE& key)
{
    // (1) append zeros to the end of K to create a B byte string
    const auto step_1_result = make_hmac_key(std::begin(key), std::end(key));

    // (2) XOR (bitwise exclusive-OR) the B byte string computed 
    // in step (1) with ipad
    auto step_2_result = step_1_result;
    apply_xor_pad(step_2_result, ipad_byte);

    // (3) append the stream of data 'text' to the B byte string
    // resulting from step(2)
    auto step_3_result = cat_ranges(step_2_result, data);

    // (4) apply H to the stream generated in step (3)
    auto step_4_result = hash_method::hash(std::begin(step_3_result), std::end(step_3_result));

    // (5) XOR (bitwise exclusive-OR) the B byte string computed in
    // step(1) with opad
    auto step_5_result = step_1_result;
    apply_xor_pad(step_5_result, opad_byte);

    // (6) append the H result from step (4) to the B byte string
    // resulting from step(5)
    auto step_6_result = cat_ranges(step_5_result, step_4_result);

    // (7) apply H to the stream generated in step (6) and output
   // the result
    return hash_method::hash(std::begin(step_6_result), std::end(step_6_result));

    /*
    auto temp_hmac = sha256(std::begin(step_6_result), std::end(step_6_result));
    for (auto& it : temp_hmac)
    {
        it = it & 0xFF;
    }

    return temp_hmac;
    */

}




template<typename hash_method>
std::string hmac<hash_method>::compute_str(const std::string& data,
    const std::string& key)
{
    return util::bytes_to_hex_string(compute(data, key));
}


#endif // !HMAC_H_INCLUDED