#include"hmac.h"
#include <type_traits>
#include <iterator>
#include <string>
#include <iostream>
#include <cassert>

namespace hmac_hash
{
    namespace
    {
        const std::size_t SHA256_BLOCK_SIZE = 64;
        const util::byte ipad_byte = 0x36;
        const util::byte opad_byte = 0x5c;


        template < typename ITERATOR >
        util::byte_array<SHA256_BLOCK_SIZE> make_hmac_key(ITERATOR begin, ITERATOR end)
        {
            // sanity check: the ITERATOR iterates over byte sozed items
            static_assert( sizeof(*begin) == sizeof(util::byte) );

            const std::size_t SZ = std::distance(begin, end);

            util::byte_array<SHA256_BLOCK_SIZE> result;
            result.fill(0); // initialize with all zeroes

            if (SZ <= result.size())
                std::copy(begin, end, result.begin());
            else
            {
                auto hash = sha256(begin, end);
                std::copy(hash.begin(), hash.end(), result.begin());
            }

            return result; 
        }

        void apply_xor_pad( util::byte_array<SHA256_BLOCK_SIZE>& bytes, util::byte pad)
        {
            for (util::byte& b : bytes)
            {
                unsigned int u = b;
                u ^= pad;
                b = static_cast<util::byte>(u);
            }
        }

        template < typename ITER1, typename ITER2 >
        util::byte_sequence cat(  ITER1 begin1, ITER1 end1,
                                  ITER2 begin2, ITER2 end2 )
        {
            util::byte_sequence result(begin1, end1);
            result.insert( result.end(), begin2, end2 );

            // sanity checks
            const auto SZ1 = std::distance(begin1, end1);
            const auto SZ2 = std::distance(begin2, end2);
            assert(result.size() == std::size_t(SZ1 + SZ2));
            if (SZ1) assert(result.front() == *begin1);
            if (SZ2) assert(result[SZ1] == *begin2);
            if (SZ1) assert(result[SZ1-1] == *--end1);
            if (SZ2) assert(result.back() == *--end2);

            return result;
        }

        template < typename RANGE1, typename RANGE2 >
        util::byte_sequence cat_ranges( const RANGE1& a, const RANGE2& b ) 
        {
            return cat(std::begin(a), std::end(a), std::begin(b), std::end(b));
        }

        template < typename DATA_RANGE, typename KEY_RANGE >
        sha256_context::digest_t hmac_helper( const DATA_RANGE& data,
                                              const KEY_RANGE& key)
        {
            // (1) append zeros to the end of K to create a B byte string
            const auto hmac_key = make_hmac_key(std::begin(key), std::end(key));

            // (2) XOR (bitwise exclusive-OR) the B byte string computed 
            // in step (1) with ipad
            auto step_2_result = hmac_key;
            apply_xor_pad(step_2_result, ipad_byte);

            // (3) append the stream of data 'text' to the B byte string
            // resulting from step(2)
            auto step_3_result = cat_ranges(step_2_result, data);

            // (4) apply H to the stream generated in step (3)
            auto step_4_result = sha256(std::begin(step_3_result), std::end(step_3_result));

            // (5) XOR (bitwise exclusive-OR) the B byte string computed in
            // step(1) with opad
            auto step_5_result = hmac_key;
            apply_xor_pad(step_5_result, opad_byte);

            // (6) append the H result from step (4) to the B byte string
            // resulting from step(5)
            auto step_6_result = cat_ranges(step_5_result, step_4_result);

             // (7) apply H to the stream generated in step (6) and output
            // the result
            return sha256(std::begin(step_6_result), std::end(step_6_result));
            
            /*
            auto temp_hmac = sha256(std::begin(step_6_result), std::end(step_6_result));
            for (auto& it : temp_hmac)
            {
                it = it & 0xFF;
            }

            return temp_hmac;
            */

        }

     
        
    }

    std::string hmac_rfc_str(const std::string& data,
        const std::string& key)
    {
        return util::bytes_to_hex_string(hmac_helper(data, key));
    }


    void test_make_key()
    {
        std::string user_key;
        std::cout << "user key: ";
        std::getline(std::cin, user_key);
        const auto key = make_hmac_key(user_key.begin(), user_key.end());
        std::cout << util::bytes_to_hex_string(key) << '\n';

        auto temp = key;
        apply_xor_pad(temp, 0x36);
        std::cout << util::bytes_to_hex_string(temp) << '\n';

        temp = key;
        apply_xor_pad(temp, 0x5C);
        std::cout << util::bytes_to_hex_string(temp) << '\n';
       
        util::byte_sequence seq1{ 1, 2, 3, 4 };
        std::string seq2 = "abcdefgh";
        const auto c = cat_ranges(seq1, seq2);
        // cat(seq1.begin(), seq1.end(), seq2.begin(), seq2.end());
        std::cout << util::bytes_to_hex_string(c) << '\n';

    }

    sha256_context::digest_t hmac(const util::byte_sequence& data,
        const util::byte_sequence& key )
    {
        const unsigned int BlockSize = 64 ;
        util::byte_array<BlockSize> usedKey ;
        // initialize usedKey with zeros
        usedKey.fill(0);

        // adjust length of key: must contain exactly blockSize bytes
        if (key.size() <= BlockSize)
        {
            // copy key
            std::copy(key.begin(), key.end(), usedKey.begin());
            // memcpy(usedKey, key, numKeyBytes);
        }
        else
        {
            // shorten key: usedKey = hashed(key)
            const auto hash = sha256(key.begin(), key.end());
            std::copy(hash.begin(), hash.end(), usedKey.begin());
        }


        /*
        for (size_t i = 0; i < BlockSize; i++)
        {
            usedKey[i] ^= 0x36;
        }
       */

       // inside = hash((usedKey ^ 0x36) + data)

        util::byte_sequence temp(usedKey.begin(), usedKey.end()); // temp ==  usedKey
        // create initial XOR padding
        for (auto& b : temp) b ^= 0x36; // temp == (usedKey ^ 0x36)

        temp.insert(temp.end(), data.begin(), data.end()); // temp == (usedKey ^ 0x36) + data

        const auto hash_key36_plus_data = sha256(temp.begin(), temp.end());


        // undo usedKey's previous 0x36 XORing and apply a XOR by 0x5C
        // for (auto& b : usedKey) b ^= 0x5C ^ 0x36;

        /*
        for (size_t i = 0; i < BlockSize; i++)
            usedKey[i] ^= 0x5C ^ 0x36;
        */

        // hash( (usedKey ^ 0x5C) + hash((usedKey ^ 0x36) + data) )

        temp = { usedKey.begin(), usedKey.end() }; // temp ==  usedKey
        for (auto& b : temp) b ^= 0x5C; // temp == (usedKey ^ 0x5C)


        temp.insert(temp.end(), hash_key36_plus_data.begin(), hash_key36_plus_data.end());
        // now, temp == (usedKey ^ 0x5C) + hash((usedKey ^ 0x36) + data)

        return sha256(temp.begin(), temp.end());
    }

    std::string hmac_str(util::byte_sequence data, util::byte_sequence key)
    {
        return util::bytes_to_hex_string(hmac(data, key));
    }

    std::string hmac_str( std::string_view data, std::string_view key)
    {
        return hmac_str({ data.begin(), data.end() }, { key.begin(), key.end() } );
    }
}