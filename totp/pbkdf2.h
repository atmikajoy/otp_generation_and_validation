#ifndef PBKDF2_H_INCLUDED
#define PBKDF2_H_INCLUDED
#include <string>
#include<algorithm>
#include<vector>
#include"byte_stream.h"
#include<limits>
#include"hmac.h"
namespace pbkdf2
{
    namespace 
    {
        std::array<util::byte, 4> four_octet_encoding(std::uint32_t i)
        {
            return { { util::byte(i >> 24U), util::byte(i >> 16U) ,
                       util::byte(i >> 8U) , util::byte(i)} };
        }
    }

    

    // Password-Based Key Derivation Function 2 (PBKDF2)
    // RFC 2898 PKCS#5 version 2.0
    template<typename HASH_ALGO>
    util::byte_sequence calculate( const util::byte_sequence& P, // P = Password/Secret
        const util::byte_sequence& S, // S = SALT
        std::size_t  c, // c = rounds/iterations
        std::size_t dkLen) // dkLen = Derived Key Length 
    {

       // (1) If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
       // stop.
       // PRF (pseudo random function) in our case is HMAC
       // Hlen is size of the digest_type returned by HMAX::hash()
        std::size_t hLen =hmac<HASH_ALGO>::digest_size;
        static auto max_32bit_val = long(std::numeric_limits<int32_t>::max());
        if (dkLen > (max_32bit_val) * hLen) 
            std::invalid_argument("Derived Key too long");

        // (2) Let l be the number of hLen-octet blocks in the derived key,
        //rounding up, and let r be the number of octets in the last
        //    block :
        //              l = CEIL (dkLen / hLen) 
        //              r = dkLen - (l - 1) * hLen
        
        static std::uint32_t l = (dkLen % hLen) ? (dkLen/hLen) : (dkLen/hLen + 1); 
        static std::size_t r = dkLen - ((l - 1) * hLen);

        /* 
        (3) For each block of the derived key apply the function F defined
         below to the password P, the salt S, the iteration count c, and
         the block index to compute the block
            T_l = F(P, S, c, l),

         where the function F is defined as the exclusive - or sum of the
         first c iterates of the underlying pseudorandom function PRF (HMAC)
         applied to the password P and the concatenation of the salt S
         and the block index i :
         F(P, S, c, i) = U_1 \ xor U_2 \ xor ... \ xor U_c
         where
         U_1 = PRF(P, S || INT(i)),
         U_2 = PRF(P, U_1),
         ...
         U_c = PRF(P, U_{ c - 1 }) .
         Here, INT(i) is a four - octet encoding of the integer i, most
         significant octet first.
        */
        util::byte_sequence p = P; 
        util::byte_sequence running_xor;
        std::vector<util::byte_sequence> T;
        util::byte_sequence temp_S = S; 
        for (unsigned int iterations = 1; iterations <= c; ++iterations)
        {
            auto i = four_octet_encoding(c);
            temp_S.insert(temp_S.end(), i.begin(), i.end());
            {
                const auto temp = hmac<HASH_ALGO>::compute(P, temp_S);;
                p = { temp.begin(), temp.end() };
            }

            for (std::size_t j = 1; j <= l; ++j)
            {
                auto un = hmac<HASH_ALGO>::compute(p, S);

                for (std::size_t k = 0; k < un.size(); ++k)
                {
                    running_xor.push_back(un[k] ^ p[k]);
                }

                T.push_back(running_xor);
                running_xor.clear();
                p = { un.begin(), un.end() };
            }
        }

        // (4) Concatenate the blocks and extract the first dkLen octets to
        // produce a derived key DK : 
        // DK = T_1 || T_2 || ... || T_l<0..r - 1>

        util::byte_sequence DK(T[0].size());
        for (unsigned int n = 0; n < T.size() - 1; ++n)
        {
            for (unsigned int j = 0; j < T[n].size(); ++j)
            {
                DK[j] = (T[n][j] + T[n + 1][j]);
            }
        }

        // (5) Resize to dklen and return the derived key DK
        DK.resize(dkLen);
        return DK;       
        
    }
}
#endif // PBKDF2_H_INCLUDED