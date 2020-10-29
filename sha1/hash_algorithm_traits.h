#ifndef HASH_ALGORITHM_TRAITS_H_INCLUDED
#define HASH_ALGORITHM_TRAITS_H_INCLUDED

#include "byte_strean.h"
#include <functional>

template < typename T > struct hash_algorithm_traits
{
	constexpr std::size_t BLOCK_SIZE = T::BLOCK_SIZE;
	using digest_type = T::digest_type;
	// digest_type (*pfn_hash_function)( const util::byte_sequence& )
};

#endif // HASH_ALGORITHM_TRAITS_H_INCLUDED