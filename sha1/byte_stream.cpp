#include "byte_strean.h"
#include <sstream>
#include <iomanip>
#include <map>
#include <cctype>
#include <fstream>
#include <iterator>

namespace util
{
	namespace
	{
		const std::map<char, int> hex_chars
		{
			{ 'A', 10 }, { 'B', 11 }, { 'C', 12 },
			{ 'D', 13 }, { 'E', 14 }, { 'F', 15 },

			{ 'a', 10 }, { 'b', 11 }, { 'c', 12 },
			{ 'd', 13 }, { 'e', 14 }, { 'f', 15 }
		};

		int hex_char_to_int(char c)
		{
			unsigned char uc = c;
			if (std::isdigit(uc)) return c - '0';

			const auto iter = hex_chars.find(c);
			if (iter != hex_chars.end()) return iter->second;
			else return -1;
		}
	}

	byte_sequence hex_string_to_bytes(std::string_view hex_str)
	{
		static const std::invalid_argument bad_arg_error("bad hex string");
		
		if (hex_str.size() % 2u == 1U ) throw bad_arg_error ;
		
		byte_sequence result;

		for( std::size_t i = 0 ; i < hex_str.size() ; i += 2 )
		{
			const int first = hex_char_to_int(hex_str[i] ) * 16;
			const int second = hex_char_to_int(hex_str[i + 1]);
			if( first < 0 || second < 0 ) throw bad_arg_error;
			result.push_back(first + second);
		}

		return result;
	}

	byte_sequence bytes_in_file(const std::string& file_name)
	{
		if (std::ifstream file{ file_name, std::ios::binary })
		{ 
			/*
			byte_sequence result;

			char c ;
			while( file.get(c) ) result.push_back(c);

			return result ;
			*/

			file >> std::noskipws;
			using iterator = std::istream_iterator<byte>;
			return { iterator(file), iterator{} };
		}

		return {};
	}
}