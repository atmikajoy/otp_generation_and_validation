#include "base32.h"
#include <bitset>
#include <cctype>
#include <stdexcept>
#include <sstream>

namespace util
{
	namespace
	{
		const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
		constexpr char pad_char = '=';
		static const std::invalid_argument bad_arg_error("bad base32 string");

		std::string bit_string(byte b)
		{
			unsigned long v = b;
			return std::bitset<8>(v).to_string();
		}

		char bits_to_base32(std::string bits)
		{
			unsigned long value = std::bitset<5>(bits).to_ulong();
			return alphabet[value];
		}

		std::size_t index_value(char c)
		{
			c = std::toupper((unsigned char)c);
			auto pos = alphabet.find(c);
			if (pos == std::string::npos) throw bad_arg_error;
			return pos;
		}

		std::bitset<5> bits_of(char c)
		{
			return std::bitset<5>(index_value(c));
		}

		std::string bit_string_of(char c)
		{
			return bits_of(c).to_string();
		}
	};

	std::string to_base32(const byte_sequence& bytes)
	{
		std::string bits_str;
		for (byte b : bytes) bits_str += bit_string(b);
		auto nbits = bits_str.size();
		while (nbits % 5 != 0)
		{
			bits_str += '0';
			nbits += 1;
		}

		std::string result;
		for (std::size_t i = 0; i < bits_str.size(); i += 5)
			result += bits_to_base32(bits_str.substr(i, 5));
		return result;
	}

	std::string to_padded_base32(const byte_sequence& bytes)
	{
		std::string b32_str = to_base32(bytes);
		while (b32_str.size() % 8 != 0) b32_str += pad_char;
		return b32_str;
	}

	base32_data to_base32_data(const byte_sequence& bytes)
	{
		return { bytes.size(), to_base32(bytes) };
	}

	namespace
	{
		bool is_padded(std::string_view base32_str)
		{
			if (base32_str.size() % 8 != 0) return false;

			if (base32_str.back() != pad_char) return false;

			const auto pos = base32_str.find_first_not_of(alphabet);
			const auto npads = base32_str.size() - pos;
			return npads == 6 || npads == 4 || npads == 3 || npads == 1;
		}

		byte_sequence from_padded_base32_helper(std::string_view str)
		{
			std::size_t nbytes = (str.size() / 8) * 5;

			if (is_padded(str))
			{
				std::size_t npads = 0;

				while (str.back() == pad_char)
				{
					str.remove_suffix(1);
					++npads;
				}

				switch (npads)
				{
				case 1: nbytes -= 1; break;
				case 3: nbytes -= 2; break;
				case 4: nbytes -= 3; break;
				default: nbytes -= 4;
				}
			}

			return from_base32(str, nbytes);
		}
	}

	byte_sequence from_base32(std::string_view str, std::size_t sz)
	{
		// if the base32 string consists of an integral multiple of eight characters,
		// then we know that he origibal data consysted of an integral multiple 
		// of 5-byte (40-bit) byte segments. so we ignore the soze
		// (note that 5 bytes (40 bits) form 8 base32 characters.)
		if (str.size() % 8 == 0) sz = -1;

		byte_sequence result_byte_seq;
		std::string result_byte_str;
		for (auto b : str) result_byte_str += bit_string_of(b);
		auto nbits = result_byte_str.size();
		while (nbits % 8 != 0)
		{
			result_byte_str += '0';
			++nbits;
		}
		for (std::size_t i = 0; i < nbits; i += 8)
		{
			std::string val = result_byte_str.substr(i, 8);
			result_byte_seq.push_back(byte(std::bitset<8>(val).to_ulong()));
		}

		if (!result_byte_seq.empty() && result_byte_seq.back() == 0)
		{
			if (sz == result_byte_seq.size() - 1) result_byte_seq.pop_back();
		}

		return result_byte_seq;
	}

	byte_sequence from_padded_base32(std::string_view str)
	{
		if (!is_padded(str) && str.size() % 8 != 0)
			throw std::invalid_argument("badly padded base32 sring");
		return from_padded_base32_helper(str);
	}

	std::string base32_data::to_string() const
	{
		return std::to_string(nbytes) + " :" + b32_str;
	}

	base32_data::base32_data(const std::string& length_prefixed_str)
	{
		std::istringstream stm(length_prefixed_str);
		char colon;
		if (stm >> nbytes >> colon && colon == ':' && std::getline(stm, b32_str))
		{
		}
		else throw std::invalid_argument("bad length_prefixed string");
	}
}
