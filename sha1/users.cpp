#include "users.h"
#include <algorithm>
#include <unordered_map>
#include <stdexcept>
#include<fstream>
#include<iostream>
#include <random>

namespace users
{
	namespace
	{
		static const std::size_t MIN_PASSWORD_SIZE = 6;

		// TO DO: use an actual encryption algorithm (PBKDF2) later
		util::byte_sequence encrypt(const std::string& password)
		{
			auto bytes = util::str_to_bytes(password);
			for (auto& b : bytes)
			{
				if (b < 40) b += 39;
				else b -= 39;
			}
			std::reverse(bytes.begin(), bytes.end());
			return bytes;
		}

		std::unordered_map< user_id_t, util::byte_sequence > user_secret_map;
	}

	bool load_users(const std::string& file_name)
	{
		std::ifstream stm(file_name);
		user_id_t uid;
		std::string secret;
		std::string line;
		while (std::getline(stm,line))
		{
			std::stringstream stm(line);
			stm >> uid >> secret;
			if (user_secret_map.find(uid) != user_secret_map.end())
				return false;
			user_secret_map[uid] = util::hex_string_to_bytes(secret);

			
		}
		return true;
	}

	bool save_users(const std::string& file_name)
	{
		std::ofstream stm(file_name);
		for (auto [uid, secret] : user_secret_map)
		{
			stm << uid << " " << util::bytes_to_hex_string(secret) << '\n';
		}
		return true;
	}

	bool add_user(user_id_t user_id, const std::string& password)
	{
		if (user_secret_map.find(user_id) != user_secret_map.end())
			return false;

		if (password.size() < MIN_PASSWORD_SIZE) return false;

		user_secret_map[user_id] = encrypt(password); 
		return true;
	}

	// throw std::domain_error if user_id is invalid
	util::byte_sequence secret_key(user_id_t user_id)
	{
		const auto iter = user_secret_map.find(user_id);
		
		if (iter == user_secret_map.end())
			throw std::domain_error("invalid user id");

		return iter->second;
	}

	namespace
	{
		static const std::size_t MAX_PASSWORD_SIZE = 30;

		const std::string valid_chars = "ABCDEFGHIJKLNOPQRSTUVWXYZ"
			"abcdefghijklnopqrstuvwxyz"
			"1234567890!@#$%^&*()_+";

		std::mt19937 rng(std::random_device{}());

		char random_char()
		{
			static std::uniform_int_distribution<std::size_t> distrib(0, valid_chars.size() - 1);
			return valid_chars[distrib(rng)];
		}

		std::string random_password()
		{
			static std::uniform_int_distribution<std::size_t> distrib(MIN_PASSWORD_SIZE, MAX_PASSWORD_SIZE);
			
			const auto len = distrib(rng);
			std::string pword;
			while (pword.size() < len) pword += random_char();
			return pword;

		}

		const unsigned int START_USER_ID = 1000;

	}

	unsigned int generate_random_users(std::size_t n)
	{
		static unsigned int next_id = START_USER_ID;

		const unsigned int first_id = next_id;

		for (std::size_t i = 0; i < n; ++i)
		{
			add_user( next_id++, random_password() );
		}

		return first_id;

	}
}
