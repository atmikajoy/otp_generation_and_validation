#include "users.h"
#include <algorithm>
#include <unordered_map>
#include <stdexcept>
#include<fstream>
#include<iostream>
#include <random>
#include"pbkdf2.h"
namespace users
{
	namespace
	{
		static const std::size_t MIN_PASSWORD_SIZE = 6;
		static const std::string SALT_STR = "E1F53135E559C253";
		static util::byte_sequence salt = util::hex_string_to_bytes(SALT_STR);
		static const std::size_t dkLen = 32; 
		static const std::size_t c = 4000; 
		// TO DO: use an actual encryption algorithm (PBKDF2) later
		util::byte_sequence encrypt(const std::string& password)
		{
			
			auto passwd = util::str_to_bytes(password);
		
			
			return pbkdf2::calculate<sha256>(passwd, salt, c, dkLen);;
		}

		std::unordered_map< user_id_t, util::byte_sequence > user_secret_map;
	}
	bool login_user()
	{
		int i = 0; 
		user_id_t uid;
		std::string password;
		do
		{
			std::cout << "enter UID, Password";
			std::cin >> uid >> password;
			if (validate_user(uid, password))
				return true;
			else
				std::cout << "Invalid login credentials";
			++i;
		} while (i < 3);
	}

	bool change_password(user_id_t user_id, const std::string& old_password,
		const std::string& new_password)
	{
		const auto iter = user_secret_map.find(user_id);
		if ( iter != user_secret_map.end())
		{
			if (iter->second == encrypt(old_password))
			{
				iter->second = encrypt(new_password);
				return true;
			}
			return false; 	 
		}
		return false; 

	}
	bool remove_user(user_id_t user_id, const std::string& password)
	{
		const auto iter = user_secret_map.find(user_id);
		if (iter != user_secret_map.end())
		{
			if (iter->second == encrypt(password))
			{
				user_secret_map.erase(iter);
				return true;
			}
		}
		return false;
	}

	bool validate_user(unsigned int user_id, std::string password)
	{
		if (user_secret_map.find(user_id) != user_secret_map.end())
			return encrypt(password) == user_secret_map[user_id];
		
		return false; 
	}

	bool load_users(const std::string& file_name)
	{
		std::ifstream stm(file_name);
		user_id_t uid;
		std::string secret;
		std::string line;
		while (std::getline(stm, line))
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
			add_user(next_id++, random_password());
			/*if (i % 10 == 9)*/ std::cout << '.' << std::flush;
		}
		std::cout << '\n';

		return first_id;

	}
}
