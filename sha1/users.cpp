#include "users.h"
#include <algorithm>
#include <unordered_map>
#include <stdexcept>

namespace users
{
	namespace
	{
		static const std::size_t MIN_PASSWORD_SIZE = 6;

		// TO DO: use an actual encryption algorith later
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
}
