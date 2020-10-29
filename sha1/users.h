#ifndef USERS_H_INCLUDED
#define USERS_H_INCLUDED

#include <string>
#include "byte_stream.h"

namespace users
{
	using user_id_t = unsigned int;

	bool load_users(const std::string& file_name);
	bool save_users(const std::string& file_name);

	bool add_user( user_id_t user_id, const std::string& password);

	/*
	// not required for this program
	bool change_password( user_id_t user_id, const std::string& old_password,
		                  const std::string& new_password );
	bool remove_user( user_id_t user_id, const std::string& password );
	*/
	
	// throw std::domain_error if user_id is invalid
	util::byte_sequence secret_key(user_id_t user_id);

	// for testing
	// return the lowest user id that was generated
	unsigned int generate_random_users(std::size_t n);
}


#endif // USERS_H_INCLUDED