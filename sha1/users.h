#ifndef USERS_H_INCLUDED
#define USERS_H_INCLUDED

#include <string>
#include "byte_strean.h"

namespace users
{
	using user_id_t = unsigned int;

	bool add_user( user_id_t user_id, const std::string& password);

	/*
	// not required for this program
	bool change_password( user_id_t user_id, const std::string& old_password,
		                  const std::string& new_password );
	bool remove_user( user_id_t user_id, const std::string& password );
	*/
	
	// throw std::domain_error if user_id is invalid
	util::byte_sequence secret_key(user_id_t user_id);
}


#endif // USERS_H_INCLUDED