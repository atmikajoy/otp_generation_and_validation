#pragma warning (disable:4180) // disable 'qualifier applied to function type has 
                               //          no meaning; ignored' warning from pybind11
#include <pybind11/pybind11.h>
#include "../totp/sha256.h"
#include"../totp/hmac.h"
#include"../totp/hotp.h"
#include "../totp/totp.h"
#include "../totp/users.h"
namespace py_api
{
	std::string sha256(std::string input)
	{
		return ::sha256_str(input);
	}

	std::string hmac_sha256(std::string data, std::string key)
	{
		return hmac<::sha256>::compute_str(data, key);
	}

	// input strings contain bytes encoded as hex strings
	std::string hotp_hmac_sha256( std::string secret_key,
		                          std::string counter, int code_len )
	{
		// static constexpr unsigned int code_len = 5;
		if (code_len < 1) throw std::invalid_argument("bad value for code length");
		return hotp::calculate<::sha256>( secret_key, counter, code_len );
	}

	std::string generate_totp(std::string secret_key)
	{
		return totp::generate<::sha256>(util::str_to_bytes(secret_key));
	}

	bool validate_totp(std::string secret_key, std::string otp)
	{
		return totp::validate<::sha256>(util::str_to_bytes(secret_key), otp);
	}

	bool user_add(unsigned int user_id, std::string password)
	{
		return users::add_user(user_id, password);
	}

	bool user_login(unsigned int uid, std::string password)
	{
		return users::login_user(uid, password);
	}

	bool change_password(unsigned int user_id,
		std::string old_password,
		std::string new_password)
	{
		return users::change_password(user_id, old_password, new_password);
	}
	bool user_remove(unsigned int user_id, std::string password)
	{
		return users::remove_user(user_id, password);
	}
	
}

PYBIND11_MODULE( cryptopp, python_module) 
{
	python_module.doc() = "sha256,hmac in c++"; // optional module docstring

	python_module.def( "sha256", &py_api::sha256, 
		               "sha256 hash digest as a hex string");

	python_module.def("hmac_sha256", &py_api::hmac_sha256,
		              "compute hmac using undelying sha256 hash");

	python_module.def("hotp_hmac_sha256", &py_api::hotp_hmac_sha256,
		          "generate hotp using hmac and undelying sha256 hash");

	python_module.def("generate_totp", &py_api::generate_totp,
		              "function to generate totp");

	python_module.def("validate_totp", &py_api::validate_totp,
		              "function to validate totp");

	python_module.def("user_add", &py_api::user_add, "adding users");

	python_module.def("user_login", &py_api::user_login, "logging users in");

	python_module.def("user_change_password", &py_api::change_password,
		              "changing password for a particular user ");

	python_module.def("user_remove", &py_api::user_remove, "removing a user");
}