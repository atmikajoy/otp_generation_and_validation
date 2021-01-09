#define _CRT_SECURE_NO_WARNINGS
#include <iomanip>
#include <iostream>
#include "byte_stream.h"
#include "base32.h"
#include <fstream>
#include"sha256.h"
#include"hmac.h"
#include <bitset>
#include"hotp.h"
#include<unordered_map>
#define TEST_TOTP
#include "totp.h"
#include <thread>
#include <chrono>
#include"pbkdf2.h"

#define PRINT(x) \
     (std::cout << #x << " == " << x << '\n')

#define CAT(x,y) (x##y)

#define MAX_OF(a,b) ( (a)>(b) ? (a) : (b) )

template < typename A, typename B >
inline decltype(auto) max_of(A& a, B& b) { return a > b ? a : b; }

util::byte_sequence cat(util::byte_sequence a, const util::byte_sequence b)
{
	a.insert(a.end(), b.begin(), b.end());
	return a;
}

constexpr unsigned long long ipow(unsigned int a, unsigned int b)
{
	return b == 0 ? 1 : a * ipow(a, b - 1);
}

std::vector<int> read_numbers_from_line(std::istream& stm)
{
	std::string line;
	if (std::getline(stm, line))
	{
		std::istringstream str_stm(line);
		return { std::istream_iterator<int>(str_stm),
				 std::istream_iterator<int>{} };
	}

	else return {}; // getline failed
}

void foo(util::byte) { std::cout << "void foo( util::byte )\n"; }
void foo(int) { std::cout << "void foo( int )\n"; }
void test_hmac()
{
	const std::string test_string[] =
	{
		"grape",
		"how now brown cow",
		"this is a long long long long long long long long string",
		"this is a.long long long long long long long long string",
		"a",
		"a string\nwith new lines\nin it!",
		""
	};

	const std::string expected_hmac_sha256_hex_string[std::size(test_string)] =
	{
		"022414aa54471a58c1bfa5216ffd1ff2696464b7fefc55e3c58ea0659655e57d",
		"0362def74af0d692dcfc9f207a48cf24a7b3187b3e0488a1b9744749f15ead7d",
		"92b51c29630e819a775c2d5e53e746871f928f79afe38137173312fd29ae8edf",
		"7ca4aceb9f2adca8d24978128c59395df0083552ea872fdc68b104843b9d42d4",
		"2305899dd7ff6219a9106e9509c13fa18bb17407c1dbd61bf25bbf8f834499bc",
		"c604ca91044c45f320e9fd0f436d7d182d23c33127521de98814d6a9413ef248",
		"4d3ffa81150bb023b190db966426e7ffa29ebc05353e48c2a5bf1c35c074a5bf"

	};

	for (std::size_t i = 0; i < std::size(test_string); ++i)
	{
		const auto result = hmac<sha256>::compute_str(test_string[i], "hello");
		std::cout << "          input: " << test_string[i] << '\n'
			<< "expected hmac: " << expected_hmac_sha256_hex_string[i] << '\n'
			<< "  atmiks hmac: " << result << '\n'
			<< "ok? " << std::boolalpha << (result == expected_hmac_sha256_hex_string[i])
			<< "\n\n";
	}
}

void test_sha256()
{
	const std::string test_string[] =
	{
		"grape",
		"how now brown cow",
		"this is a long long long long long long long long string",
		"this is a.long long long long long long long long string",
		"a",
		"a string\nwith new lines\nin it!",
		""
	};

	const std::string expected_sha256_hex_string[std::size(test_string)] =
	{
		"0f78fcc486f5315418fbf095e71c0675ee07d318e5ac4d150050cd8e57966496",
		"510d398e47ff1296ec7d9208019abfcd33bcb12fb225044d141581c70211e21b",
		"b8bb66346ee2bd6fae4a16e609caa07c3750c5b768356d879a70e5c5b21ac4dd",
		"ac9764520f736bcdc1791b195d01abad3aebc24b86e15238bb404a3022be7668",
		"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		"e4f77e8f94b9e3dd6447f6a6b24fdf121a8c205b6410ed849996085aaa922ee2",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	};

	for (std::size_t i = 0; i < std::size(test_string); ++i)
	{
		const auto sha256_result = sha256_str(test_string[i]);
		const auto sha256_result2 = sha256_str(test_string[i].begin(), test_string[i].end());
		std::cout << "          input: " << test_string[i] << '\n'
			<< "expected sha256: " << expected_sha256_hex_string[i] << '\n'
			<< "  atmiks sha256: " << sha256_result << '\n'
			<< "               : " << sha256_result2 << '\n'
			<< "ok? " << std::boolalpha << (sha256_result == expected_sha256_hex_string[i] &&
				sha256_result2 == expected_sha256_hex_string[i])
			<< "\n\n";
	}

}

void test_hotp()
{
	const std::string test_string[] =
	{
		"grape",
		"how now brown cow",
		"this is a long long long long long long long long string",
		"this is a.long long long long long long long long string",
		"a",
		"a string\nwith new lines\nin it!",
		""
	};

	const std::string expected_hotp[std::size(test_string)] =
	{
		"0f78fcc486f5315418fbf095e71c0675ee07d318e5ac4d150050cd8e57966496",
		"510d398e47ff1296ec7d9208019abfcd33bcb12fb225044d141581c70211e21b",
		"b8bb66346ee2bd6fae4a16e609caa07c3750c5b768356d879a70e5c5b21ac4dd",
		"ac9764520f736bcdc1791b195d01abad3aebc24b86e15238bb404a3022be7668",
		"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		"e4f77e8f94b9e3dd6447f6a6b24fdf121a8c205b6410ed849996085aaa922ee2",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	};

	for (std::size_t i = 0; i < std::size(test_string); ++i)
	{
		const unsigned int otp_len = 6;
		const auto hotp_result = hotp::calculate<sha256>
			(util::str_to_bytes(test_string[i]),
				util::str_to_bytes("hello"),
				otp_len);
		std::cout << "OTP for " << std::quoted(test_string[i]) << " is -> " << hotp_result << '\n';
	}
}

std::string now()
{
	const auto t = std::time(nullptr);
	std::string str = std::ctime(std::addressof(t));
	str.pop_back();
	return str;
}

void test_totp()
{
	const std::string test_string[] =
	{
		"grape",
		"how now brown cow",
		"this is a long long long long long long long long string",
		"this is a.long long long long long long long long string",
		"a",
		"a string\nwith new lines\nin it!",
		""
	};

	const auto nsteps = totp::SYS_VALID_TIME_NUM_INTERVALS + 2;

	for (const std::string& str : test_string)
	{
		static const auto asecond = std::chrono::seconds(1);
		const auto skey = util::str_to_bytes(str);
		const auto time_str = now();
		const auto otp = totp::generate<sha256>(skey);
		auto rotp = otp;
		std::reverse(rotp.begin(), rotp.end());

		std::cout << "TOTP for " << std::quoted(str) << " is -> " << otp
			<< "  (" << time_str << ")\n";

		for (std::uint64_t i = 0; i < nsteps; ++i)
		{
			std::cout << now() << "   " << otp << "  is ";
			std::cout << (totp::validate<sha256>(skey, otp) ? "valid\n" : "invalid\n");

			std::cout << now() << "   " << rotp << "  is ";
			std::cout << (totp::validate<sha256>(skey, rotp) ? "valid\n" : "invalid\n");

			std::this_thread::sleep_for(asecond);
		}

		std::cout << "\npress enter to continue: ";
		std::cin.get();
		std::cout << "\n\n";
	}
}

std::array<util::byte, 4> four_octet_encoding(std::uint32_t i)
{
	return { { util::byte(i >> 24U), util::byte(i >> 16U) ,
				util::byte(i >> 8U) , util::byte(i)} };
}

void fun(int a, double b) {}

void foo()
{
	fun(23, 56.8);
}

int main()
{
	
	//const std::size_t NUSERS = 100;
	//auto id = users::generate_random_users(NUSERS);
	users::load_users("C:\\otp\\users.txt");
	users::add_user(10101, "atmikajoy");
	std::string password = "atmikajoy"; 
	std::size_t uid = 10101; 
	std::cout<< std::boolalpha<<"Match to a user? "<<users::validate_user(uid, password);
	
	
	
	{

		auto result = pbkdf2::calculate<sha256>
			(util::str_to_bytes("this"),
			 util::str_to_bytes("fuwbiw gwirgnuiwr wgurgbe gbuiergbui"), 
		     5, 
			 6
			);
		std::cout << util::bytes_to_hex_string(result);
		return 0; 
	}
		
	for (int v : four_octet_encoding(0x12345678))
		std::cout << std::hex << v << ' ';
	    
	
	const std::size_t NUSERS = 1'000;
	auto id = users::generate_random_users(NUSERS);
	// users::save_users("C:\\otp\\users.txt");

	std::unordered_map<std::size_t, std::string > otp_map;

	using namespace std::chrono;
	std::size_t nvalid = 0;
	for (std::size_t i = id; i < (id + NUSERS); ++i)
	{
		otp_map[i] = totp::generate<sha256>(i);
	}

	//std::this_thread::sleep_for(seconds(2));
	const auto start = steady_clock::now();
	for (std::size_t i = id; i < (id + NUSERS); ++i)
		if (totp::validate<sha256>(i, otp_map[i])) ++nvalid;

	//otp.pop_back();
	//otp.push_back('0');
	//totp::validate<sha256>(i, otp);
	//++id;

	const auto end = steady_clock::now();

	const auto msecs = duration_cast<milliseconds>(end - start).count();

	std::cout << nvalid << " of " << NUSERS << " valid\n"
		<< " in " << msecs << " millisecs, "
		<< NUSERS * 1000.0 / msecs << " per second\n";
	return 0;

	std::cout << std::boolalpha << "rime in seconds? "
		<< totp::time_is_in_seconds() << '\n';

	const std::uint64_t n = 0x123456789abcdeff;
	std::cout << std::hex << n << '\n';
	std::cout << util::bytes_to_hex_string(totp::bytes_big_endian(n)) << '\n';

	return 0;

	{
		test_hotp();
		std::cin.get();
		test_totp();
		return 0;
	}

	{
		constexpr auto n = ipow(10, 6);
		for (int i = 0; i < 16; ++i) std::cout << ipow(10, i) << '\n';
		std::cout << HUGE_VAL << '\n';
		return 0;
	};

	{
		test_sha256();
		std::cin.get();
		test_hmac();
	}
#ifdef not_used
	{
		util::byte b = 123;

		unsigned int u = b & 0xff;

		b = u;
		std::cout << b << ' ' << u << '\n';
		return 0;


		for (util::byte b = 0; b <= std::numeric_limits<util::byte>::max() - 1; ++b)
		{
			unsigned int u = b;
			std::cout << std::hex << u << "  " << std::bitset<8>(u) << '\n';


		}
		return 0;
	}

	{
		//hmac_hash::test_make_key();
		//return 0;

		//secret key = hello

		return 0;
	}
	{
		while (std::cin)
		{
			const auto vec = read_numbers_from_line(std::cin);
			std::cout << "you entered " << vec.size() << " numbers [ ";
			for (int v : vec) std::cout << v << ' ';
			std::cout << "]\n";
		}
		return 0;
	}

	{
		const std::string str = "test";
		std::string_view view = str;

		util::byte_sequence bytes{ 1, 2, 3, 4, 5 };
		while (bytes.size() < 27)
		{
			bytes.push_back(util::byte(bytes.size()));
			const auto padded_b32 = util::to_padded_base32(bytes);
			std::cout << padded_b32 << ' ';
			if (util::from_padded_base32(padded_b32) == bytes) std::cout << "ok\n";
			else std::cout << "*** error ***\n";
		}

		return 0;
	}

	{
		int i = 2, j = 5;
		const int c = 8;
		// int k = 5 / MAX_OF(i + 2, j - 3); // 5 / (i+2 > j-3 ? i+2 : j-3) ;
		// MAX_OF(++i, ++j);
		(true ? i : j) = 23;

		max_of(i, c);
	}
	int n = 255;
	PRINT(n);

	int abc234 = 56;
	std::cout << CAT(abc, 234) << '\n';
	PRINT(CAT(abc, 234));
	// return 0;

	std::cout << n << '\n' // 255
		<< std::hex
		<< n << '\n' // ff
		<< std::setfill('0')
		<< std::setw(5) << n << '\n' // 000ff
		<< std::showbase
		<< std::setw(5) << n << '\n' // 00xff 
		<< std::uppercase << std::setw(5) << n << '\n'; // 00XFF

	util::byte_sequence bytes{ 0xab, 7, 36, 12 };
	for (int i = 0; i < 256; ++i) bytes.push_back(i);

	std::string str = util::bytes_to_hex_string(bytes);
	std::cout << str << '\n';
	const auto seq2 = util::hex_string_to_bytes(str);
	if (seq2 == bytes) std::cout << "ok\n";

	util::byte_sequence bytes2{ 0xab, 7, 36, 123 };
	const auto b32 = util::to_base32(bytes2);
	std::cout << b32 << '\n';
	std::cout << "\n-----------------\n";

	auto cpy = util::from_base32(b32, bytes2.size());

	const auto b32d = util::to_base32_data(bytes2);
	cpy = util::from_base32(b32d.b32_str, b32d.nbytes);

	for (int i : cpy)
	{
		std::cout << i << '\n';
	}

	std::cout << b32d.to_string() << '\n';

	const util::base32_data b32d_cpy(b32d.to_string());

	if (b32d_cpy.nbytes == b32d.nbytes && b32d_cpy.b32_str == b32d.b32_str)
		std::cout << "2. ok\n";

	if (util::from_base32_data(util::to_base32_data(bytes)) == bytes)
		std::cout << "3. ok\n";

	std::cout << "\n--------------\n";
	{
		const std::string fname = "test.txt";
		std::ofstream(fname) << "abcd \n efghij \n  klmnopqest";

		auto bytes = util::bytes_in_file(fname);
		std::cout << util::bytes_to_hex_string(bytes) << '\n';
	}


	/*
	std::string input = "grape";
	std::string output1 = sha256(input);
	std::cout << std::dec << "\nsha256 size == " << output1.size() << '\n';
	util::byte_sequence sha256_bytes = util::str_to_bytes(output1);
	std::cout << "\nsha256(" << input << "): "
		<< output1 << '\n';
			  // << util::bytes_to_hex_string(sha256_bytes) << '\n';
	// std::cout << "\nsha256(" << input << "):" << output1 << '\n';
	*/
#endif // #ifdef not_used
	return 0;

}
