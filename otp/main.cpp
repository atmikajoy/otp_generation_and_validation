#include <iostream>
#include <ctime>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>
#include<cstddef>
#include <type_traits>

using byte = std::uint8_t;
using byte_seq = std::vector<byte>;
static_assert(std::is_same_v<byte, unsigned char>);

/*
std::byte b{ 33 };
auto i = std::to_integer<int>(b);
*/

byte_seq as_bytes(const std::string& str)
{
	static_assert(std::numeric_limits<unsigned char>::digits <= 8);
	return { str.begin(), str.end() };
}


int main()
{
	{
		std::uint8_t n = 0;
		using limits = std::numeric_limits< std::uint8_t>;
		std::cout << int(limits::min()) << " to " << int(limits::max()) << '\n'
			<< limits::radix << " radix " << limits::digits << " digits\n";
		return 0;
	}
	const auto N = 365 * 24 * 60 * 60.0;
	const std::time_t t = std::time(nullptr);
	std::cout << t / N << '\n';
	const std::time_t t2 = t + 5 * 60 + 30;
	std::cout << std::difftime(t2, t) << '\n';

	const int interval_secs = 5 * 60; // 5 minutes
	const int interval_number = t / interval_secs;
	std::cout << interval_number << '\n';



}