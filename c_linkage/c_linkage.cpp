
int __cdecl fun(int a, double b)
{
	return a + int(b);
}

int __stdcall fun(char c) { return c; }

void fun() {}

extern "C" int cfun(int a, double b) 
{
	return a + int(b);
}

int vfun(const char* fmt, ...)
{
	return 0;
}

extern "C"
{
	// void some_function(char);
	extern int some_function;
}

#include <iostream>

int main()
{
	// some_function(23);

	// some_function = 34;
	std::cout << some_function << '\n';

	fun(12, 2.3);
	cfun(12, 2.3);

	fun('A');

	fun();
}