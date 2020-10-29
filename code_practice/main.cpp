#include<iostream>
#include<string>
#include<algorithm>
int main()
{
	int i = 90034566; 
	std::string str = std::to_string(i);
	std::sort(str.begin(), str.end());
	std::string str1;
	for (auto i= str.begin(); i!= str.end(); ++i)
	{
		str1 = str;
		if (*i == '0')
		{
			str1.erase(i);
		}
	}
	std::cout << str1;
}