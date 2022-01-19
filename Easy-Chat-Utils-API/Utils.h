#pragma once
#include <sstream>
#include <string>
#include <vector>

#ifdef UTILS_EXPORTS
#define UTILS_API __declspec(dllexport)
#else
#define UTILS_API __declspec(dllimport)
#endif

namespace Utils
{
	void UTILS_API memory_error();

	size_t UTILS_API string_to_size_t(std::string string);
	size_t UTILS_API gcd(size_t a, size_t b);

	std::string UTILS_API get_query(std::string file);

	std::string UTILS_API replace(std::string string, std::string substring_to_replace, std::string replacement);


	std::string UTILS_API double_vector_to_string(std::vector<double> v);
	std::vector<double> UTILS_API string_to_double_vector(std::string string);

	template <class T>
	std::string vector_to_string(std::vector<T> v)
	{
		std::stringstream string_stream;
		std::copy(v.begin(), v.end(), std::ostream_iterator<T>(string_stream, " "));
		std::string result = string_stream.str();
		return result;
	}

	template <class T>
	std::vector<T> string_to_vector(std::string str)
	{
		std::vector<T> result;
		std::stringstream stream(str);
		T element;
		while (stream >> element)
		{
			result.push_back(element);
		}
		return result;
	}
}
