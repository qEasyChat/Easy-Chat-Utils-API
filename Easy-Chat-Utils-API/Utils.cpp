#include "pch.h"

#define UTILS_EXPORTS
#include "Utils.h"

#include <fstream>
#include <iostream>
#include <sstream>

void Utils::memory_error()
{
	std::cerr << "MEMORY ERROR: server connection" << std::endl;
	exit(EXIT_FAILURE);
}

size_t Utils::string_to_size_t(std::string string)
{

	std::stringstream sstream(string);
	size_t result;
	sstream >> result;
	return result;
}

std::string Utils::get_query(std::string file)
{
	std::string query = "";
	std::fstream query_file(file);
	std::string line;
	while (getline(query_file, line)) {
		query += line + " ";
	}

	return query;
}

std::string Utils::replace(std::string string, std::string substring_to_replace, std::string replacement)
{

	size_t start_position = string.find(substring_to_replace);
	string.replace(start_position, substring_to_replace.length(), replacement);
	return string;
}

size_t Utils::gcd(size_t a, size_t b)
{
	size_t mod_result;
	while (true) {
		mod_result = a % b;
		if (mod_result == 0)
		{
			return b;
		}
		a = b;
		b = mod_result;
	}
}

std::string Utils::double_vector_to_string(std::vector<double> v)
{
	auto result = Utils::vector_to_string(v);
	return result;
}

std::vector<double> Utils::string_to_double_vector(std::string string)
{
	auto result = Utils::string_to_vector<double>(string);
	return result;
}
