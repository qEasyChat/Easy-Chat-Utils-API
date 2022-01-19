#pragma once
#include <string>
#include <vector>

#ifdef CRYTPO_MANAGER_EXPORTS
#define CRYTPO_MANAGER_API __declspec(dllexport)
#else
#define CRYTPO_MANAGER_API __declspec(dllimport)
#endif


class CRYTPO_MANAGER_API Crypto_Manager
{
public:
	Crypto_Manager();
	std::string get_sha3_512_hash(std::string message);
	std::string rsa_decrypt(std::vector<double> encrypted_message);
	std::vector<double> rsa_encrypt(std::string message);


private:
	const double E = 7;
	const char* RANDOM_SEED = "SEED";
	const size_t RSA_PRIVATE_KEY_SIZE = 10;

	double p;
	double q;
	double n;
	double phi;

	double rsa_encrypt_char(char c);
	char rsa_decrypt_char(double encrypted);
	double get_random_prime();
	std::string bytes_to_hex_string(const std::vector<uint8_t>& bytes);
};

