#include "pch.h"

#include "Crypto_Manager.h"

#include <cmath>

#include <sstream>
#include <iomanip>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "Utils.h"

Crypto_Manager::Crypto_Manager()
{
    do
    {
        this->p = get_random_prime();
    } while (this->p == Crypto_Manager::E);
    do
    {
        this->q = get_random_prime();
    } while (this->q == Crypto_Manager::E);
    this->n = p * q;
    this->phi = (p - 1) * (q - 1);
}

std::string Crypto_Manager::bytes_to_hex_string(const std::vector<uint8_t>& bytes)
{
    std::ostringstream stream;
    for (uint8_t b : bytes)
    {
        stream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(b);
    }
    return stream.str();
}

std::string Crypto_Manager::get_sha3_512_hash(std::string input)
{
    uint32_t digest_length = SHA512_DIGEST_LENGTH;
    const EVP_MD* algorithm = EVP_sha3_512();
    uint8_t* digest = static_cast<uint8_t*>(OPENSSL_malloc(digest_length));
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, algorithm, nullptr);
    EVP_DigestUpdate(context, input.c_str(), input.size());
    EVP_DigestFinal_ex(context, digest, &digest_length);
    EVP_MD_CTX_destroy(context);
    std::string output = Crypto_Manager::bytes_to_hex_string(std::vector<uint8_t>(digest, digest + digest_length));
    OPENSSL_free(digest);
    return output;
}

double Crypto_Manager::rsa_encrypt_char(char c)
{
    double message = static_cast<double>(c);
    double encrypted = pow(message, Crypto_Manager::E);
    return encrypted;
}

char Crypto_Manager::rsa_decrypt_char(double encrypted)
{
    double d1 = 1 / Crypto_Manager::E;
    double d = fmod(d1, Crypto_Manager::phi);
    double decrypted = pow(encrypted, d);
    decrypted = fmod(decrypted, Crypto_Manager::n);
    char c = static_cast<char>(round(decrypted));
    return c;
}

std::vector<double> Crypto_Manager::rsa_encrypt(std::string message)
{
    std::vector<double> encryption;
	for (auto c: message)
	{
        double encrypted_char = Crypto_Manager::rsa_encrypt_char(c);
        encryption.push_back(encrypted_char);
	}
    return encryption;
}

std::string Crypto_Manager::rsa_decrypt(std::vector<double> encrypted_message)
{
    std::string message = "";
    for (auto encrypted_char : encrypted_message)
    {
        char decrypted_char = Crypto_Manager::rsa_decrypt_char(encrypted_char);
        message += decrypted_char;
    }
    return  message;
}

double Crypto_Manager::get_random_prime()
{
    BIGNUM* bignum;
    bignum = BN_new();
    BN_generate_prime_ex(bignum, RSA_PRIVATE_KEY_SIZE, 0, NULL, NULL, NULL);
    char* bignum_char = BN_bn2dec(bignum);
    double prime = std::stod(bignum_char);
    BN_free(bignum);
    return prime;
}
