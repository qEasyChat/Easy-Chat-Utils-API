#pragma once
#pragma comment( lib, "ws2_32.lib")

#include <string>

#include <winsock2.h>

#include "Crypto_Manager.h"

#define BUFFER_SIZE 65536
#define SIZE_BYTES 10

#ifdef CONNECTION_EXPORTS
#define CONNECTION_API __declspec(dllexport)
#else
#define CONNECTION_API __declspec(dllimport)
#endif

class CONNECTION_API Client_Down_Exception : public std::exception {
    virtual const char* what() const throw() {
        return "Client down";
    }
};

class CONNECTION_API Bad_Socket_Exception : public std::exception {
    virtual const char* what() const throw() {
        return "Bad socket";
    }
};
class CONNECTION_API Socket_Error_Exception : public std::exception {
    virtual const char* what() const throw() {
        return "Unknown socket error";
    }
};

class CONNECTION_API Connection
{
public:
    Connection(int port_number=0, const std::string ip="", const std::string username = "Anon");
    ~Connection();
    std::string get_fixed_length_size(std::string message);
    std::string get_fixed_length_size(std::vector<char> data);

    void send_message(std::string message);
    std::string recive_message();

    void send_message(std::vector<unsigned char> data);
    std::vector<unsigned char> recive_bytes();

    SOCKET get_socket();
    void set_socket(SOCKET socket);

    int get_port_number();


    void set_port_number(int port_number);

    std::string get_username();
    void set_username(std::string username);

	std::string get_ip();
    void set_ip(std::string ip);

    class Message_Not_Sent_Exception : public std::exception {
        virtual const char* what() const throw() {
            return "Message was not sent";
        }
    };

private:
    const size_t MESSAGE_BEGIN_SIZE = 5;
    const std::string MESSAGE_BEGIN_CHECK = "BEGIN";
    const std::string HEADER_NOT_FOUND_MESSAGE = "HEADER NOT FOUND";
    const size_t MESSAGE_END_SIZE = 3;
    const std::string MESSAGE_END_CHECK = "END";
    const std::string ENDING_NOT_FOUND_MESSAGE = "ENDING NOT FOUND";

    int port_number;

    std::string username;
    std::string ip;

	SOCKET sock;

    Crypto_Manager crypto_manager;

	size_t get_size_from(std::string fixed_length_string);
    std::string get_message(size_t size);
    std::vector<unsigned char> get_bytes(size_t size);
    int socket_init();
    int socket_close();
    int socket_quit();
    bool socket_check();

    std::string encrypt_message(std::string message);
    std::string decrypt_message(std::string package);
};

