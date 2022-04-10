#include "pch.h"
#include "Connection.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "Crypto_Manager.h"
#include "Utils.h"

Connection::Connection(int port_number, const std::string ip, const std::string username)
    : port_number(port_number),
    username(username),
    ip(ip)
{
    if (socket_init() != 0) {
        std::cerr << ("socket init failed") << std::endl;
    }
    this->sock = socket(AF_INET, SOCK_STREAM, 0);
}

Connection::~Connection()
{
    socket_close();
    this->sock = 0;
    this->username = "";
    this->port_number = 0;
}

std::string Connection::get_fixed_length_size(std::string message)
{
	std::stringstream stream;
	stream << std::setw(SIZE_BYTES) << std::setfill('0') << message.size();
	std::string size = stream.str();
	return size;
}

std::string Connection::get_fixed_length_size(std::vector<char> data)
{
    std::stringstream stream;
    stream << std::setw(SIZE_BYTES) << std::setfill('0') << data.size();
    std::string size = stream.str();
    return size;
}


void Connection::send_message(std::string message)
{

    std::cout << "SENT MESSAGE" << std::endl;
    std::cout << message << std::endl;
    message = encrypt_message(message);
    std::string encapsulated_string = get_fixed_length_size(message) + message;
    encapsulated_string = MESSAGE_BEGIN_CHECK + encapsulated_string + MESSAGE_END_CHECK;
	size_t total_bytes_sent = 0;
    size_t bytes_sent = 0;	std::ifstream file("file_path", std::ios::binary);

    std::vector<char> data = std::vector<char>(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());

    while (total_bytes_sent < encapsulated_string.size()) {
        std::string message_left = encapsulated_string.substr(bytes_sent);
        bytes_sent = send(this->sock, data.data(), message_left.size(), 0);
        total_bytes_sent += bytes_sent;
        if (bytes_sent < 0) {
            throw Message_Not_Sent_Exception();
        }
    }

    std::cout << message << std::endl;
}

std::string Connection::recive_message()
{
    std::cout << "RECIVED MESSAGE" << std::endl;
    std::string message = "";
    std::string header = get_message(MESSAGE_BEGIN_SIZE);
    if (header != MESSAGE_BEGIN_CHECK)
    {
        return HEADER_NOT_FOUND_MESSAGE;
    }

    std::string recv_string = get_message(SIZE_BYTES);
    size_t message_size = get_size_from(recv_string);
    if (message_size > 0) {
        message = get_message(message_size);
    } else
    {
        throw Client_Down_Exception();
    }
    std::string ending = get_message(MESSAGE_END_SIZE);
    if (ending != MESSAGE_END_CHECK)
    {
        return ENDING_NOT_FOUND_MESSAGE;
    }
    std::string decrypted_message = decrypt_message(message);
    std::cout << decrypted_message << std::endl;
    return decrypted_message;
}

void Connection::send_message(std::vector<char> data)
{
    std::cout << "SENDING DATA" << std::endl;
    std::cout << data.data() << std::endl;
    send_message(std::to_string(data.size()));

    size_t bytes_sent = 0;

    while (!data.empty()) {
        data.erase(data.begin(), data.begin() + bytes_sent);
        bytes_sent = send(this->sock, data.data(), data.size(), 0);
        if (bytes_sent < 0) {
            throw Message_Not_Sent_Exception();
        }
    }
}

std::vector<char> Connection::recive_bytes()
{
    std::cout << "RECIVED DATA" << std::endl;
    std::vector<char> data;

    std::string data_size_str = recive_message();
    size_t data_size = std::stoi(data_size_str);


    std::string recv_string = get_message(SIZE_BYTES);
    size_t message_size = get_size_from(recv_string);
    if (message_size > 0) {
        message = get_message(message_size);
    }
    else
    {
        throw Client_Down_Exception();
    }
    std::string ending = get_message(MESSAGE_END_SIZE);
    if (ending != MESSAGE_END_CHECK)
    {
        return ENDING_NOT_FOUND_MESSAGE;
    }
    std::string decrypted_message = decrypt_message(message);
    std::cout << decrypted_message << std::endl;
    return decrypted_message;
}


size_t Connection::get_size_from(std::string fixed_length_string)
{
    fixed_length_string.erase(0, std::min(fixed_length_string.find_first_not_of('0'), fixed_length_string.size() - 1));
    size_t size;
    if (fixed_length_string.size() < 1) {
        return 0;
    }
    try {
        size = std::stol(fixed_length_string);
    }
    catch (const std::exception& e) {
        std::cerr << "connection: " << e.what() << " " << fixed_length_string << '\n';
    }
    return size;
}

std::string Connection::get_message(size_t size)
{
    std::string message = "";
    std::unique_ptr<char[]> buffer(new char[BUFFER_SIZE]);
    size_t bytes_recived = 0;
    while (bytes_recived < size) {
        memset(buffer.get(), '\0', BUFFER_SIZE);
        size_t len = recv(this->sock, buffer.get(), size - bytes_recived, 0);
        if (len < 0) {
            throw Socket_Error_Exception();
        }
        if (len == 0) {
            throw Client_Down_Exception();
        }
        std::string recived_message = std::string(buffer.get());
        message += recived_message;
        bytes_recived += len;
    }
    return message;

}

std::vector<char> Connection::get_bytes(size_t size)
{
    std::vector<char> data;
    std::unique_ptr<char[]> buffer(new char[BUFFER_SIZE]);
    size_t bytes_recived = 0;
    while (bytes_recived < size) {
        memset(buffer.get(), '\0', BUFFER_SIZE);
        size_t len = recv(this->sock, buffer.get(), size - bytes_recived, 0);
        if (len < 0) {
            throw Socket_Error_Exception();
        }
        if (len == 0) {
            throw Client_Down_Exception();
        }
        auto buffer_array = buffer.get();
        data.insert(data.end(), &buffer_array[0], &buffer_array[bytes_recived]);
        bytes_recived += len;
    }
    return data;
}


int Connection::socket_init() {
    WSADATA wsa_data;
    return WSAStartup(MAKEWORD(1, 1), &wsa_data);
}

int Connection::socket_close() {
    int status = 0;
    status = shutdown(this->sock, SD_BOTH);
    if (status == 0) {
        status = closesocket(this->sock);
    }
    return status;
}

int Connection::socket_quit() {
    return WSACleanup();
}

bool Connection::socket_check() {
    if (this->sock == INVALID_SOCKET) {
        return false;
    }
    return true;
}

SOCKET Connection::get_socket()
{
	return this->sock;
}

void Connection::set_socket(SOCKET socket)
{
	this->sock = socket;
    if (!socket_check()) {
        socket_close();
        socket_quit();
        throw Bad_Socket_Exception();
    }
}

int Connection::get_port_number()
{
	return this->port_number;
}

void Connection::set_port_number(int port_number)
{
	this->port_number = port_number;
}

std::string Connection::get_username()
{
	return this->username;
}

void Connection::set_username(std::string username)
{
	this->username = username;
}

std::string Connection::get_ip()
{
    return this->ip;
}

void Connection::set_ip(std::string ip)
{
    this->ip= ip;
}

std::string Connection::encrypt_message(std::string message)
{
    std::vector<double> encryption = crypto_manager.rsa_encrypt(message);
    std::string encryption_string = Utils::vector_to_string(encryption);
	return encryption_string;
}

std::string Connection::decrypt_message(std::string package)
{
    std::vector<double> encrypted_message = Utils::string_to_vector<double>(package);
    std::string decrypted_message = crypto_manager.rsa_decrypt(encrypted_message);
    return decrypted_message;
}