#include "communication.h"
#include <poll.h>
#include <stdexcept>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>



ce::udp::client::client(const std::string& dest_address, int dest_port)
    : m_address(dest_address)
    , m_port(dest_port)
{
    char decimal_port[16];
    snprintf(decimal_port, sizeof(decimal_port), "%d", m_port);
    decimal_port[sizeof(decimal_port) / sizeof(decimal_port[0]) - 1] = '\0';

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    int r = getaddrinfo(m_address.c_str(), decimal_port, &hints, &m_addrinfo);
    if(r != 0 || m_addrinfo == 0) {
        throw std::runtime_error("[ce_udp_c] E01 - Invalid address (" + m_address + ") or socket (" + std::to_string(m_socket) + ").");
    }

    m_socket = socket(m_addrinfo->ai_family, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
    if(m_socket == -1) {
        freeaddrinfo(m_addrinfo);
        throw std::runtime_error("[ce_udp_c] E02 - Could not create socket for " + m_address + ":" + std::to_string(m_port) + ".");
    }
}

ce::udp::client::~client()
{
    freeaddrinfo(m_addrinfo);
    close(m_socket);
}

int ce::udp::client::send(const void *msg, size_t size)
{
    return sendto(m_socket, msg, size, 0, m_addrinfo->ai_addr, m_addrinfo->ai_addrlen);
}

void ce::udp::client::set_dscp(int value)
{
    if ((value < 0) || (value > 63)) {
        throw std::runtime_error("[ce_udp_c] E03 - Invalid DSCP value: " + std::to_string(value) + ".");
    }

    int dscp_val = value << 2;
    if(setsockopt(m_socket, IPPROTO_IP, IP_TOS, &dscp_val, sizeof(dscp_val)) < 0) {
        throw std::runtime_error("[ce_udp_c] E04 - Could not set DSCP for " + m_address + ":" + std::to_string(m_port) + ".");
    }
}


ce::udp::server::server(const std::string& dest_address, int dest_port)
    : m_address(dest_address)
    , m_port(dest_port)
{
    char decimal_port[16];
    snprintf(decimal_port, sizeof(decimal_port), "%d", m_port);
    decimal_port[sizeof(decimal_port) / sizeof(decimal_port[0]) - 1] = '\0';

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    int r = getaddrinfo(m_address.c_str(), decimal_port, &hints, &m_addrinfo);
    if(r != 0 || m_addrinfo == NULL) {
        throw std::runtime_error("[ce_udp_s] E01 -  Invalid address (" + m_address + ") or socket (" + std::to_string(m_socket) + ").");
    }

    m_socket = socket(m_addrinfo->ai_family, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
    if(m_socket == -1)
    {
        freeaddrinfo(m_addrinfo);
        throw std::runtime_error("[ce_udp_s] E02 - Could not create socket for " + m_address + ":" + std::to_string(m_port) + ".");
    }

    // SO_RCVBUF (intentionally left out)

    r = bind(m_socket, m_addrinfo->ai_addr, m_addrinfo->ai_addrlen);
    if(r != 0)
    {
        freeaddrinfo(m_addrinfo);
        close(m_socket);
        throw std::runtime_error("[ce_udp_s] E05 - Could not bind socket with " + m_address + ":" + std::to_string(m_socket) + ".");
    }
}

ce::udp::server::~server()
{
    freeaddrinfo(m_addrinfo);
    close(m_socket);
}

int ce::udp::server::receive(void *msg, size_t max_size, int timeout)
{
    // NOTE: The timeout is specified in ms.

    if(timeout == -1)
    {
        return recv(m_socket, msg, max_size, 0);
    }
    else
    {
        struct pollfd fd;
        int res;

        fd.fd = m_socket;
        fd.events = POLLIN;
        res = ::poll(&fd, 1, timeout);

        if(0 == res || -1 == res) {
            return -2; // timeout
        }
        else if(-1 == res) {
            return -1; // error
        }
        else {
            return recv(m_socket, msg, max_size, 0);
        }
    }
}
