#include "communication.h"

#include <arpa/inet.h>
#include <stdexcept>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

ce::raw::client::client(const std::string &src_address, const std::string &dest_address, size_t max_size)
    : m_max_size(max_size)
{
    int max_packet_size = sizeof(struct iphdr) + max_size;
    m_buffer_ptr = malloc(max_packet_size);
    if (NULL == m_buffer_ptr) {
        throw std::runtime_error("[ce_raw_c] E01 - Could not allocate buffer.");
    }
    memset(&m_buffer_ptr, 0, sizeof(struct iphdr) + max_size);

    m_ip_ptr = (struct iphdr*) m_buffer_ptr;
    m_ip_ptr->version = 4;                        // IPv4
    m_ip_ptr->ihl = 5;                            // IP-Header Länge
    m_ip_ptr->id = 0;                             // ID (set by the Kernel)
    m_ip_ptr->ttl = 255;
    m_ip_ptr->protocol = IPPROTO_UDP;             // UDP
    m_ip_ptr->saddr = inet_addr(src_address.c_str());     // Sender IP
    m_ip_ptr->saddr = inet_addr(dest_address.c_str());    // Receiver IP
    m_ip_ptr->check = 0;                          // Checksum (calculated by kernel)

    m_data_ptr = (m_buffer_ptr + sizeof(struct iphdr));

    m_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(m_socket < 0) {
        throw std::runtime_error("[ce_raw_c] E02 - Could not create socket.");
    }

    struct sockaddr_in src_info;
    src_info.sin_family = AF_INET;
    src_info.sin_addr.s_addr = inet_addr(src_address.c_str());
    src_info.sin_port = htons(0);

    // bind socket - define source address, define network interface
    if (0 != bind(m_socket, (struct sockaddr*) &src_info, sizeof(src_info)))
    {
        throw std::runtime_error("[ce_raw_c] E03 - Could not bind socket.");
    }

    struct sockaddr_in dest_info;
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr.s_addr = inet_addr(dest_address.c_str());
    dest_info.sin_port = htons(0);

    // connect socket - define destination address
    if (0 != connect(m_socket, (struct sockaddr*) &src_info, sizeof(src_info)))
    {
        throw std::runtime_error("[ce_raw_c] E04 - Could not connect socket.");
    }
}

ce::raw::client::~client()
{
    close(m_socket);
    free(m_buffer_ptr);
}

int ce::raw::client::send(const void *msg, size_t size)
{
    if (size > m_max_size)
    {
        throw std::runtime_error("[ce_raw_c] E05 - Message size larger than maximum size.");
    }

    memcpy(m_data_ptr, msg, size);

    m_ip_ptr->tot_len = htons(sizeof(struct iphdr) + size);

    return ::send(m_socket, m_buffer_ptr, sizeof(struct iphdr) + size, 0);
}


ce::raw::server::server(const std::string &dest_address)
{
    // Raw socket can oly receive packets from a specific protocol.
    m_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if(m_socket < 0) {
        throw std::runtime_error("[ce_raw_s] E01 - Could not create socket.");
    }

    struct sockaddr_in src_info;
    src_info.sin_family = AF_INET;
    src_info.sin_addr.s_addr = inet_addr(dest_address.c_str());
    src_info.sin_port = htons(0);

    // bind socket - define source address, define network interface
    if (0 != bind(m_socket, (struct sockaddr*) &src_info, sizeof(src_info)))
    {
        throw std::runtime_error("[ce_raw_c] E03 - Could not bind socket.");
    }
}

ce::raw::server::~server()
{
    close(m_socket);
}

int ce::raw::server::receive(void *msg, size_t max_size)
{
    // The current implementation returns the IP Header. This is different that the client implementation.
    return ::recv(m_socket, msg, max_size, 0);
}
