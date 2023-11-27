#include "uce.h"
#include <arpa/inet.h>
#include <cstring>
#include <netinet/ether.h>
#include <stdexcept>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <unistd.h>


uce::client::client(sock_type type, std::string src_address, std::string dst_address, int dst_port)
    : m_type(type)
    , m_src_address(inet_addr(src_address.c_str()))
    , m_dst_address(inet_addr(dst_address.c_str()))
    , m_dst_port(dst_port)
    , m_src_interface(uce::support::get_interface_from_ip(src_address))
{
    if(m_type == sock_type::ST_PACKET)
    {
        m_src_mac = uce::support::get_mac_from_interface(m_src_interface);
        m_dst_mac = uce::support::get_mac_from_ip(src_address, dst_address, m_src_interface);
    }

    m_buffer_ptr = malloc(UCE_MTU);
    if(NULL == m_buffer_ptr) {
        throw std::runtime_error("[uce_c] E01 - Could not allocate buffer.");
    }
    memset(m_buffer_ptr, 0, UCE_MTU);

    // Prepares the required headers. Sets the pointer to the headers and the data. Calculates header size for application.
    prepare_header();


    // Create the socket.
    switch(m_type)
    {
    case sock_type::ST_PACKET:
        m_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
        break;
    case sock_type::ST_RAW:
        m_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        break;
    }
    if(m_socket < 0)
    {
        throw std::runtime_error("[uce_c] E02 - Could not create socket.");
    }


    // Bind (and connect) the socket. Defines the source (and destination) address.
    switch(m_type)
    {
    case sock_type::ST_PACKET:
        // NOTE: To bind the socket to an interface, the index number of the interface is required.

        // Get index number of interface.
        struct ifreq ifr;
        strncpy(ifr.ifr_name, m_src_interface.c_str(), sizeof(ifr.ifr_name));
        if(ioctl(m_socket, SIOCGIFINDEX, &ifr) != 0)
        {
            throw std::runtime_error("[uce_c] E03 - Could not get interface index number for " + m_src_interface + ".");
        }

        // Bind interface to socket.
        struct sockaddr_ll sock_addr;
        memset(&sock_addr, 0, sizeof(struct sockaddr_ll));
        sock_addr.sll_family = AF_PACKET;           // link layer address family
        sock_addr.sll_ifindex = ifr.ifr_ifindex;    // interface index number
        if (0 != bind(m_socket, (struct sockaddr*) &sock_addr, sizeof(sock_addr)))
        {
            throw std::runtime_error("[uce_c] E03 - Could not bind socket.");
        }
        break;
    case sock_type::ST_RAW:
        struct sockaddr_in src_info;
        src_info.sin_family = AF_INET;
        src_info.sin_addr.s_addr = m_src_address;
        src_info.sin_port = htons(0);

        if (0 != bind(m_socket, (struct sockaddr*) &src_info, sizeof(src_info)))
        {
            throw std::runtime_error("[uce_c] E03 - Could not bind socket.");
        }

        struct sockaddr_in dest_info;
        dest_info.sin_family = AF_INET;
        dest_info.sin_addr.s_addr = m_dst_address;
        dest_info.sin_port = htons(m_dst_port);

        if (0 != connect(m_socket, (struct sockaddr*) &dest_info, sizeof(dest_info)))
        {
            throw std::runtime_error("[uce_c] E03 - Could not connect socket.");
        }
        break;
    }
}

uce::client::~client()
{
    close(m_socket);
    free(m_buffer_ptr);
}

void uce::client::prepare_header()
{
    // NOTE: This function assumes that the buffers are allocated and filled with 0.

    if(m_type == sock_type::ST_PACKET)
    {
        m_heth_ptr = (struct ethhdr*) m_buffer_ptr;
        m_hip_ptr  = (struct iphdr*) ((char *) m_buffer_ptr + UCE_HEADER_ETH_SIZE);
        m_hudp_ptr = (struct udphdr*) ((char *) m_buffer_ptr + UCE_HEADER_ETH_SIZE + UCE_HEADER_IP_SIZE);
        m_header_size = UCE_HEADER_ETH_SIZE + UCE_HEADER_IP_SIZE + UCE_HEADER_UDP_SIZE;

        m_data_ptr = ((char *) m_buffer_ptr + m_header_size);
    }
    else if(m_type == sock_type::ST_RAW)
    {
        m_hip_ptr  = (struct iphdr*) m_buffer_ptr;
        m_hudp_ptr = (struct udphdr*) ((char *) m_buffer_ptr + UCE_HEADER_IP_SIZE);
        m_header_size = UCE_HEADER_IP_SIZE + UCE_HEADER_UDP_SIZE;

        m_data_ptr = ((char *) m_buffer_ptr + m_header_size);
    }


    if(m_type == sock_type::ST_PACKET)
    {
        memcpy(m_heth_ptr->h_source, (u_char *)ether_aton(m_src_mac.c_str()), ETHER_ADDR_LEN);
        memcpy(m_heth_ptr->h_dest, (u_char *)ether_aton(m_dst_mac.c_str()), ETHER_ADDR_LEN);
        m_heth_ptr->h_proto = htons(ETHERTYPE_IP);
    }

    m_hip_ptr->version = 4;              // IPv4
    m_hip_ptr->ihl = 5;                  // IP header lenght
    m_hip_ptr->id = 0;                   // ID (NOTE: Not required, we do not fragment packets here.)
    m_hip_ptr->ttl = 255;
    m_hip_ptr->protocol = IPPROTO_UDP;   // UDP protocol
    m_hip_ptr->saddr = m_src_address;    // Sender IP
    m_hip_ptr->daddr = m_dst_address;    // Receiver IP
    m_hip_ptr->check = 0;                // Cecksum (RAW: calculated by kernel / PACKET: no checksum)

    m_hudp_ptr->source = htons(0);       // NOTE: Source port is optional according to RFC 768.
    m_hudp_ptr->dest = htons(m_dst_port);
    m_hudp_ptr->check = 0;               // Checksum (NOTE: Not required according to RFC 768.)
}

bool uce::client::enable_timestamps(timestamp_mode mode)
{
    switch (mode) {
    case timestamp_mode::TSTMP_SW:
        // On the client site there is nothing to enable/initialize.
        client_timestamps.enabled = true;
        return true;
    case timestamp_mode::TSTMP_ALL:
        // This is not supported.
        return false;
    }

    return false;
}

int uce::client::send(const void *msg, size_t size)
{
    if (size > UCE_MAX_MSG_SIZE)
    {
        throw std::runtime_error("[ce_raw_c] E05 - Message size larger than maximum size.");
    }

    memcpy(m_data_ptr, msg, size);

    m_hip_ptr->tot_len = htons(UCE_HEADER_IP_SIZE + UCE_HEADER_UDP_SIZE + size);
    m_hudp_ptr->len    = htons(UCE_HEADER_UDP_SIZE + size);

    if (client_timestamps.enabled) clock_gettime(CLOCK_REALTIME, &(client_timestamps.m_snt_program));
    return ::send(m_socket, m_buffer_ptr, m_header_size + size, 0);
}
