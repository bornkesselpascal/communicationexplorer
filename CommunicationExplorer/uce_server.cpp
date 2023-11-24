#include "uce.h"
#include <arpa/inet.h>
#include <cstring>
#include <netinet/ether.h>
#include <stdexcept>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <linux/sockios.h>


uce::server::server(sock_type type, std::string dst_address, int dst_port)
    : m_type(type)
    , m_dst_address(inet_addr(dst_address.c_str()))
    , m_dst_port(dst_port)
    , m_dst_interface(uce::support::get_interface_from_ip(dst_address))
{
    // Create the socket.
    switch(m_type)
    {
    case sock_type::ST_PACKET:
        m_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
        break;
    case sock_type::ST_RAW:
        m_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        break;
    }
    if(m_socket < 0)
    {
        throw std::runtime_error("[uce_s] E01 - Could not create socket.");
    }

    // Bind the socket to an network interface.
    switch(m_type)
    {
    case sock_type::ST_PACKET:
        // Get index number of interface.
        struct ifreq ifr;
        strncpy(ifr.ifr_name, m_dst_interface.c_str(), sizeof(ifr.ifr_name));
        if(ioctl(m_socket, SIOCGIFINDEX, &ifr) != 0)
        {
            throw std::runtime_error("[uce_s] E02 - Could not get interface index number for " + m_dst_interface + ".");
        }

        // Bind interface to socket.
        struct sockaddr_ll sock_addr;
        memset(&sock_addr, 0, sizeof(struct sockaddr_ll));
        sock_addr.sll_family = AF_PACKET;           // link layer address family
        sock_addr.sll_ifindex = ifr.ifr_ifindex;    // interface index number
        if (0 != bind(m_socket, (struct sockaddr*) &sock_addr, sizeof(sock_addr)))
        {
            throw std::runtime_error("[uce_s] E02 - Could not bind socket.");
        }
        break;
    case sock_type::ST_RAW:
        struct sockaddr_in src_info;
        src_info.sin_family = AF_INET;
        src_info.sin_addr.s_addr = m_dst_address;
        src_info.sin_port = htons(m_dst_port);

        if (0 != bind(m_socket, (struct sockaddr*) &src_info, sizeof(src_info)))
        {
            throw std::runtime_error("[uce_s] E02 - Could not bind socket.");
        }
        break;
    }
}

uce::server::~server()
{
    close(m_socket);
}

int uce::server::receive(void *msg, size_t max_size)
{
    struct iphdr* hip_ptr;
    struct udphdr* hudp_ptr;
    switch(m_type)
    {
    case sock_type::ST_PACKET:
        hip_ptr  = (struct iphdr*) ((char*) msg + UCE_HEADER_ETH_SIZE);
        hudp_ptr = (struct udphdr*) ((char *) msg + UCE_HEADER_ETH_SIZE + UCE_HEADER_IP_SIZE);
        break;
    case sock_type::ST_RAW:
        hip_ptr  = (struct iphdr*) msg;
        hudp_ptr = (struct udphdr*) ((char *) msg + UCE_HEADER_IP_SIZE);
        break;
    }

    while(true)
    {
        int bytes = ::recv(m_socket, msg, max_size, 0);
        clock_gettime(CLOCK_MONOTONIC, &m_rec_time_sw);
        if (-1 == bytes)
        {
            return bytes;
        }

        // Check if the recieved message is an UDP message.
        if (IPPROTO_UDP != hip_ptr->protocol)
        {
            continue;
        }

        // Check if the destination port matches.
        if (m_dst_port != ntohs(hudp_ptr->dest))
        {
            continue;
        }

        // Get receive time.
        //    - Returns the receive timestamp of the last packet passed to user.
        ioctl(m_socket, SIOCGSTAMP, &m_rec_time_socket);

        return bytes;
    }
}
