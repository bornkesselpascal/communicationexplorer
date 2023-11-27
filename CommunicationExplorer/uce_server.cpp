#include "uce.h"
#include <arpa/inet.h>
#include <cstring>
#include <linux/net_tstamp.h>
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
        throw std::runtime_error("[uce_s] E02 - Could not create socket.");
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
            throw std::runtime_error("[uce_s] E03 - Could not get interface index number for " + m_dst_interface + ".");
        }

        // Bind interface to socket.
        struct sockaddr_ll sock_addr;
        memset(&sock_addr, 0, sizeof(struct sockaddr_ll));
        sock_addr.sll_family = AF_PACKET;           // link layer address family
        sock_addr.sll_ifindex = ifr.ifr_ifindex;    // interface index number
        if (0 != bind(m_socket, (struct sockaddr*) &sock_addr, sizeof(sock_addr)))
        {
            throw std::runtime_error("[uce_s] E03 - Could not bind socket.");
        }
        break;
    case sock_type::ST_RAW:
        struct sockaddr_in src_info;
        src_info.sin_family = AF_INET;
        src_info.sin_addr.s_addr = m_dst_address;
        src_info.sin_port = htons(m_dst_port);

        if (0 != bind(m_socket, (struct sockaddr*) &src_info, sizeof(src_info)))
        {
            throw std::runtime_error("[uce_s] E03 - Could not bind socket.");
        }
        break;
    }

    // Initialize reseive datastructures.
    memset(&(m_receive_helper.iov), 0, sizeof(struct iovec));
    memset(&(m_receive_helper.msh), 0, sizeof(struct msghdr));

    m_receive_helper.msh.msg_iov = &(m_receive_helper.iov);
    m_receive_helper.msh.msg_iovlen = 1;
    m_receive_helper.msh.msg_namelen = sizeof(struct sockaddr_in);
    m_receive_helper.msh.msg_control = m_receive_helper.control_buffer;
    m_receive_helper.msh.msg_controllen = sizeof(m_receive_helper.control_buffer);
}

uce::server::~server()
{
    close(m_socket);
}

bool uce::server::enable_timestamps(timestamp_mode mode)
{
    switch (mode) {
    case timestamp_mode::TSTMP_SW:
    {
        // Enable software timestamping.
        int flags = SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;
        if (setsockopt(m_socket, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) < 0)
        {
            return false;
        }

        server_timestamps.enabled = true;
        return true;
    }
    case timestamp_mode::TSTMP_ALL:
    {
        // Enable hardware timestamping on the interface.
        // NOTE: Intel X710 and Intel X540/X520 do not support timestamping of incoming packets.
        struct ifreq ifr;
        struct hwtstamp_config hwconfig;

        memset(&ifr, 0, sizeof(ifr));
        memset(&hwconfig, 0, sizeof(hwconfig));

        strncpy(ifr.ifr_name, m_dst_interface.c_str(), sizeof(ifr.ifr_name));
        hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;
        ifr.ifr_data = reinterpret_cast<char*>(&hwconfig);

        if (ioctl(m_socket, SIOCSHWTSTAMP, &ifr) < 0)
        {
            return false;
        }

        // Enable hardware and software timestamping.
        int flags = SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
        if (setsockopt(m_socket, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) < 0)
        {
            return false;
        }

        server_timestamps.enabled = true;
        return true;
    }
    }

    return false;
}

int uce::server::receive(void *msg, size_t max_size)
{
    m_receive_helper.iov.iov_base = msg;
    m_receive_helper.iov.iov_len = max_size;

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
        int bytes = ::recvmsg(m_socket, &(m_receive_helper.msh), 0);
        if (-1 == bytes)
        {
            return bytes;
        }

        // Check if the recieved message is an UDP message.
        if (IPPROTO_UDP != hip_ptr->protocol)
        {
            continue;
        }

        // Get program timestamp.
        if (server_timestamps.enabled) clock_gettime(CLOCK_REALTIME, &(server_timestamps.m_rec_program));

        // Check if the destination port matches.
        if (m_dst_port != ntohs(hudp_ptr->dest))
        {
            continue;
        }

        // Process ancillary data to extract sw/hw timestamps.
        if(server_timestamps.enabled)
        {
            struct cmsghdr *cmsg;
            for (cmsg = CMSG_FIRSTHDR(&(m_receive_helper.msh)); cmsg != NULL; cmsg = CMSG_NXTHDR(&(m_receive_helper.msh), cmsg))
            {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING)
                {
                    struct timespec *timestamps = (struct timespec *) CMSG_DATA(cmsg);
                    server_timestamps.m_rec_sw = timestamps[0]; // software timestamp
                    server_timestamps.m_rec_hw = timestamps[2]; // hardware timestamp
                }
            }
        }

        return bytes;
    }
}
