#ifndef UCE_H
#define UCE_H

#include "uce_support.h"
#include <string>
#include <netdb.h>
#include <linux/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>


const int UCE_MTU             = 9000;

const int UCE_HEADER_ETH_SIZE = sizeof(struct ethhdr);
const int UCE_HEADER_IP_SIZE  = sizeof(struct iphdr);
const int UCE_HEADER_UDP_SIZE = sizeof(struct udphdr);

const int UCE_MAX_MSG_SIZE    = UCE_MTU - (UCE_HEADER_ETH_SIZE + UCE_HEADER_IP_SIZE + UCE_HEADER_UDP_SIZE);


namespace uce
{
enum class sock_type
{
    ST_RAW,
    ST_PACKET,
};

class client
{
public:
    client(sock_type type, std::string src_address, std::string dst_address, int dst_port);
    ~client();

    int get_socket() { return m_socket; }
    struct timespec get_send_time_sw() { return m_send_time_sw; }

    int send(const void *msg, size_t size);

private:
    void prepare_header();

    int m_socket;

    sock_type m_type;
    in_addr_t m_src_address;
    in_addr_t m_dst_address;
    int m_dst_port;
    std::string m_src_interface;
    std::string m_src_mac;
    std::string m_dst_mac;

    void* m_buffer_ptr = NULL;
    struct ethhdr* m_heth_ptr = NULL;
    struct iphdr* m_hip_ptr = NULL;
    struct udphdr* m_hudp_ptr = NULL;
    size_t m_header_size;

    void* m_data_ptr = NULL;

    struct timespec m_send_time_sw;     // Seconds/Nanoseconds
};

class server
{
public:
    server(sock_type type, std::string dst_address, int dst_port);
    ~server();

    int get_socket() const { return m_socket;  }
    struct timeval get_rec_time_socket() { return m_rec_time_socket; }
    struct timespec get_rec_time_sw() { return m_rec_time_sw; }

    int receive(void *msg, size_t max_size);

private:
    int m_socket;

    sock_type m_type;
    in_addr_t m_dst_address;
    int m_dst_port;
    std::string m_dst_interface;

    struct timeval m_rec_time_socket;   // Seconds/Microseconds
    struct timespec m_rec_time_sw;      // Seconds/Nanoseconds
};

}

#endif // UCE_H
