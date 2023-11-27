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
enum class timestamp_mode
{
    TSTMP_SW,
    TSTMP_ALL,
};

class client
{
public:
    client(sock_type type, std::string src_address, std::string dst_address, int dst_port);
    ~client();

    int  get_socket() { return m_socket; }
    bool enable_timestamps(timestamp_mode mode);
    int  send(const void *msg, size_t size);

    struct client_timestamps {
        bool enabled = false;
        struct timespec m_snt_program;
    } client_timestamps ;

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
};

class server
{
public:
    server(sock_type type, std::string dst_address, int dst_port);
    ~server();

    int  get_socket() const { return m_socket; }
    bool enable_timestamps(timestamp_mode mode);
    int  receive(void *msg, size_t max_size);

    struct server_timestamps {
        bool enabled = false;
        struct timespec m_rec_hw;
        struct timespec m_rec_sw;
        struct timespec m_rec_program;
    } server_timestamps ;

private:
    int m_socket;

    sock_type m_type;
    in_addr_t m_dst_address;
    int m_dst_port;
    std::string m_dst_interface;

    struct receive_helper {
        struct iovec iov;
        struct msghdr msh;
        char control_buffer[1024];
    } m_receive_helper;
};

}

#endif // UCE_H
