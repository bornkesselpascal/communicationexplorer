#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include <string>
#include <netdb.h>
#include <linux/ip.h>

namespace ce {

/**
 *  @brief Classes for sending/receieving UDP packets over UDP socket.
 *      - Packets pass layer 2 to 4.
 *      - All headers are created by the kernel.
 */
namespace udp {
class client {
public:
    client(const std::string& dest_address, int dest_port);
    ~client();

    int         get_socket()  const { return m_socket;  }
    int         get_port()    const { return m_port;    }
    std::string get_address() const { return m_address; }

    int  send(const void *msg, size_t size);
    void set_dscp(int value);

private:
    int m_socket;
    int m_port;
    std::string m_address;
    struct addrinfo *m_addrinfo;
};

class server
{
public:
    server(const std::string& dest_address, int dest_port);
    ~server();

    int         get_socket()  const { return m_socket;  }
    int         get_port()    const { return m_port;    }
    std::string get_address() const { return m_address; }

    int receive(void *msg, size_t max_size, int timeout = -1);

private:
    int m_socket;
    int m_port;
    std::string m_address;
    struct addrinfo *m_addrinfo;
};
}

/**
 *  @brief Classes for sending/receieving UDP packets over raw socket.
 *      - Packets pass layer 2 to 3.
 *      - The IP header is manually created. The checksums are calculated by the kernel.
 *      - The packets do not contain a UDP header.
 */
namespace raw {
class client {
public:
    client(const std::string& src_address, const std::string& dest_address, size_t max_size);
    ~client();

    int get_socket()  const { return m_socket;  }

    int send(const void *msg, size_t size);

private:
    int m_socket;
    size_t m_max_size;

    void* m_buffer_ptr;
    struct iphdr* m_ip_ptr;
    void* m_data_ptr;
};

class server
{
public:
    server(const std::string& dest_address);
    ~server();

    int get_socket() const { return m_socket;  }

    int receive(void *msg, size_t max_size);

private:
    int m_socket;
};
}



}

#endif // COMMUNICATION_H
