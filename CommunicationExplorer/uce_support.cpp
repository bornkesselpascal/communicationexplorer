#include "uce_support.h"
#include <cstring>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if.h>
#include <netinet/ether.h>
#include <netdb.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <ifaddrs.h>


// SUPPORT: Interface name from IP address
//    - This returns the interface name of a local interface based on the IP address.

std::string uce::support::get_interface_from_ip(std::string& address)
{
    struct ifaddrs *addrs, *iap;
    struct sockaddr_in *sa;
    char buf[32];

    getifaddrs(&addrs);
    for (iap = addrs; iap != NULL; iap = iap->ifa_next) {
        if (iap->ifa_addr && (iap->ifa_flags & IFF_UP) && iap->ifa_addr->sa_family == AF_INET) {
            sa = (struct sockaddr_in *)(iap->ifa_addr);
            inet_ntop(iap->ifa_addr->sa_family, (void *)&(sa->sin_addr), buf, sizeof(buf));
            if (!strcmp(address.c_str(), buf)) {
                freeifaddrs(addrs);
                return std::string(iap->ifa_name);
            }
        }
    }

    freeifaddrs(addrs);
    return "";
}


// SUPPORT: MAC address from interface name
//    - This is a simplied way to get the MAC address of an interface on the current machine without an ARP request.
//    - Fetches the MAC address using the ioctl command.

std::string uce::support::get_mac_from_interface(std::string& src_interface)
{
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    struct ifreq ifr{};
    strcpy(ifr.ifr_name, src_interface.c_str());
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    char mac[18];
    strcpy(mac, ether_ntoa((ether_addr *) ifr.ifr_hwaddr.sa_data));

    return std::string(mac);
}


// SUPPORT: MAC address from IP address
//    - This function returns the MAC address of a machine on the local network based on the IP address.
//    - Fetches the MAC address by sending an ARP request to the remote machine.

struct arp_packet {
    ethhdr eth_hdr;
    arphdr arp_hdr;
    uint8_t sender_mac[ETH_ALEN];
    uint8_t sender_ip[4];
    uint8_t target_mac[ETH_ALEN];
    uint8_t target_ip[4];
};

std::string mac_to_string(const uint8_t* mac) {
    std::ostringstream str;

    for (size_t i = 0; i < ETH_ALEN; ++i) {
        str << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(mac[i]);
        if (i < (ETH_ALEN - 1)) str << ":";
    }

    return str.str();
}

std::string uce::support::get_mac_from_ip(std::string& src_address, std::string& dst_address, std::string& src_interface)
{
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        throw std::runtime_error("[uce_support] E01 - Could not create socket.");
    }

    sockaddr_ll device = {};
    ifreq ifr = {};
    std::strncpy(ifr.ifr_name, src_interface.c_str(), IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        throw std::runtime_error("[uce_support] E02 - Could not get interface index number.");
    }

    device.sll_ifindex = ifr.ifr_ifindex;
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    device.sll_halen = ETH_ALEN;

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        throw std::runtime_error("[uce_support] E03 - Could not get interface hardware address.");
    }

    arp_packet packet = {};
    packet.eth_hdr.h_proto = htons(ETH_P_ARP);
    memcpy(packet.eth_hdr.h_source, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    memset(packet.eth_hdr.h_dest, 0xff, ETH_ALEN);

    packet.arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
    packet.arp_hdr.ar_pro = htons(ETH_P_IP);
    packet.arp_hdr.ar_hln = ETH_ALEN;
    packet.arp_hdr.ar_pln = 4;
    packet.arp_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(packet.sender_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    inet_pton(AF_INET, src_address.c_str(), packet.sender_ip); // Replace with your IP address
    memset(packet.target_mac, 0x00, ETH_ALEN);
    inet_pton(AF_INET, dst_address.c_str(), packet.target_ip);

    if (sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr*)&device, sizeof(device)) < 0) {
        throw std::runtime_error("[uce_support] E04 - Could not send ARP request.");
    }

    char buf[512];
    while (true) {
        ssize_t len = recvfrom(sockfd, buf, sizeof(buf), 0, nullptr, nullptr);

        if (len != -1) {
            auto* rcv_packet = reinterpret_cast<arp_packet*>(buf);
            if (ntohs(rcv_packet->arp_hdr.ar_op) == ARPOP_REPLY) {
                return mac_to_string(rcv_packet->sender_mac);
            }
        }
        else {
            throw std::runtime_error("[uce_support] E05 - Could not recieve ARP response.");
        }
    }
}
