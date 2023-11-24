#ifndef UCE_SUPPORT_H
#define UCE_SUPPORT_H

#include <string>

namespace uce
{
class support
{
public:
    support() = delete;

    static std::string get_interface_from_ip(std::string& address);
    static std::string get_mac_from_interface(std::string& src_interface); // NOTE: This does only work on for the current machine.
    static std::string get_mac_from_ip(std::string& src_address, std::string& dst_address, std::string& src_interface);
};
}

#endif // UCE_SUPPORT_H
