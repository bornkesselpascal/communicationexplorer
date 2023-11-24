#include <iostream>
#include "uce.h"


int main()
{
    uce::server my_server(uce::sock_type::ST_RAW, "10.1.0.52", 21005);

    char buffer[UCE_MTU];
    int bytes = my_server.receive(&buffer, sizeof(buffer));
}
