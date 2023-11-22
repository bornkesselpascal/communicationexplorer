cmake_minimum_required(VERSION 3.5)

project(CommunicationExplorer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(CommunicationExplorer main.cpp
    communication.h
    communication_udp.cpp
    communication_raw.cpp )

include(GNUInstallDirs)
install(TARGETS CommunicationExplorer
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
