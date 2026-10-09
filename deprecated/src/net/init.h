#ifndef __SRC_NET_INIT_H__
#define __SRC_NET_INIT_H__

#include <climits>
#include <cstring>
#include <limits>

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <afunix.h>
#include <ws2tcpip.h>
#include <windows.h>
#define CERTPP_CLOSE_SOCKET ::closesocket
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/un.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <unistd.h>
#define CERTPP_CLOSE_SOCKET ::close
#endif

namespace certpp {
namespace net {

/**
 * Initializes the network subsystem for the application.
 * On Windows, it ensures that the Winsock library is properly started.
 */
class NetInit {
private:
#if defined(_WIN32) || defined(_WIN64)
    WSADATA _wsaData;
    ERetCode _state;

    NetInit() : _state(ERET_OK) {
        // --> Initialize the Winsock library and store the result as an ERetCode.
        _state = toRetCode(WSAStartup(MAKEWORD(2, 2), &_wsaData));
    }

    ~NetInit() {
        if (_state == 0) {
            WSACleanup();
        }
    }

    /**
     * Retrieves the last error that occurred during network initialization.
     * @return An ERetCode representing the last error.
     */
    static inline ERetCode toRetCode(int32_t state) {
        switch (state) {
        case 0:
            return ERET_OK;
        case WSASYSNOTREADY:
            return ERET_NETDOWN;
        case WSAVERNOTSUPPORTED:
            return ERET_NOTSUP;
        case WSAEINVAL:
            return ERET_INVAL;
        case WSAEPROCLIM:
            return ERET_BUSY;
        default:
            return ERET_UNKNOWN;
        }
    }

#endif
public:
    /**
     * Initializes the network subsystem.
     * @return An ERetCode indicating whether network initialization succeeded.
     */
    static certpp::ERetCode init() {
#if defined(_WIN32) || defined(_WIN64)
        static NetInit __INIT__;
        return __INIT__._state;
#else
        return ERET_OK;
#endif
    }
};

} // namespace net
} // namespace certpp

#endif