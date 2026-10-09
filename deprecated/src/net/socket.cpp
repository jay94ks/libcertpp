#include <certpp/net/socket.hpp>
#include "init.h"

namespace certpp {
namespace net {

    /**
     * Translates the most recent native socket error to the library error code.
     */
    static inline ERetCode socketErrorToRetCode(int32_t err) {
#if defined(_WIN32) || defined(_WIN64)
        switch (err) {
        case WSAEINVAL:
        case WSAENOTSOCK:
            return ERET_INVAL;
        case WSAEFAULT:
            return ERET_BUF_ERROR;
        case WSAEINTR:
        case WSAEWOULDBLOCK:
        case WSAEINPROGRESS:
            return ERET_AGAIN;
        case WSAEALREADY:
            return ERET_BUSY;
        case WSAEISCONN:
            return ERET_ALREADY;
        case WSAETIMEDOUT:
            return ERET_TIMEOUT;
        case WSAENETDOWN:
            return ERET_NETDOWN;
        case WSAENETUNREACH:
        case WSAEHOSTUNREACH:
        case WSAEHOSTDOWN:
            return ERET_HOSTUNREACH;
        case WSAECONNRESET:
            return ERET_CONNRESET;
        case WSAECONNABORTED:
            return ERET_CONNABORTED;
        case WSAECONNREFUSED:
            return ERET_CONNREFUSED;
        case WSAENOTCONN:
        case WSAEDESTADDRREQ:
        case WSAESHUTDOWN:
            return ERET_NOTCONN;
        case WSAEADDRINUSE:
            return ERET_ADDRINUSE;
        case WSAEADDRNOTAVAIL:
            return ERET_ADDRNOTAVAIL;
        case WSAEMFILE:
        case WSAENOBUFS:
            return ERET_NOMEM;
        case WSAEAFNOSUPPORT:
        case WSAEPROTONOSUPPORT:
        case WSAEPROTOTYPE:
        case WSAESOCKTNOSUPPORT:
        case WSAEOPNOTSUPP:
        case WSAENOPROTOOPT:
            return ERET_NOTSUP;
        default:
            return ERET_UNKNOWN;
        }
#else
        switch (err) {
        case EBADF:
        case EINVAL:
        case ENOTSOCK:
            return ERET_INVAL;
        case EFAULT:
            return ERET_BUF_ERROR;
        case EINTR:
        case EAGAIN:
#if EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
        case EINPROGRESS:
            return ERET_AGAIN;
        case EALREADY:
            return ERET_BUSY;
        case EISCONN:
            return ERET_ALREADY;
        case ETIMEDOUT:
            return ERET_TIMEOUT;
        case ENETDOWN:
            return ERET_NETDOWN;
        case ENETUNREACH:
        case EHOSTUNREACH:
        case EHOSTDOWN:
            return ERET_HOSTUNREACH;
        case ECONNRESET:
        case EPIPE:
            return ERET_CONNRESET;
        case ECONNABORTED:
            return ERET_CONNABORTED;
        case ECONNREFUSED:
            return ERET_CONNREFUSED;
        case ENOTCONN:
        case EDESTADDRREQ:
            return ERET_NOTCONN;
        case EADDRINUSE:
            return ERET_ADDRINUSE;
        case EADDRNOTAVAIL:
            return ERET_ADDRNOTAVAIL;
        case EMFILE:
        case ENFILE:
        case ENOMEM:
        case ENOBUFS:
            return ERET_NOMEM;
        case EAFNOSUPPORT:
        case EPROTONOSUPPORT:
        case EPROTOTYPE:
        case EOPNOTSUPP:
        case ENOPROTOOPT:
            return ERET_NOTSUP;
        default:
            return ERET_UNKNOWN;
        }
#endif
    }

    /**
     * Retrieves and translates the most recent native socket error.
     */
    ERetCode CSocket::lastError() {
#if defined(_WIN32) || defined(_WIN64)
        return socketErrorToRetCode(WSAGetLastError());
#else
        return socketErrorToRetCode(errno);
#endif
    }

    /**
     * Returns the largest payload size accepted by one native send/receive call.
     */
    static inline size_t maxSocketTransferSize() {
#if defined(_WIN32) || defined(_WIN64)
        return static_cast<size_t>(INT_MAX);
#else
        return static_cast<size_t>(std::numeric_limits<ssize_t>::max());
#endif
    }

    /**
     * Initializes the socket.
     *
     * @param af The address family for the socket.
     * @param type The type of the socket (stream or datagram).
     * @param protocol The network protocol for the socket.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::create(EAddressFamily af, ESocket type, EProtocol protocol) {
        if (_raw >= 0) {
            return ERET_ALREADY;
        }

        if (af <= EAF_UNSPEC || af >= EAF_MAX) {
            return ERET_INVAL;
        }

        // --> initialize the network subsystem.
        ERetCode initResult = NetInit::init();
        if (initResult != ERET_OK) {
            return initResult;
        }

        // --
        int32_t rawAf = SSocketAddress::toRawFamily(af);
        int32_t rawSt = 0;
        int32_t rawPr = 0;

        // --> Convert the socket type to their raw values.
        switch (type) {
            case ESOCK_STREAM: rawSt = SOCK_STREAM; break;
            case ESOCK_DGRAM:  rawSt = SOCK_DGRAM;  break;
            default: return ERET_INVAL;
        }

        // --> Convert the protocol to its raw value.
        switch (protocol) {
            case EPROT_UNSPEC: rawPr = 0; break;
            case EPROT_TCP: rawPr = IPPROTO_TCP; break;
            case EPROT_UDP: rawPr = IPPROTO_UDP; break;
            default: return ERET_INVAL;
        }

        // --> Create the socket with the specified address family, type, and protocol.
        RawType raw = ::socket(rawAf, rawSt, rawPr);
        if (raw < 0) {
            return lastError();
        }
        _raw = raw;

        return ERET_OK;
    }

    /**
     * Binds the socket to the specified local address.
     *
     * @param addr The local address to bind the socket to.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::bind(const SSocketAddress& addr) {
        if (_raw < 0) {
            return ERET_INVAL;
        }

        const sockaddr* rawAddr = reinterpret_cast<const sockaddr*>(addr.raw);
        socklen_t addrLen = static_cast<socklen_t>(addr.size);

        if (::bind(_raw, rawAddr, addrLen) != 0) {
            return lastError();
        }

        return ERET_OK;
    }

    /**
     * Puts the socket into a listening state, ready to accept incoming connections.
     *
     * @param backlog The maximum length of the queue of pending connections.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::listen(int32_t backlog) {
        if (_raw < 0) {
            return ERET_INVAL;
        }
        if (backlog < 0) {
            return ERET_INVAL;
        }

        if (::listen(_raw, backlog) != 0) {
            return lastError();
        }

        return ERET_OK;
    }

    /**
     * Connects the socket to the specified remote address.
     *
     * @param addr The remote address to connect the socket to.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::connect(const SSocketAddress& addr) {
        if (_raw < 0) {
            return ERET_INVAL;
        }
        const sockaddr* rawAddr = reinterpret_cast<const sockaddr*>(addr.raw);
        socklen_t addrLen = static_cast<socklen_t>(addr.size);

        // --> Attempt to connect the socket to the specified remote address.
        if (::connect(_raw, rawAddr, addrLen) != 0) {
            return lastError();
        }

        return ERET_OK;
    }

    /**
     * Accepts an incoming connection on the listening socket.
     *
     * @param out The socket object to store the accepted connection.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::accept(CSocket& out) {
        if (_raw < 0) {
            return ERET_INVAL;
        }

        sockaddr_storage addr;
        socklen_t addrLen = sizeof(addr);
        RawType clientRaw = ::accept(_raw, reinterpret_cast<sockaddr*>(&addr), &addrLen);
        if (clientRaw < 0) {
            return lastError();
        }

        out.reset(clientRaw);
        return ERET_OK;
    }

    /**
     * Closes the socket if it is open.
     * @return True if the socket was successfully closed, false otherwise.
     */
    ERetCode CSocket::close() {
        if (empty()) {
            return ERET_ALREADY;
        }

#if defined(_WIN32) || defined(_WIN64)
        if (CERTPP_CLOSE_SOCKET(_raw) == SOCKET_ERROR) {
            return lastError();
        }
#else
        int result = CERTPP_CLOSE_SOCKET(_raw);
        _raw = -1;
        if (result != 0) {
            return lastError();
        }
#endif
        _raw = -1;
        return ERET_OK;
    }

    /**
     * Duplicates the underlying raw socket into another CSocket object.
     *
     * @param out The CSocket object to store the duplicated socket.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::dup(CSocket& out) {
        if (_raw < 0) {
            return ERET_INVAL;
        }

#if defined(_WIN32) || defined(_WIN64)
        WSAPROTOCOL_INFO info;
        if (WSADuplicateSocket(static_cast<SOCKET>(_raw), GetCurrentProcessId(), &info) == SOCKET_ERROR) {
            return lastError();
        }

        RawType dupRaw = WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &info, 0, 0);
        if (dupRaw == static_cast<RawType>(INVALID_SOCKET)) {
            return lastError();
        }

        out.reset(dupRaw);
#else
        RawType dupRaw = ::dup(_raw);
        if (dupRaw < 0) {
            return lastError();
        }

        out.reset(dupRaw);
#endif

        return ERET_OK;
    }

    /**
     * Retrieves the local address of the socket.
     *
     * @param out The structure to store the local address.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::localAddress(SSocketAddress& out) const {
        if (_raw < 0) {
            return ERET_INVAL;
        }

        sockaddr_storage addr;
        socklen_t addrLen = sizeof(addr);

        if (getsockname(_raw, reinterpret_cast<sockaddr*>(&addr), &addrLen) != 0) {
            return lastError();
        }

        if (addrLen > sizeof(out.raw)) {
            return ERET_BUF_ERROR;
        }

        out.size = addrLen;
        std::memcpy(out.raw, &addr, addrLen);

        return ERET_OK;
    }

    /**
     * Retrieves the remote address of the socket.
     *
     * @param out The structure to store the remote address.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::remoteAddress(SSocketAddress& out) const {
        if (_raw < 0) {
            return ERET_INVAL;
        }

        sockaddr_storage addr;
        socklen_t addrLen = sizeof(addr);

        if (getpeername(_raw, reinterpret_cast<sockaddr*>(&addr), &addrLen) != 0) {
            return lastError();
        }

        if (addrLen > sizeof(out.raw)) {
            return ERET_BUF_ERROR;
        }

        out.size = addrLen;
        std::memcpy(out.raw, &addr, addrLen);

        return ERET_OK;
    }

    /**
     * Sets the receive timeout for the socket.
     *
     * @param timeout The timeout duration.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::recvTimeout(const STimeSpan& timeout) {
        if (_raw < 0) {
            return ERET_INVAL;
        }
        if (timeout.milliseconds < 0) {
            return ERET_INVAL;
        }

#if defined(_WIN32) || defined(_WIN64)
        if (timeout.milliseconds > static_cast<int64_t>(MAXDWORD)) {
            return ERET_TOO_LONG;
        }
        DWORD timeoutMs = static_cast<DWORD>(timeout.milliseconds);
        if (setsockopt(_raw, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs)) != 0) {
            return lastError();
        }
#else
        struct timeval tv;
        tv.tv_sec = static_cast<time_t>(timeout.totalSeconds());
        tv.tv_usec = static_cast<suseconds_t>((timeout.totalMilliseconds() % 1000) * 1000);
        if (setsockopt(_raw, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
            return lastError();
        }
#endif

        return ERET_OK;
    }

    /**
     * Sets the send timeout for the socket.
     *
     * @param timeout The timeout duration.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::sendTimeout(const STimeSpan& timeout) {
        if (_raw < 0) {
            return ERET_INVAL;
        }
        if (timeout.milliseconds < 0) {
            return ERET_INVAL;
        }

#if defined(_WIN32) || defined(_WIN64)
        if (timeout.milliseconds > static_cast<int64_t>(MAXDWORD)) {
            return ERET_TOO_LONG;
        }
        DWORD timeoutMs = static_cast<DWORD>(timeout.milliseconds);
        if (setsockopt(_raw, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs)) != 0) {
            return lastError();
        }
#else
        struct timeval tv;
        tv.tv_sec = static_cast<time_t>(timeout.totalSeconds());
        tv.tv_usec = static_cast<suseconds_t>((timeout.totalMilliseconds() % 1000) * 1000);
        if (setsockopt(_raw, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
            return lastError();
        }
#endif

        return ERET_OK;
    }

    /**
     * Enables or disables the TCP_NODELAY option for the socket.
     *
     * @param enable True to enable TCP_NODELAY, false to disable it.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::noDelay(bool enable) {
        if (_raw < 0) {
            return ERET_INVAL;
        }

#if defined(_WIN32) || defined(_WIN64)
        BOOL flag = enable ? TRUE : FALSE;
        if (setsockopt(_raw, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&flag), sizeof(flag)) != 0) {
            return lastError();
        }
#else
        int flag = enable ? 1 : 0;
        if (setsockopt(_raw, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) != 0) {
            return lastError();
        }
#endif

        return ERET_OK;
    }

    /**
     * Enables or disables blocking mode for the socket.
     *
     * @param enable True to enable blocking mode, false to disable it.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::blocking(bool enable) {
        if (_raw < 0) {
            return ERET_INVAL;
        }

#if defined(_WIN32) || defined(_WIN64)
        u_long mode = enable ? 0 : 1;
        if (ioctlsocket(_raw, FIONBIO, &mode) != 0) {
            return lastError();
        }
#else
        int flags = fcntl(_raw, F_GETFL, 0);
        if (flags < 0) {
            return lastError();
        }
        if (enable) {
            flags &= ~O_NONBLOCK;
        } else {
            flags |= O_NONBLOCK;
        }
        if (fcntl(_raw, F_SETFL, flags) != 0) {
            return lastError();
        }
#endif

        return ERET_OK;
    }

    /**
     * Sends data to the socket.
     *
     * @param buffer The buffer containing the data to send.
     * @param size The size of the data to send.
     * @param written The number of bytes actually written.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::send(const void* buffer, size_t size, size_t& written) {
        if (_raw < 0) {
            return ERET_INVAL;
        }
        written = 0;
        if (size > 0 && !buffer) {
            return ERET_INVAL;
        }

        const size_t maxChunk = maxSocketTransferSize();
        while (written < size) {
            const size_t remaining = size - written;
            const size_t chunkSize = remaining < maxChunk ? remaining : maxChunk;

#if defined(_WIN32) || defined(_WIN64)
            int result = ::send(_raw, reinterpret_cast<const char*>(buffer) + written,
                                static_cast<int>(chunkSize), 0);
#else
            ssize_t result = ::write(_raw, static_cast<const uint8_t*>(buffer) + written, chunkSize);
#endif

            if (result < 0) {
                return lastError();
            }

            if (result == 0) {
                break;
            }

            written += static_cast<size_t>(result);
        }

        return ERET_OK;
    }

    /**
     * Receives data from the socket.
     *
     * @param buffer The buffer to store the received data.
     * @param size The size of the buffer.
     * @param read The number of bytes actually read.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::recv(void* buffer, size_t size, size_t& read) {
        if (_raw < 0) {
            return ERET_INVAL;
        }

        read = 0;

        if (size > 0 && !buffer) {
            return ERET_INVAL;
        }

        const size_t maxChunk = maxSocketTransferSize();
        while (read < size) {
            const size_t remaining = size - read;
            const size_t chunkSize = remaining < maxChunk ? remaining : maxChunk;

#if defined(_WIN32) || defined(_WIN64)
            int result = ::recv(_raw, reinterpret_cast<char*>(buffer) + read,
                                static_cast<int>(chunkSize), 0);
#else
            ssize_t result = ::read(_raw, static_cast<uint8_t*>(buffer) + read, chunkSize);
#endif

            if (result < 0) {
                return lastError();
            }
            if (result == 0) {
                break;
            }
            read += static_cast<size_t>(result);
        }

        return ERET_OK;
    }

    /**
     * Sends data to the specified remote address.
     *
     * @param addr The remote socket address to send data to.
     * @param buffer The buffer containing the data to write.
     * @param size The size of the data to write.
     * @param written The number of bytes actually written.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::sendTo(const SSocketAddress& addr, const void* buffer, size_t size, size_t& written) {
        if (_raw < 0) {
            return ERET_INVAL;
        }
        written = 0;
        if (size > 0 && !buffer) {
            return ERET_INVAL;
        }

#if defined(_WIN32) || defined(_WIN64)
        if (size > static_cast<size_t>(INT_MAX)) {
            return ERET_TOO_LONG;
        }

        int result = ::sendto(_raw, reinterpret_cast<const char*>(buffer), static_cast<int>(size), 0,
                              reinterpret_cast<const sockaddr*>(addr.raw), static_cast<int>(addr.size));
        if (result < 0) {
            return lastError();
        }

        written = static_cast<size_t>(result);
#else
        ssize_t result = ::sendto(_raw, buffer, size, 0, reinterpret_cast<const sockaddr*>(addr.raw),
                                  static_cast<socklen_t>(addr.size));
        if (result < 0) {
            return lastError();
        }
        written = static_cast<size_t>(result);
#endif

        return ERET_OK;
    }

    /**
     * Receives data from the specified remote address.
     *
     * @param addr The remote socket address from which data is received.
     * @param buffer The buffer to store the received data.
     * @param size The size of the buffer.
     * @param read The number of bytes actually read.
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::recvFrom(SSocketAddress& addr, void* buffer, size_t size, size_t& read) {
        if (_raw < 0) {
            return ERET_INVAL;
        }

        read = 0;

        if (size > 0 && !buffer) {
            return ERET_INVAL;
        }

        sockaddr_storage rawAddr;

#if defined(_WIN32) || defined(_WIN64)
        if (size > static_cast<size_t>(INT_MAX)) {
            return ERET_TOO_LONG;
        }

        int addrLen = sizeof(sockaddr_storage);
        int result = ::recvfrom(_raw, reinterpret_cast<char*>(buffer), static_cast<int>(size), 0,
                                reinterpret_cast<sockaddr*>(&rawAddr), &addrLen);
        if (result < 0) {
            return lastError();
        }

        read = static_cast<size_t>(result);
#else
        socklen_t addrLen = sizeof(sockaddr_storage);
        ssize_t result = ::recvfrom(_raw, buffer, size, 0, reinterpret_cast<sockaddr*>(&rawAddr), &addrLen);
        if (result < 0) {
            return lastError();
        }

        read = static_cast<size_t>(result);
#endif
        if (addrLen > sizeof(addr.raw)) {
            read = 0;
            return ERET_BUF_ERROR;
        }
        addr.size = static_cast<size_t>(addrLen);
        std::memcpy(addr.raw, &rawAddr, addr.size);

        return ERET_OK;
    }

    /* Waits until the socket is ready for the requested operations. */
    ERetCode CSocket::poll(EPollHow how, const STimeSpan& timeout, EPollHow* ready) {
        if (ready) {
            *ready = static_cast<EPollHow>(0);
        }
        if (_raw < 0) {
            return ERET_INVAL;
        }

        int timeoutMs = -1;
        if (timeout.milliseconds >= 0) {
            timeoutMs = timeout.milliseconds > static_cast<int64_t>(INT_MAX)
                ? INT_MAX : static_cast<int>(timeout.milliseconds);
        }

        struct pollfd pfd;
        std::memset(&pfd, 0, sizeof(pfd));
        pfd.fd = static_cast<decltype(pfd.fd)>(_raw);
        if ((how & EPOLL_RCV) != 0) {
            pfd.events |= POLLIN;
        }
        if ((how & EPOLL_SND) != 0) {
            pfd.events |= POLLOUT;
        }

#if defined(_WIN32) || defined(_WIN64)
        const int result = ::WSAPoll(&pfd, 1, timeoutMs);
#else
        const int result = ::poll(&pfd, 1, timeoutMs);
#endif
        if (result < 0) {
            return lastError();
        }
        if (result == 0) {
            return ERET_TIMEOUT;
        }

        if (ready) {
            EPollHow got = static_cast<EPollHow>(0);
            if ((pfd.revents & POLLIN) != 0) {
                got = got | EPOLL_RCV;
            }
            if ((pfd.revents & POLLOUT) != 0) {
                got = got | EPOLL_SND;
            }
            if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                got = got | EPOLL_ERR;
            }
            *ready = got;
        }
        return ERET_OK;
    }

    /**
     * Shuts down the socket for reading, writing, or both.
     * @param how The shutdown mode (EShut).
     * @return An ERetCode indicating the result of the operation.
     */
    ERetCode CSocket::shutdown(EShut how) {
        if (_raw < 0) {
            return ERET_INVAL;
        }

#if defined(_WIN32) || defined(_WIN64)
        int result = ::shutdown(_raw, static_cast<int>(how));
        if (result < 0) {
            return lastError();
        }
#else
        int result = ::shutdown(_raw, static_cast<int>(how));
        if (result < 0) {
            return lastError();
        }
#endif

        return ERET_OK;
    }

    /**
     * Converts a CSocket instance to a shared pointer.
     * @param socket The CSocket instance to convert.
     * @return A shared pointer to the CSocket instance.
     */
    CSocketPtr toShared(CSocket& socket) {
        return std::make_shared<CSocket>(
            static_cast<CSocket&&>(socket)
        );
    }

} // namespace net
} // namespace certpp