#ifndef __INCLUDE_CERTPP_NET_SOCKET_HPP__
#define __INCLUDE_CERTPP_NET_SOCKET_HPP__

#include <certpp/common.hpp>
#include <certpp/net/sockaddr.hpp>
#include <certpp/io/stream.hpp>
#include <certpp/io/span.hpp>
#include <certpp/time.hpp>

namespace certpp {
namespace net {

    /**
     * Enumeration representing different types of sockets.
     */
    enum ESocket {
        ESOCK_STREAM = 0,
        ESOCK_DGRAM
    };

    /**
     * Enumeration representing different network protocols.
     */
    enum EProtocol {
        EPROT_UNSPEC = 0,
        EPROT_TCP,
        EPROT_UDP
    };

    /**
     * Enumeration representing different shutdown modes for a socket.
     */
    enum EShut {
        ESHUT_RD = 0,
        ESHUT_WR,
        ESHUT_RDWR
    };

    /**
     * Flags describing the readiness conditions CSocket::poll() waits for or reports.
     */
    enum EPollHow {
        EPOLL_RCV = 0x01,   /**< Data (or EOF / a pending connection) can be received. */
        EPOLL_SND = 0x02,   /**< Data can be sent without blocking. */
        EPOLL_ERR = 0x04,   /**< An error or hang-up condition; always reported, never needs requesting. */
        EPOLL_ANY = EPOLL_RCV | EPOLL_SND | EPOLL_ERR
    };

    /**
     * Combines two EPollHow flag sets.
     */
    inline EPollHow operator|(EPollHow a, EPollHow b) {
        return static_cast<EPollHow>(static_cast<int>(a) | static_cast<int>(b));
    }

    /**
     * Intersects two EPollHow flag sets.
     */
    inline EPollHow operator&(EPollHow a, EPollHow b) {
        return static_cast<EPollHow>(static_cast<int>(a) & static_cast<int>(b));
    }

    /**
     * Represents a network socket.
     */
    class CERTPP_API CSocket {
    public:
#if defined(_WIN32) || defined(_WIN64)
        using RawType = intptr_t;
#else
        using RawType = int32_t;
#endif

    private:
        RawType _raw;           /**< The raw socket descriptor. */

    public:
        /**
         * Default constructor initializes the socket to an invalid state (-1).
         */
        CSocket() : _raw(-1) {}

        /**
         * Deleted copy constructor and assignment operator to prevent copying.
         */
        CSocket(const CSocket&) = delete;

        /**
         * Move constructor transfers ownership of the socket from another instance.
         * @param other The other socket to move from.
         */
        CSocket(CSocket&& other) noexcept
            : _raw(other._raw)
        {
            other._raw = -1;
        }

        /**
         * Destructor closes the socket if it is open.
         */
        ~CSocket() {
            close();
        }

        /**
         * Deleted assignment operator to prevent copying.
         */
        CSocket& operator=(const CSocket&) = delete;

        /**
         * Move assignment operator transfers ownership of the socket from another instance.
         * @param other The other socket to move from.
         * @return Reference to this socket.
         */
        inline CSocket& operator=(CSocket&& other) noexcept {
            if (this != &other) {
                swap(_raw, other._raw);
            }

            return *this;
        }

    protected:
        /**
         * Resets the socket with a new raw descriptor and last error.
         * @param raw The new raw socket descriptor.
         */
        inline void reset(RawType raw) {
            if (raw != _raw) {
                close();
            }

            _raw = raw;
        }

    public:
        /**
         * Checks if the socket is valid (i.e., not in an invalid state).
         * @return True if the socket is valid, false otherwise.
         */
        inline bool empty() const { return _raw < 0; }

        /**
         * Checks if the socket is valid (i.e., not in an invalid state).
         * @return True if the socket is valid, false otherwise.
         */
        inline operator bool() const { return !empty(); }

        /**
         * Checks if the socket is in an invalid state.
         * @return True if the socket is invalid, false otherwise.
         */
        inline bool operator !() const { return empty(); }

        /**
         * Returns the raw socket descriptor.
         * @return The raw integer value representing the socket.
         */
        inline RawType raw() const { return _raw; }

        /**
         * Retrieves and translates the most recent native socket error.
         * @return An ERetCode indicating the last socket error.
         */
        static ERetCode lastError();

        /**
         * Creates a new socket with the specified address family, type, and protocol.
         * @param af The address family for the socket.
         * @param type The type of the socket (stream or datagram).
         * @param protocol The network protocol for the socket.
         * @return An ERetCode indicating the result of the operation.
         */
        ERetCode create(EAddressFamily af, ESocket type, EProtocol protocol = EPROT_UNSPEC);

        /**
         * Binds the socket to the specified local address.
         * @param addr The local address to bind the socket to.
         * @return An ERetCode indicating the result of the operation.
         */
        ERetCode bind(const SSocketAddress& addr);

        /**
         * Puts the socket into a listening state, ready to accept incoming connections.
         * @param backlog The maximum length of the queue of pending connections.
         * @return An ERetCode indicating the result of the operation.
         * @note Returns ERET_INVAL if the socket is closed or backlog is negative.
         */
        ERetCode listen(int32_t backlog);

        /**
         * Connects the socket to the specified remote address.
         * @param addr The remote address to connect the socket to.
         * @return An ERetCode indicating the result of the operation.
         */
        ERetCode connect(const SSocketAddress& addr);

        /**
         * Accepts an incoming connection on the listening socket.
         * @param out The socket object to store the accepted connection.
         * @return An ERetCode indicating the result of the operation.
         */
        ERetCode accept(CSocket& out);

        /**
         * Closes the socket if it is open.
         * @return ERET_OK if closed, ERET_ALREADY if already closed, or a translated native error.
         */
        ERetCode close();

        /**
         * Duplicates the underlying raw socket into another CSocket object.
         * @param out The CSocket object to store the duplicated socket.
         * @return An ERetCode indicating the result of the operation.
         */
        ERetCode dup(CSocket& out);

        /**
         * Detaches the underlying raw socket from the CSocket object.
         * @return The raw socket descriptor.
         * @note After calling this function, the CSocket object will no longer manage the socket.
         */
        inline RawType detach() {
            RawType raw = -1;
            swap(_raw, raw);
            return raw;
        }

        /**
         * Retrieves the local address of the socket.
         * @param out The output socket address to store the local address.
         * @return An ERetCode indicating success or failure.
         */
        ERetCode localAddress(SSocketAddress& out) const;

        /**
         * Retrieves the local address of the socket.
         * @return The local socket address.
         */
        inline SSocketAddress localAddress() const {
            SSocketAddress addr;
            localAddress(addr);
            return addr;
        }

        /**
         * Retrieves the remote address of the socket.
         * @param out The output socket address to store the remote address.
         * @return An ERetCode indicating success or failure.
         */
        ERetCode remoteAddress(SSocketAddress& out) const;

        /**
         * Retrieves the remote address of the socket.
         * @return The remote socket address.
         */
        inline SSocketAddress remoteAddress() const {
            SSocketAddress addr;
            remoteAddress(addr);
            return addr;
        }

        /**
         * Sets the receive timeout for the socket.
         * @param timeout The timeout duration.
         * @return An ERetCode indicating the result of the operation.
         */
        ERetCode recvTimeout(const STimeSpan& timeout);

        /**
         * Sets the send timeout for the socket.
         * @param timeout The timeout duration.
         * @return An ERetCode indicating the result of the operation.
         */
        ERetCode sendTimeout(const STimeSpan& timeout);

        /**
         * Enables or disables the TCP_NODELAY option for the socket.
         * @param enable True to enable TCP_NODELAY, false to disable it.
         * @return An ERetCode indicating the result of the operation.
         */
        ERetCode noDelay(bool enable);

        /**
         * Enables or disables blocking mode for the socket.
         * @param enable True to enable blocking mode, false to disable it.
         * @return An ERetCode indicating the result of the operation.
         */
        ERetCode blocking(bool enable);

        /**
         * Sends data to the socket.
         * @param buffer The buffer containing the data to send.
         * @param size The size of the data to send.
         * @param written The number of bytes actually written.
         * @return ERET_OK after the buffer is sent, or a translated native error; written retains
         *         the number of bytes transferred before an error.
         */
        ERetCode send(const void* buffer, size_t size, size_t& written);

        /**
         * Sends data to the socket.
         * @param buffer The buffer containing the data to send.
         * @param size The size of the data to send.
         * @return The number of bytes actually written.
         */
        inline size_t send(const void* buffer, size_t size) {
            size_t written = 0;
            send(buffer, size, written);
            return written;
        }

        /**
         * Receives data from the socket.
         * @param buffer The buffer to store the received data.
         * @param size The size of the buffer.
         * @param read The number of bytes actually read.
         * @return ERET_OK after the buffer is filled or the peer closes, or a translated native
         *         error; read retains the number of bytes transferred before an error.
         */
        ERetCode recv(void* buffer, size_t size, size_t& read);

        /**
         * Receives data from the socket.
         * @param buffer The buffer to store the received data.
         * @param size The size of the buffer.
         * @return The number of bytes actually read.
         */
        inline size_t recv(void* buffer, size_t size) {
            size_t read = 0;
            recv(buffer, size, read);
            return read;
        }

        /**
         * Sends data to the specified remote address.
         * @param addr The remote socket address to send data to.
         * @param buffer The buffer containing the data to send.
         * @param size The size of the data to send.
         * @param written The number of bytes actually written.
         * @return An ERetCode indicating the result of the operation.
         */
        ERetCode sendTo(const SSocketAddress& addr, const void* buffer, size_t size, size_t& written);

        /**
         * Receives data from the specified remote address.
         * @param addr The remote socket address from which data is received.
         * @param buffer The buffer to store the received data.
         * @param size The size of the buffer.
         * @param read The number of bytes actually read.
         * @return An ERetCode indicating the result of the operation.
         */
        ERetCode recvFrom(SSocketAddress& addr, void* buffer, size_t size, size_t& read);

        /**
         * Waits until the socket is ready for the requested operations.
         * This is how a caller waits out ERET_AGAIN instead of spinning on it.
         * @param how The conditions to wait for (EPOLL_RCV, EPOLL_SND, ...); EPOLL_ERR is always reported.
         * @param timeout How long to wait; a negative span waits indefinitely and zero only checks.
         * @param ready Optional; receives the conditions that are actually met.
         * @return ERET_OK when at least one condition is met, ERET_TIMEOUT when the timeout
         *         expired first, ERET_AGAIN if interrupted (call again), or a translated native error.
         */
        ERetCode poll(EPollHow how, const STimeSpan& timeout, EPollHow* ready = nullptr);

        /**
         * Shuts down the socket for reading, writing, or both.
         * @param how The shutdown mode (EShut).
         * @return An ERetCode indicating the result of the operation.
         */
        ERetCode shutdown(EShut how);
    };

    /**
     * A shared pointer to a CSocket instance.
     */
    using CSocketPtr = std::shared_ptr<CSocket>;

    /**
     * Converts a CSocket instance to a shared pointer.
     * This clears the original CSocket instance by moving it into the shared pointer.
     *
     * @param socket The CSocket instance to convert.
     * @return A shared pointer to the CSocket instance.
     */
    CERTPP_API CSocketPtr toShared(CSocket& socket);

} // namespace net
} // namespace certpp

#endif