#include <certpp/net/sockaddr.hpp>
#include "init.h"

namespace certpp {
namespace net {

    using SNativeSA = sockaddr;

    /**
     * Translates a getaddrinfo error to the library error code.
     */
    static inline ERetCode resolveErrorToRetCode(int32_t err) {
        switch (err) {
        case EAI_AGAIN:
            return ERET_AGAIN;
        case EAI_MEMORY:
            return ERET_NOMEM;
        case EAI_NONAME:
            return ERET_NOTFOUND;
        case EAI_FAMILY:
        case EAI_SOCKTYPE:
        case EAI_SERVICE:
            return ERET_NOTSUP;
#if defined(EAI_SYSTEM)
        case EAI_SYSTEM:
            switch (errno) {
            case EAGAIN:
            case EINTR:
                return ERET_AGAIN;
            case ENOMEM:
            case ENOBUFS:
                return ERET_NOMEM;
            case EINVAL:
                return ERET_INVAL;
            default:
                return ERET_UNKNOWN;
            }
#endif
        default:
            return ERET_UNKNOWN;
        }
    }

    /**
     * Maps the socket address family (SAF) to the corresponding address family (AF) used by the system.
     */
    const int32_t SAF_TO_AF[] = {
        AF_UNSPEC,  // EAF_UNSPEC
        AF_INET,  // SAF_INET
        AF_INET6, // EAF_INET6
        AF_UNIX,  // EAF_UNIX
    };

    /**
     * Converts the system address family (AF) to the corresponding socket address family (SAF).
     */
    static inline EAddressFamily af_to_saf(int af) {
        switch (af) {
            case AF_INET:  return EAF_INET;
            case AF_INET6: return EAF_INET6;
            case AF_UNIX:  return EAF_UNIX;
            default:       return EAF_UNSPEC;
        }
    }

    /**
     * Copy constructor.
     */
    SSocketAddress::SSocketAddress(const SSocketAddress& other) {
        if ((size = other.size) > 0) {
            std::memcpy(raw, other.raw, size);
        }
    }

    /**
     * Move constructor.
     */
    SSocketAddress::SSocketAddress(SSocketAddress&& other) {
        if ((size = other.size) > 0) {
            std::memcpy(raw, other.raw, size);
        }

        other.size = 0;
    }

    /**
     * Copy assignment operator.
     */
    SSocketAddress& SSocketAddress::operator=(const SSocketAddress& other) {
        if (this != &other) {
            if ((size = other.size) > 0) {
                std::memcpy(raw, other.raw, size);
            }
        }

        return *this;
    }

    /**
     * Move assignment operator.
     */
    SSocketAddress& SSocketAddress::operator=(SSocketAddress&& other) {
        if (this != &other) {
            uint8_t tmp[128];  // temporary buffer for the raw data
            const size_t tsz = size;

            memcpy(tmp, raw, size);
            if ((size = other.size) > 0) {
                memcpy(raw, other.raw, size);
            }

            if ((other.size = tsz) > 0) {
                memcpy(other.raw, tmp, other.size);
            }
        }

        return *this;
    }

    /**
     * Converts an EAddressFamily value to its corresponding raw address family value.
     */
    int32_t SSocketAddress::toRawFamily(EAddressFamily family) {
        if (family < EAF_UNSPEC || family >= EAF_MAX) {
            return AF_UNSPEC;
        }

        return SAF_TO_AF[static_cast<int>(family)];
    }

    /**
     * Retrieves the address family of the socket address.
     */
    EAddressFamily SSocketAddress::family() const {
        if (size == 0) {
            return EAF_UNSPEC;
        }

        return af_to_saf(((const SNativeSA*)raw)->sa_family);
    }

    /**
     * Retrieves the port number of the socket address.
     */
    int32_t SSocketAddress::port() const {
        if (size == 0) {
            return -1;
        }

        switch (family()) {
            case EAF_INET:
                return ntohs(native<sockaddr_in>()->sin_port);

            case EAF_INET6:
                return ntohs(native<sockaddr_in6>()->sin6_port);

            default:
                return -1;
        }
    }

    /**
     * Sets the port number of the socket address.
     */
    ERetCode SSocketAddress::port(uint16_t v) {
        if (size == 0) {
            return ERET_INVAL;
        }

        switch (family()) {
            case EAF_INET: {
                sockaddr_in* sa = native<sockaddr_in>();
                sa->sin_port = htons(v);
                return ERET_OK;
            }

            case EAF_INET6: {
                sockaddr_in6* sa6 = native<sockaddr_in6>();
                sa6->sin6_port = htons(v);
                return ERET_OK;
            }

            default:
                return ERET_NOTSUP;
        }
    }

    /**
     * Retrieves the "any" address (e.g., 0.0.0.0 for IPv4 or :: for IPv6) corresponding to the specified address family.
     *
     * @param out The output socket address to store the "any" address.
     * @param port The port number to set for the socket address (default is 0).
     * @param family The address family (default is SAF_INET).
     * @return An ERetCode indicating success or failure.
     */
    ERetCode SSocketAddress::any(SSocketAddress& out, uint16_t port, EAddressFamily family) {
        switch (family) {
            case EAF_UNSPEC: return ERET_INVAL;
            case EAF_INET: {
                out.size = sizeof(sockaddr_in);

                // --
                sockaddr_in* sa = out.native<sockaddr_in>();

                sa->sin_family = AF_INET;
                sa->sin_addr.s_addr = htonl(INADDR_ANY);
                sa->sin_port = htons(port);

                return ERET_OK;
            }

            case EAF_INET6: {
                out.size = sizeof(sockaddr_in6);

                // --
                sockaddr_in6* sa6 = out.native<sockaddr_in6>();

                sa6->sin6_family = AF_INET6;
                sa6->sin6_addr = in6addr_any;
                sa6->sin6_port = htons(port);

                return ERET_OK;
            }

            default:
                break;
        }

        return ERET_NOTSUP;
    }

    /**
     * Retrieves the loopback address (e.g., 127.0.0.1 for IPv4 or ::1 for IPv6) corresponding to the specified address family.
     *
     * @param out The output socket address to store the loopback address.
     * @param port The port number to set for the socket address (default is 0).
     * @param family The address family (default is SAF_INET).
     * @return An ERetCode indicating success or failure.
     */
    ERetCode SSocketAddress::loopback(SSocketAddress& out, uint16_t port, EAddressFamily family) {
        // --> determine the loopback address based on the specified address family.
        switch (family) {
            case EAF_UNSPEC: return ERET_INVAL;
            case EAF_INET: {
                // --> set loopback address for IPv4.
                out.size = sizeof(sockaddr_in);

                // --
                sockaddr_in* sa = out.native<sockaddr_in>();

                // --> set the address family and loopback address for IPv4.
                sa->sin_family = AF_INET;
                sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                sa->sin_port = htons(port);
                return ERET_OK;
            }

            case EAF_INET6: {
                // --> set loopback address for IPv6.
                out.size = sizeof(sockaddr_in6);

                // --
                sockaddr_in6* sa6 = out.native<sockaddr_in6>();

                // --> set the address family and loopback address for IPv6.
                sa6->sin6_family = AF_INET6;
                sa6->sin6_addr = in6addr_loopback;
                sa6->sin6_port = htons(port);
                return ERET_OK;
            }

            default:
                break;
        }

        return ERET_NOTSUP;
    }

    /**
     * Determines whether this socket address is a loopback address.
     * @return True if the socket address is a loopback address, false otherwise.
     */
    bool SSocketAddress::loopback() const {
        if (size == 0) {
            return false;
        }

        switch (family()) {
            case EAF_INET: {
                const sockaddr_in* sa = native<sockaddr_in>();
                return sa && sa->sin_addr.s_addr == htonl(INADDR_LOOPBACK);
            }

            case EAF_INET6: {
                const sockaddr_in6* sa6 = native<sockaddr_in6>();
                return sa6 && IN6_ARE_ADDR_EQUAL(&sa6->sin6_addr, &in6addr_loopback);
            }

            default:
                break;
        }

        return false;
    }

    /**
     * Resolves the specified hostname to a socket address.
     * @param out The output socket address to store the resolved address.
     * @param hostname The hostname to resolve.
     * @param family The address family (default is SAF_INET).
     * @param port The port number to set for the socket address (default is 0).
     * @return An ERetCode indicating success or failure.
     */
    ERetCode SSocketAddress::resolve(SSocketAddress& out, const CString& hostname, uint16_t port, EAddressFamily family) {
        if (hostname.empty()) {
            return ERET_INVAL;
        }

        if (family < EAF_UNSPEC || family >= EAF_MAX || family == EAF_LOCAL) {
            return ERET_INVAL;
        }

        // --> initialize the network subsystem.
        ERetCode initResult = NetInit::init();
        if (initResult != ERET_OK) {
            return initResult;
        }

        // --
        const bool wannaInet = (family == EAF_UNSPEC || family == EAF_INET);
        const bool wannaInet6 = (family == EAF_UNSPEC || family == EAF_INET6);

        // --
        sockaddr_storage ss;
        // --> clear the sockaddr_storage structure.
        std::memset(&ss, 0, sizeof(ss));

        // --> try to parse the hostname as an IPv4 address.
        if (wannaInet && ::inet_pton(AF_INET, hostname.toPtr(), &((sockaddr_in*)&ss)->sin_addr)) {
            reinterpret_cast<sockaddr_in*>(&ss)->sin_family = AF_INET;
            out.size = sizeof(sockaddr_in);

            // --> retrieve the native sockaddr_in structure from the output socket address.
            sockaddr_in* sa = out.native<sockaddr_in>();

            // --> copy the contents of the temporary sockaddr_storage structure into the native sockaddr_in structure.
            std::memcpy(sa, &ss, sizeof(sockaddr_in));

            // --> set the port number for the native sockaddr_in structure.
            sa->sin_port = htons(port);
            return ERET_OK;
        }

        // --> try to parse the hostname as an IPv6 address.
        if (wannaInet6 && ::inet_pton(AF_INET6, hostname.toPtr(), &((sockaddr_in6*)&ss)->sin6_addr)) {
            reinterpret_cast<sockaddr_in6*>(&ss)->sin6_family = AF_INET6;
            out.size = sizeof(sockaddr_in6);

            // --> retrieve the native sockaddr_in6 structure from the output socket address.
            sockaddr_in6* sa6 = out.native<sockaddr_in6>();

            // --> copy the contents of the temporary sockaddr_storage structure into the native sockaddr_in6 structure.
            std::memcpy(sa6, &ss, sizeof(sockaddr_in6));

            // --> set the port number for the native sockaddr_in6 structure.
            sa6->sin6_port = htons(port);
            return ERET_OK;
        }

        // --> try to resolve the hostname using getaddrinfo.
        addrinfo hints{};
        hints.ai_family = SSocketAddress::toRawFamily(family);
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* res = nullptr;
        int resolveResult = ::getaddrinfo(hostname.toPtr(), nullptr, &hints, &res);
        if (resolveResult != 0) {
            return resolveErrorToRetCode(resolveResult);
        }
        if (!res) {
            return ERET_NOTFOUND;
        }

        addrinfo* cur = res;
        bool found = false;

        // --> iterate through the linked list of addrinfo structures to find a suitable address.
        while (cur) {
            if (wannaInet && cur->ai_family == AF_INET) {
                out.size = cur->ai_addrlen;
                found = true;

                // --> retrieve the native sockaddr_in structure from the output socket address.
                sockaddr_in* sa = out.native<sockaddr_in>();

                // --> copy the resolved IPv4 address into the output structure.
                std::memcpy(sa, cur->ai_addr, cur->ai_addrlen);

                // --> set the port number for the native sockaddr_in structure.
                sa->sin_port = htons(port);
                break;
            }

            if (wannaInet6 && cur->ai_family == AF_INET6) {
                out.size = cur->ai_addrlen;
                found = true;

                // --> retrieve the native sockaddr_in6 structure from the output socket address.
                sockaddr_in6* sa6 = out.native<sockaddr_in6>();

                // --> copy the resolved IPv6 address into the output structure.
                std::memcpy(sa6, cur->ai_addr, cur->ai_addrlen);

                // --> set the port number for the native sockaddr_in6 structure.
                sa6->sin6_port = htons(port);
                break;
            }

            cur = cur->ai_next;
        }

        ::freeaddrinfo(res);
        if (found) {
            return ERET_OK;
        }

        return ERET_NOTFOUND;
    }

    /**
     * Resolve the given hostname into a list of socket addresses.
     *
     * @param out The vector to store the resolved socket addresses.
     * @param hostname The hostname to resolve.
     * @param port The port number to set for the resolved addresses.
     * @return ERET_OK if at least one address was resolved, otherwise an error code.
     */
    ERetCode SSocketAddress::resolve(std::vector<SSocketAddress>& out, const CString& hostname, uint16_t port) {
        if (hostname.empty()) {
            return ERET_INVAL;
        }

        // --> initialize the network subsystem.
        ERetCode initResult = NetInit::init();
        if (initResult != ERET_OK) {
            return initResult;
        }

        // --
        sockaddr_storage ss;
        // --> clear the sockaddr_storage structure.
        std::memset(&ss, 0, sizeof(ss));

        // --> try to parse the hostname as an IPv4 address.
        if (::inet_pton(AF_INET, hostname.toPtr(), &((sockaddr_in*)&ss)->sin_addr)) {
            reinterpret_cast<sockaddr_in*>(&ss)->sin_family = AF_INET;
            SSocketAddress sa;

            sa.size = sizeof(sockaddr_in);
            sockaddr_in* sa4 = sa.native<sockaddr_in>();

            std::memcpy(sa4, &ss, sizeof(sockaddr_in));
            sa4->sin_port = htons(port);

            out.push_back(sa);
            return ERET_OK;
        }

        // --> try to parse the hostname as an IPv6 address.
        if (::inet_pton(AF_INET6, hostname.toPtr(), &((sockaddr_in6*)&ss)->sin6_addr)) {
            reinterpret_cast<sockaddr_in6*>(&ss)->sin6_family = AF_INET6;
            SSocketAddress sa;

            sa.size = sizeof(sockaddr_in6);
            sockaddr_in6* sa6 = sa.native<sockaddr_in6>();

            std::memcpy(sa6, &ss, sizeof(sockaddr_in6));
            sa6->sin6_port = htons(port);

            out.push_back(sa);
            return ERET_OK;
        }

        // --> try to resolve the hostname using getaddrinfo.
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* res = nullptr;
        int resolveResult = ::getaddrinfo(hostname.toPtr(), nullptr, &hints, &res);
        if (resolveResult != 0) {
            return resolveErrorToRetCode(resolveResult);
        }
        if (!res) {
            return ERET_NOTFOUND;
        }

        addrinfo* cur = res;
        bool hasAny = false;

        // --> iterate through the linked list of addrinfo structures to find a suitable address.
        while (cur) {
            if (cur->ai_family == AF_INET) {
                SSocketAddress sa;
                hasAny = true;

                sa.size = cur->ai_addrlen;
                sockaddr_in* sa4 = sa.native<sockaddr_in>();

                // --> copy the resolved IPv4 address into the output structure.
                std::memcpy(sa4, cur->ai_addr, cur->ai_addrlen);
                sa4->sin_port = htons(port);

                out.push_back(sa);
            }

            else if (cur->ai_family == AF_INET6) {
                SSocketAddress sa;
                hasAny = true;

                sa.size = cur->ai_addrlen;
                sockaddr_in6* sa6 = sa.native<sockaddr_in6>();

                // --> copy the resolved IPv6 address into the output structure.
                std::memcpy(sa6, cur->ai_addr, cur->ai_addrlen);
                sa6->sin6_port = htons(port);

                out.push_back(sa);
            }

            cur = cur->ai_next;
        }

        ::freeaddrinfo(res);
        if (hasAny) {
            return ERET_OK;
        }

        return ERET_NOTFOUND;
    }

    /**
     * Retrieves the local Unix domain socket address for the specified path.
     * @param out The output socket address to store the local address.
     * @param unix The path to the Unix domain socket.
     * @return An ERetCode indicating success or failure.
     */
    ERetCode SSocketAddress::local(SSocketAddress& out, const CString& path) {
        if (path.empty()) {
            return ERET_INVAL;
        }

        sockaddr_un saun;

        if (path.size() >= sizeof(saun.sun_path)) {
            return ERET_TOO_LONG;
        }

        // --> clear the sockaddr_un structure before use.
        std::memset(&saun, 0, sizeof(sockaddr_un));

        // --> set the address family to AF_UNIX and copy the path into the sockaddr_un structure.
        saun.sun_family = AF_UNIX;
        std::strncpy(saun.sun_path, path.toPtr(), sizeof(saun.sun_path) - 1);

        // --> copy the sockaddr_un structure into the output socket address.
        out.size = sizeof(sockaddr_un);
        std::memcpy(out.native<sockaddr_un>(), &saun, sizeof(sockaddr_un));

        // --
        return ERET_OK;
    }

    /**
     * Converts the socket address to a string representation.
     * @param out The output string to store the string representation.
     */
    void SSocketAddress::toString(CString& out) const {
        out.clear();

        if (size == 0) {
            return;
        }

        union {
            char inet[INET_ADDRSTRLEN + 1];
            char inet6[INET6_ADDRSTRLEN + 1];
        } bufs;

        switch (family()) {
            case EAF_INET: {
                const sockaddr_in* sa = native<sockaddr_in>();
                if (sa) {
                    memset(&bufs, 0, sizeof(bufs));
                    inet_ntop(AF_INET, &(sa->sin_addr), bufs.inet, sizeof(bufs.inet) - 1);
                    out = bufs.inet;
                }
                break;
            }

            case EAF_INET6: {
                const sockaddr_in6* sa = native<sockaddr_in6>();
                if (sa) {
                    memset(&bufs, 0, sizeof(bufs));
                    inet_ntop(AF_INET6, &(sa->sin6_addr), bufs.inet6, sizeof(bufs.inet6) - 1);
                    out = bufs.inet6;
                }
                break;
            }

            case EAF_UNIX: {
                const sockaddr_un* sa = native<sockaddr_un>();
                if (sa) {
                    out = sa->sun_path;
                }

                break;
            }

            default: {
                out = "<unknown>";
                break;
            }
        }

    }

} // namespace net
} // namespace certpp