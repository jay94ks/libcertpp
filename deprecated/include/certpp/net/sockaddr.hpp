#ifndef __INCLUDE_CERTPP_NET_SOCKADDR_HPP__
#define __INCLUDE_CERTPP_NET_SOCKADDR_HPP__

#include <certpp/common.hpp>
#include <certpp/string.hpp>

namespace certpp {
namespace net {

    /**
     * Represents the address family of a socket address.
     */
    enum EAddressFamily {
        EAF_UNSPEC = 0,
        EAF_INET,       /**< IPv4 address family. */
        EAF_INET6,      /**< IPv6 address family. */
        EAF_UNIX,       /**< Unix domain socket address family. */

        // --
        EAF_MAX,        /**< Maximum value for the socket address family. */
        EAF_LOCAL = EAF_UNIX,   /**< Local (alias for Unix domain) socket address family. */
    };

    /**
     * Represents a network socket address.
     */
    struct CERTPP_API SSocketAddress {
        uint8_t raw[128];  /**< The raw bytes representing the socket address. */
        size_t size;       /**< The size of the socket address in bytes. */

        /**
         * Default constructor initializes the socket address to an empty state.
         */
        SSocketAddress() : size(0) {}

        /**
         * Copy constructor.
         */
        SSocketAddress(const SSocketAddress& other);

        /**
         * Move constructor.
         */
        SSocketAddress(SSocketAddress&& other);

        /**
         * Copy assignment operator.
         */
        SSocketAddress& operator=(const SSocketAddress& other);

        /**
         * Move assignment operator.
         */
        SSocketAddress& operator=(SSocketAddress&& other);

        /**
         * Retrieves the native socket address structure.
         * @tparam TNativeSA The type of the native socket address structure.
         * @return A pointer to the native socket address structure.
         */
        template<typename TNativeSA>
        inline const TNativeSA* native() const {
            if (size != sizeof(TNativeSA)) {
                return nullptr;
            }

            return reinterpret_cast<const TNativeSA*>(raw);
        }

        /**
         * Retrieves the native socket address structure (non-const version).
         * @tparam TNativeSA The type of the native socket address structure.
         * @return A pointer to the native socket address structure.
         */
        template<typename TNativeSA>
        inline TNativeSA* native() {
            if (size != sizeof(TNativeSA)) {
                return nullptr;
            }

            return reinterpret_cast<TNativeSA*>(raw);
        }

        /**
         * Checks if the socket address is empty.
         * @return True if the socket address is empty, false otherwise.
         */
        inline bool empty() const {
            return size == 0;
        }

        /**
         * Checks if the socket address is valid (non-empty).
         * @return True if the socket address is valid, false otherwise.
         */
        inline operator bool() const {
            return !empty();
        }

        /**
         * Checks if the socket address is invalid (empty).
         * @return True if the socket address is invalid, false otherwise.
         */
        inline bool operator!() const {
            return empty();
        }

        /**
         * Clears the socket address, setting it to an empty state.
         */
        inline void clear() { size = 0; }

        /**
         * Converts an EAddressFamily value to its corresponding raw address family value.
         * @param family The EAddressFamily value to convert.
         * @return The raw address family value as an integer.
         */
        static int32_t toRawFamily(EAddressFamily family);

        /**
         * Retrieves the address family of the socket address.
         * @return The address family as an ESocketAddressFamily value.
         */
        EAddressFamily family() const;

        /**
         * Retrieves the port number of the socket address.
         * @return The port number in host byte order.
         * @note Returns -1 if the socket address is empty or the address family is unsupported.
         */
        int32_t port() const;

        /**
         * Sets the port number of the socket address.
         * @param v The port number to set (in host byte order).
         * @return An ERetCode indicating success or failure.
         * @note Returns ERET_INVAL for EAF_UNSPEC, or ERET_NOTSUP for an unsupported address family.
         */
        ERetCode port(uint16_t v);

        /**
         * Retrieves the "any" address (e.g., 0.0.0.0 for IPv4 or :: for IPv6) corresponding to the specified address family.
         *
         * @param out The output socket address to store the "any" address.
         * @param port The port number to set for the socket address (default is 0).
         * @param family The address family (default is EAF_INET).
         * @return An ERetCode indicating success or failure.
         * @note Returns ERET_INVAL for EAF_UNSPEC, or ERET_NOTSUP for an unsupported address family.
         */
        static ERetCode any(SSocketAddress& out, uint16_t port = 0, EAddressFamily family = EAF_INET);

        /**
         * Retrieves the loopback address (e.g., 127.0.0.1 for IPv4 or ::1 for IPv6) corresponding to the specified address family.
         *
         * @param out The output socket address to store the loopback address.
         * @param port The port number to set for the socket address (default is 0).
         * @param family The address family (default is EAF_INET).
         * @return An ERetCode indicating success or failure.
         * @note Returns ERET_INVAL for an empty hostname or invalid family, and ERET_NOTFOUND when the hostname cannot be resolved.
         */
        static ERetCode loopback(SSocketAddress& out, uint16_t port = 0, EAddressFamily family = EAF_INET);

        /**
         * Determines whether this socket address is a loopback address.
         * @return True if the socket address is a loopback address, false otherwise.
         */
        bool loopback() const;

        /**
         * Resolves the specified hostname to a socket address.
         * @param out The output socket address to store the resolved address.
         * @param hostname The hostname to resolve.
         * @param family The address family (default is EAF_INET).
         * @param port The port number to set for the socket address (default is 0).
         * @return An ERetCode indicating success or failure.
         * @note Returns ERET_INVAL for an empty hostname, and ERET_NOTFOUND when no addresses can be resolved.
         */
        static ERetCode resolve(SSocketAddress& out, const CString& hostname, uint16_t port = 0, EAddressFamily family = EAF_INET);

        /**
         * Resolves the specified hostname to multiple socket addresses.
         * @param out The output vector to store the resolved addresses.
         * @param hostname The hostname to resolve.
         * @param port The port number to set for the socket addresses (default is 0).
         * @return An ERetCode indicating success or failure.
         * @note Returns ERET_INVAL if the socket address is empty, or ERET_NOTSUP if the address family is unsupported.
         */
        static ERetCode resolve(std::vector<SSocketAddress>& out, const CString& hostname, uint16_t port = 0);

        /**
         * Retrieves the local Unix domain socket address for the specified path.
         * @param out The output socket address to store the local address.
         * @param path The path to the Unix domain socket.
         * @return An ERetCode indicating success or failure.
         * @note Returns ERET_INVAL if the socket address is empty, or ERET_TOO_LONG if the path exceeds the maximum allowed length.
         */
        static ERetCode local(SSocketAddress& out, const CString& path);

        /**
         * Converts the socket address to a string representation.
         * @param out The output string to store the string representation.
         */
        void toString(CString& out) const;

        /**
         * Converts the socket address to a string representation and returns it as a CString.
         * @return The string representation of the socket address.
         */
        inline CString toString() const {
            CString out;
            toString(out);
            return out;
        }
    };

} // namespace net
} // namespace certpp

#endif