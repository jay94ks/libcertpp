#ifndef __INCLUDE_CERTPP_COMMON_HPP__
#define __INCLUDE_CERTPP_COMMON_HPP__

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <tuple>
#include <string>
#include <vector>
#include <list>
#include <map>
#include <new>

/**
 * Defines the CERTPP_API macro for shared library support.
 * This macro ensures proper symbol export/import when building or using the shared library.
 */
#if defined(__SHARED_LIBCERTPP__) && __SHARED_LIBCERTPP__
    #if defined(__COMPILES_LIBCERTPP__) && __COMPILES_LIBCERTPP__
        #if defined(_MSC_VER)
            #define CERTPP_API __declspec(dllexport)
        #else
            #define CERTPP_API
        #endif
    #else
        #if defined(_MSC_VER)
            #define CERTPP_API __declspec(dllimport)
        #else
            #define CERTPP_API
        #endif
    #endif
#else
    #define CERTPP_API
#endif

namespace certpp {

    using uint8_t = ::uint8_t;
    using uint16_t = ::uint16_t;
    using uint32_t = ::uint32_t;
    using uint64_t = ::uint64_t;

    using int8_t = ::int8_t;
    using int16_t = ::int16_t;
    using int32_t = ::int32_t;
    using int64_t = ::int64_t;

    using float32_t = float;
    using float64_t = double;

    using size_t = ::size_t;
    using ptrdiff_t = ::ptrdiff_t;
    using offset_t = ::off_t;
    using nullptr_t = decltype(nullptr);

    /**
     * Represents the result of an operation, typically used to indicate success or various error conditions.
     */
    enum ERetCode : uint8_t {
        ERET_OK = 0,
        ERET_UNKNOWN    = 0xffu,     // --> Unknown error

        // --
        ERET_INVAL      = 0x01u,     // --> Invalid argument
        ERET_BADREQ     = 0x02u,     // --> Bad request
        ERET_NOMEM      = 0x03u,     // --> Out of memory, No memory available.
        ERET_NOTSUP     = 0x04u,     // --> Not supported
        ERET_NOSPC      = 0x05u,     // --> No space available
        ERET_TIMEOUT    = 0x06u,     // --> Operation timed out
        ERET_BUSY       = 0x07u,     // --> Resource is busy
        ERET_NOTIMPL    = 0x08u,     // --> Not implemented
        ERET_ALREADY    = 0x09u,     // --> Already exists or already in the desired state
        ERET_AGAIN      = 0x0au,     // --> Try again (e.g., temporary failure)
        ERET_NOTFOUND   = 0x0bu,     // --> The thing looked for is not there, which for a search
                                     // is an ordinary outcome rather than a failure. Distinct
                                     // from ERET_BADREQ, which says the input was wrong.

        // --
        ERET_KEY_ERROR  = 0x10u,     // --> Public/Private key error (e.g. mismatch or invalid combination).
        ERET_KEY_SIZE   = 0x11u,     // --> Key size error (e.g., invalid key length)
        ERET_KEY_FORMAT = 0x12u,     // --> Key format error (e.g., invalid key encoding)
        ERET_KEY_EMPTY  = 0x13u,     // --> Key is empty or uninitialized
        ERET_KEY_PARAM  = 0x14u,     // --> Key parameter error (e.g., invalid or missing parameter)
        ERET_KEY_COMP   = 0x15u,     // --> Key compression error (e.g., invalid or unsupported compression)

        // --
        ERET_HASH_PIPE  = 0x16u,     // --> Hash pipeline error (e.g., failed during hash processing)
    };

    /**
     * Swaps the values of two objects of the same type.
     *
     * @tparam T The type of the objects to swap.
     * @param a The first object.
     * @param b The second object.
     * @return A reference to the first object after the swap.
     */
    using std::swap;

    /**
     * Moves the value of an object to another object of the same type.
     *
     * @tparam T The type of the object to move.
     * @param t The object to move.
     * @return An rvalue reference to the moved object.
     */
    using std::move;

} // namespace certpp

#endif
