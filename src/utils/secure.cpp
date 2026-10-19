#include <certpp/utils/secure.hpp>
#include "securepool.hpp"
#include <cstdlib>
#include <cstring>

#if defined(_WIN32)
#include <malloc.h>
#endif

namespace certpp {

    namespace {

        /* Reaching memset through a volatile call target prevents dead-store elimination. */
        void* (* volatile const SECURE_MEMSET)(void*, int, size_t) = &std::memset;

#if defined(CERTPP_DISABLE_SECURE_MEM)
        bool isPowerOfTwo(size_t value) {
            return value != 0 && (value & (value - 1)) == 0;
        }

        ERetCode allocateOrdinary(void** out, size_t size, size_t alignment) {
            if (!out) {
                return ERET_INVAL;
            }
            *out = nullptr;

            if (size == 0 || !isPowerOfTwo(alignment)) {
                return ERET_INVAL;
            }

            if (alignment < sizeof(void*)) {
                alignment = sizeof(void*);
            }
#if defined(_WIN32)
            *out = _aligned_malloc(size, alignment);
            return *out ? ERET_OK : ERET_NOMEM;
#else
            void* allocated = nullptr;
            if (posix_memalign(&allocated, alignment, size) != 0) {
                return ERET_NOMEM;
            }
            *out = allocated;
            return ERET_OK;
#endif
        }

        ERetCode releaseOrdinary(void* ptr) {
            if (!ptr) {
                return ERET_OK;
            }

#if defined(_WIN32)
            _aligned_free(ptr);
#else
            std::free(ptr);
#endif
            return ERET_OK;
        }
#endif

    } // namespace

    /* Overwrites a buffer with zeroes in a way the compiler may not optimize away. */
    void CSecure::zero(const SByteSpan& buffer) {
        if (!buffer.data || buffer.size == 0) {
            return;
        }
        SECURE_MEMSET(buffer.data, 0, buffer.size);
    }

    /* Compares two byte spans in time that depends only on their length. */
    uint8_t CSecure::equalsMask(const SReadOnlyByteSpan& first, const SReadOnlyByteSpan& second) {
        // The length is public (see the class doc comment), so returning early on a mismatch
        // leaks nothing the caller didn't already know.
        if (first.size != second.size) {
            return 0x00u;
        }
        if (first.size == 0) {
            return 0xFFu; // two empty spans are equal, and neither pointer is dereferenced
        }
        if (!first.data || !second.data) {
            return 0x00u;
        }

        // Every byte is read whatever the outcome -- no break, no early return. The bulk
        // memcmp() operation would stop at the first mismatch and leak the matching prefix.
        uint8_t diff = 0;
        for (size_t i = 0; i < first.size; ++i) {
            diff = uint8_t(diff | uint8_t(first.data[i] ^ second.data[i]));
        }

        // Fold zero to 0xFF and every nonzero byte to 0x00 without a comparison branch.
        return uint8_t((uint8_t(diff | uint8_t(~diff + 1)) >> 7) - 1);
    }

    /* Copies one of two spans into out according to a mask, without branching on it. */
    bool CSecure::select(
        uint8_t mask, const SReadOnlyByteSpan& ifSet, const SReadOnlyByteSpan& ifClear,
        const SByteSpan& out
    ) {
        if (!ifSet.data || !ifClear.data || !out.data) {
            return false;
        }
        if (ifSet.size != out.size || ifClear.size != out.size) {
            return false;
        }

        const uint8_t inverse = uint8_t(~mask);
        for (size_t i = 0; i < out.size; ++i) {
            out.data[i] = uint8_t((ifSet.data[i] & mask) | (ifClear.data[i] & inverse));
        }
        return true;
    }

    /* Allocates an aligned block from locked, page-backed storage. */
    ERetCode CSecure::alloc(void** out, size_t sz, size_t alignment) {
#if defined(CERTPP_DISABLE_SECURE_MEM)
        return allocateOrdinary(out, sz, alignment);
#else
        return SecurePool::instance().allocate(out, sz, alignment);
#endif
    }

    /* Allocates a SIMD-ready block from the selected CSecure storage backend. */
    ERetCode CSecure::alloc(void** out, size_t sz) {
        constexpr size_t DEFAULT_ALIGNMENT =
            alignof(std::max_align_t) < 16 ? size_t(16) : alignof(std::max_align_t);
        return alloc(out, sz, DEFAULT_ALIGNMENT);
    }

    /* Wipes and releases one block, returning an empty page to the operating system. */
    ERetCode CSecure::dealloc(void* ptr) {
#if defined(CERTPP_DISABLE_SECURE_MEM)
        return releaseOrdinary(ptr);
#else
        return SecurePool::instance().release(ptr);
#endif
    }

} // namespace certpp
