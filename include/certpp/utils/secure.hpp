#ifndef __INCLUDE_CERTPP_UTILS_SECURE_HPP__
#define __INCLUDE_CERTPP_UTILS_SECURE_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include <cstddef>
#include <new>
#include <utility>

namespace certpp {

    /**
     * Operations on secret bytes that must not leak through timing or survive in memory:
     * zeroization that the compiler is not allowed to elide, and comparison/selection whose
     * running time depends only on the length of its inputs, never on their contents.
     *
     * Three things this cannot do, and that a caller still has to think about:
     *
     * - It cannot reach a copy the compiler made. A secret that was spilled to a register or a
     *   stack slot outside the buffer passed in stays there; zero() clears the buffer it is
     *   given and nothing else. Keeping secrets in as few places as possible is still the
     *   caller's job.
     * - It cannot hide a length. equalsMask() and select() both read every byte of their inputs
     *   unconditionally, so the *contents* leak nothing -- but the size does, and
     *   mismatched-length inputs are reported immediately. That is the right trade for every
     *   use in this library, where lengths are fixed by the algorithm and public.
     * - "Constant-time" here means the source contains no data-dependent branch, memory access
     *   or division. That is as far as portable C++ reaches; it is not a guarantee about any
     *   particular compiler's output, still less about a CPU's microarchitecture.
     *
     * The inline mask arithmetic in RSA's EME-PKCS1-v1_5 unpadding and CbcTransformer's PKCS#7
     * padding check is deliberately *not* rewritten in terms of this class. Neither of those is
     * "compare two buffers" or "choose between two buffers": they interleave masking with a scan
     * over the padding, so there is nothing here for them to call.
     */
    class CERTPP_API CSecure {
    public:
        /**
         * Overwrites a buffer with zeroes in a way the compiler may not optimize away, for
         * clearing key material, intermediate secrets and the like before they go out of scope.
         *
         * An ordinary memset() over a local buffer that is never read again is dead code, and
         * compilers do remove it; this routes the same memset through a volatile function
         * pointer, so the call cannot be proven to have no effect and therefore cannot be
         * dropped.
         * @param buffer The bytes to clear. A null or empty span is a no-op.
         */
        static void zero(const SByteSpan& buffer);

        /**
         * Compares two byte spans in time that depends only on their length, yielding a mask
         * rather than a bool so that a caller can act on the result without branching on it.
         *
         * Unlike memcmp(), this reads every byte of both inputs even once a difference is known
         * -- memcmp() stops at the first mismatch, so its running time reveals the length of the
         * matching prefix.
         * @param first The first span.
         * @param second The second span.
         * @return 0xFF if the spans have the same length and the same contents (two empty spans
         * included); 0x00 otherwise.
         */
        static uint8_t equalsMask(
            const SReadOnlyByteSpan& first, const SReadOnlyByteSpan& second
        );

        /**
         * Reports whether two byte spans are equal, in time that depends only on their length.
         *
         * Prefer equalsMask() with select() where the comparison's outcome is itself a secret --
         * as the Fujisaki-Okamoto transform's re-encryption check is, since whether a ciphertext
         * was valid is exactly what must not be observable. This overload's bool makes the next
         * branch the caller's, which is right only when that one bit is not sensitive (a MAC
         * check whose failure is reported anyway, say).
         * @param first The first span.
         * @param second The second span.
         * @return true if the spans have the same length and the same contents.
         */
        static inline bool equals(
            const SReadOnlyByteSpan& first, const SReadOnlyByteSpan& second
        ) {
            return equalsMask(first, second) != 0;
        }

        /**
         * Copies one of two spans into out according to a mask, without branching on it: out
         * receives ifSet where mask is 0xFF and ifClear where it is 0x00.
         *
         * The mask must be one equalsMask() produces -- all ones or all zeroes. Any other value
         * mixes the two inputs bit by bit, which is not a useful result but is not checked for,
         * since checking would mean branching on it.
         * @param mask 0xFF to select ifSet, 0x00 to select ifClear.
         * @param ifSet The span copied when mask is 0xFF.
         * @param ifClear The span copied when mask is 0x00.
         * @param out Receives the selected bytes; may alias neither input.
         * @return true on success; false if any span is null or the three sizes differ.
         */
        static bool select(
            uint8_t mask, const SReadOnlyByteSpan& ifSet, const SReadOnlyByteSpan& ifClear,
            const SByteSpan& out
        );

        /**
         * Allocates an aligned block from a page-backed pool that the operating system has locked
         * against paging. Small simultaneous allocations share locked pages; a larger allocation
         * may span multiple pages. No ordinary-heap fallback is used when page allocation or
         * locking fails. Default builds prefer OS large pages and retry with locked standard
         * pages when unavailable; CERTPP_DISABLE_LARGE_PAGE selects standard pages directly.
         * CERTPP_DISABLE_SECURE_MEM replaces this backend with aligned ordinary-heap allocation.
         *
         * The alignment must be a nonzero power of two. The returned block remains nonpageable
         * until dealloc() releases it, and must be released only through dealloc().
         * @param out Receives the allocated block and is set to null on failure.
         * @param sz Number of usable bytes to allocate; must be nonzero.
         * @param alignment Required address alignment in bytes; must be a power of two.
         * @return ERET_OK on success; ERET_INVAL for invalid arguments; ERET_NOMEM when a page
         *         cannot be allocated or locked.
         */
        static ERetCode alloc(void** out, size_t sz, size_t alignment);

        /**
         * Allocates a block with at least 16-byte alignment, or the platform's fundamental
         * object alignment when that is greater. This lets byte-oriented protected containers
         * feed ordinary SIMD and AES/SHA hardware paths without copying to an aligned buffer.
         * @param out Receives the allocated block and is set to null on failure.
         * @param sz Number of usable bytes to allocate; must be nonzero.
         * @return The result of the aligned alloc() overload.
         */
        static ERetCode alloc(void** out, size_t sz);

        /**
         * Allocates a block of memory of the specified size and returns a pointer to it.
         * Memory blocks allocated by this function should be deallocated using the corresponding deallocation function.
         * Because this locks the memory to prevent it from being swapped out, it may have performance implications.
         * Returns nullptr if the allocation fails.
         *
         * @param sz The size of the memory block to allocate.
         * @return Pointer to the allocated memory block, or nullptr on failure.
         */
        static inline void* alloc(size_t sz) {
            constexpr size_t DEFAULT_ALIGNMENT =
                alignof(std::max_align_t) < 16 ? size_t(16) : alignof(std::max_align_t);
            return alloc(sz, DEFAULT_ALIGNMENT);
        }

        /**
         * Allocates an aligned block from locked page-backed storage and returns its address.
         * @param sz Number of usable bytes to allocate; must be nonzero.
         * @param alignment Required address alignment in bytes; must be a power of two.
         * @return Pointer to the allocated block, or nullptr on failure.
         */
        static inline void* alloc(size_t sz, size_t alignment) {
            void* out = nullptr;

            if (CSecure::alloc(&out, sz, alignment) != ERET_OK) {
                return nullptr;
            }

            return out;
        }

        /**
         * Wipes and releases a block returned by alloc(). Its page remains protected while
         * another live block shares it; the last release wipes the complete page, unlocks a
         * standard-page mapping when needed, and returns it to the operating system. Passing
         * nullptr is a successful no-op. With CERTPP_DISABLE_SECURE_MEM, this performs the
         * matching ordinary aligned free without locking or wiping.
         *
         * @param ptr Pointer to the memory block to deallocate.
         * @return ERET_OK on success; an appropriate error code otherwise.
         */
        static ERetCode dealloc(void* ptr);

        /**
         * Creates a shared pointer to an object of type T, allocating it using CSecure::alloc.
         * The object is constructed in-place with the provided arguments.
         * The shared pointer will automatically deallocate the memory using CSecure::dealloc when it is no longer needed.
         *
         * @tparam T The type of the object to create.
         * @tparam TArgs The types of the constructor arguments.
         * @param args The constructor arguments.
         * @return A shared pointer to the newly created object, or nullptr if allocation fails.
         */
        template<typename T, typename... TArgs>
        static inline std::shared_ptr<T> make(TArgs&& ... args) {
            void* raw = CSecure::alloc(sizeof(T), alignof(T));
            if (!raw) {
                return nullptr;
            }

            T* obj = nullptr;
            try {
                obj = new (raw) T(std::forward<TArgs>(args)...);
            } catch (...) {
                CSecure::dealloc(raw);
                throw;
            }

            return std::shared_ptr<T>(obj, [](T* ptr) {
                if (ptr) {
                    ptr->~T();
                    CSecure::dealloc(ptr);
                }
            });
        }
    };

} // namespace certpp

#endif
