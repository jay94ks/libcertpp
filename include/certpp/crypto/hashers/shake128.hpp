#ifndef __INCLUDE_CERTPP_CRYPTO_HASHERS_SHAKE128_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HASHERS_SHAKE128_HPP__

#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * SHAKE128, the 128-bit-security extendable-output function from the Keccak/SHA-3 family
     * (FIPS 202). Unlike this library's other IHasher implementations, SHAKE is a genuine XOF:
     * its output length isn't fixed by the algorithm, so it's fixed by the constructor argument
     * instead (matching IHasher::byteWidth()'s existing "one fixed size per instance" contract).
     * Identical in every respect to SHAKE256 (same sponge construction, same domain-separated
     * padding) except for its rate/capacity split -- see SHAKE256's own doc comment for why that
     * means both implementations share the Keccak-f[1600] permutation itself (KeccakCore,
     * src/crypto/hashers/) rather than duplicating it.
     */
    class CERTPP_API SHAKE128 : public IHasher {
    private:
        /**
         * Internal state for SHAKE128 computation.
         */
        struct Context {
            uint8_t state[200];  // --> The 1600-bit Keccak sponge state, byte-oriented.
            uint8_t buffer[168]; // --> Unabsorbed input, buffered until a full rate-sized block is available.
            size_t bufferLen;    // --> Number of valid bytes currently in buffer (0-167).
            bool squeezing;      // --> True once the padding/permutation has run (push() rejects further input).
            size_t squeezePos;   // --> squeeze()'s cursor into the current rate block (0-168); unused by finish().
        };

    private:
        Context _ctx;

        /**
         * Applies SHAKE's domain-separated multi-rate padding and absorbs the final block,
         * switching the sponge from absorbing to squeezing. Idempotent -- whichever of finish()
         * or squeeze() runs first does the work, and the other finds it already done.
         */
        void finalizeAbsorption();

        static constexpr size_t RATE = 168; // 1344 bits -- SHAKE128's rate (capacity = 256 bits)

    public:
        /**
         * Constructs a SHAKE128 hasher, ready to accept input.
         * @param outputBytes The number of output bytes finish() will produce.
         */
        explicit SHAKE128(size_t outputBytes = 32) : IHasher(outputBytes) {
            reset();
        }

        /**
         * Resets the SHAKE128 context to its initial state.
         */
        void reset() override;

        /**
         * Pushes data into the SHAKE128 context for absorption.
         * @param buf The input data to be hashed.
         * @return The number of bytes processed.
         */
        size_t push(const SReadOnlyByteSpan& buf) override;

        /**
         * Finalizes absorption (applying the SHAKE domain-separated padding) and squeezes
         * byteWidth() bytes of output -- the first byteWidth() bytes of this instance's output
         * stream. Squeezes from a copy of the sponge state, so it may be called more than once
         * and returns the same bytes every time.
         * @param out The output buffer to store the result (at least byteWidth() bytes).
         * @return True if the output was successfully produced, false otherwise.
         */
        bool finish(SByteSpan& out) override;

        /**
         * Squeezes the next out.size bytes of this instance's output stream, advancing the sponge
         * -- the genuine extendable-output interface, for a caller that needs an arbitrary and
         * possibly unbounded amount of output rather than the one fixed length byteWidth() fixes.
         * Finalizes absorption on the first call, exactly as finish() does, so push() is rejected
         * afterwards.
         *
         * Successive calls continue where the previous one stopped, so squeezing n bytes in any
         * combination of chunk sizes yields the same n bytes. byteWidth() does not constrain it.
         * FIPS 203/204 need this: their rejection samplers read from a SHAKE stream until enough
         * candidates are accepted, with no length known in advance.
         *
         * Do not interleave this with finish(). finish() always reports the stream's first
         * byteWidth() bytes and deliberately leaves this cursor alone, so calling it after
         * squeeze() has advanced the sponge returns continuation bytes rather than the first
         * ones. Pick one of the two per instance.
         * @param out The output buffer; exactly out.size bytes are written.
         * @return True if the output was successfully produced, false otherwise.
         */
        bool squeeze(const SByteSpan& out);
    };

} // namespace crypto
} // namespace certpp

#endif
