#ifndef __INCLUDE_CERTPP_CRYPTO_RNG_HPP__
#define __INCLUDE_CERTPP_CRYPTO_RNG_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {
namespace crypto {

    /**
     * Random number generation utility, backed directly by the operating system's CSPRNG
     * (BCryptGenRandom on Windows; /dev/urandom on POSIX) rather than any third-party
     * library, falling back to std::random_device only if the OS API is unavailable and
     * the CERTPP_RNG_FALLBACK build option (ON by default) is enabled.
     */
    class CERTPP_API CRng {
    private:
        /**
         * Fallback used only if the OS CSPRNG is unavailable; fills out via std::random_device
         * when CERTPP_RNG_FALLBACK is enabled, or reports ERET_NOTSUP otherwise.
         */
        static ERetCode fillFallback(const SByteSpan& out);

    public:
        /**
         * Fills out with random bytes.
         * @param out The buffer to fill.
         * @return ERET_OK on success; ERET_NOTSUP if the OS entropy source failed and the
         *         std::random_device fallback is disabled; ERET_UNKNOWN if the fallback
         *         itself failed.
         */
        static ERetCode fill(const SByteSpan& out);

        /**
         * Fills out with random bytes.
         * @tparam T The type of the elements in the buffer.
         * @param out The buffer to fill.
         * @param size The number of elements in the buffer.
         * @return ERET_OK on success; ERET_NOTSUP if the OS entropy source failed and the
         *         std::random_device fallback is disabled; ERET_UNKNOWN if the fallback
         *         itself failed.
         */
        template<typename T>
        static inline ERetCode fill(T& out, size_t size) {
            return fill(SByteSpan(reinterpret_cast<uint8_t*>(&out), size));
        }

        /**
         * Fills out with random nonzero bytes, via rejection sampling over fill(). Needed by
         * padding schemes that forbid zero bytes (e.g. RSAES-PKCS1-v1_5, RFC 8017 7.2.1).
         * @param out The buffer to fill.
         * @return ERET_OK on success; the first failing fill() call's ERetCode otherwise.
         */
        static ERetCode fillNonZero(const SByteSpan& out);
    };

} // namespace crypto
} // namespace certpp

#endif
