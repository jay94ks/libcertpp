#ifndef __INCLUDE_CERTPP_CRYPTO_RNG_HPP__
#define __INCLUDE_CERTPP_CRYPTO_RNG_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include <memory>

namespace certpp {
namespace crypto {

    /**
     * Interface for random number generators.
     */
    class CERTPP_API IRng {
    public:
        virtual ~IRng() = default;

        /**
         * Creates an independently owned copy of this generator.
         * @param out Receives the cloned generator and is reset on failure.
         * @return ERET_OK on success; ERET_NOMEM if the clone could not be allocated; another
         *         ERetCode if the concrete generator cannot be cloned.
         */
        virtual ERetCode clone(std::shared_ptr<IRng>& out) const = 0;

        /**
         * Fills out with random bytes.
         * @param out The buffer to fill.
         * @return ERET_OK on success; ERET_NOTSUP if the OS entropy source failed and the
         *         std::random_device fallback is disabled; ERET_UNKNOWN if the fallback
         *         itself failed.
         */
        virtual ERetCode fillTo(const SByteSpan& out) const = 0;

        /**
         * Fills out with random nonzero bytes, repeatedly drawing through fillTo() and rejecting
         * zero bytes without bias.
         * @param out The buffer to fill.
         * @return ERET_OK on success; ERET_NOMEM if the temporary buffer could not be allocated;
         *         otherwise the error returned by fillTo().
         */
        virtual ERetCode fillNonZeroTo(const SByteSpan& out) const;
    };

    /**
     * Random number generation utility, backed directly by the operating system's CSPRNG
     * (BCryptGenRandom on Windows; /dev/urandom on POSIX) rather than any third-party
     * library, falling back to std::random_device only if the OS API is unavailable and
     * the CERTPP_RNG_FALLBACK build option (OFF by default) is enabled.
     */
    class CERTPP_API CRng : public IRng {
    public:
        CRng() = default;
        ~CRng() override = default;

    public:
        /**
         * Fills out with random bytes.
         * @param out The buffer to fill.
         * @return ERET_OK on success; ERET_NOTSUP if the OS entropy source failed and the
         *         std::random_device fallback is disabled; ERET_UNKNOWN if the fallback
         *         itself failed.
         */
        ERetCode fillTo(const SByteSpan& out) const override;

        /** Creates an independently owned CRng instance. */
        ERetCode clone(std::shared_ptr<IRng>& out) const override;

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
        static inline ERetCode fill(const SByteSpan& out) {
            return CRng().fillTo(out);
        }

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
            return fill(SByteSpan(reinterpret_cast<uint8_t*>(&out), sizeof(T) * size));
        }

        /**
         * Fills out with random nonzero bytes, via rejection sampling over fill(). Needed by
         * padding schemes that forbid zero bytes (e.g. RSAES-PKCS1-v1_5, RFC 8017 7.2.1).
         * @param out The buffer to fill.
         * @return ERET_OK on success; the first failing fill() call's ERetCode otherwise.
         */
        static inline ERetCode fillNonZero(const SByteSpan& out) {
            return CRng().fillNonZeroTo(out);
        }
    };

} // namespace crypto
} // namespace certpp

#endif
