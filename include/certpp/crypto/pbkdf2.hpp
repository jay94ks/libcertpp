#ifndef __INCLUDE_CERTPP_CRYPTO_PBKDF2_HPP__
#define __INCLUDE_CERTPP_CRYPTO_PBKDF2_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * PBKDF2 (RFC 8018 section 5.2), the iterated password-based key derivation function, over
     * any hash `CHmac` supports.
     *
     * **This is not interchangeable with `CHkdf`, and the difference is the entire point.** HKDF
     * is built to be fast: it runs two HMACs over a secret that already has full entropy, and
     * being fast costs it nothing because guessing the input is hopeless. A password does not
     * have full entropy, so a KDF over one has exactly one defence -- making each guess
     * expensive. That is what `iterations` buys, and it is why feeding a password to `CHkdf`
     * produces a key that is derived correctly and cracked at the attacker's line rate.
     *
     * `DK = T(1) || T(2) || ... || T(l)`, where each block is the XOR of `iterations`
     * chained HMACs:
     *
     * - `U(1) = PRF(password, salt || INT(i))`, with `INT(i)` the block number as four
     *   big-endian bytes, counting from 1.
     * - `U(j) = PRF(password, U(j-1))` -- note that only the *first* HMAC of a block sees the
     *   salt; every one after it takes the previous output as its whole message.
     * - `T(i) = U(1) ^ U(2) ^ ... ^ U(iterations)`.
     *
     * The XOR over *all* the U values, rather than just keeping the last, is the detail that an
     * implementation most often gets wrong: dropping it gives output that is self-consistent,
     * costs the same to compute, and matches nothing. RFC 6070's vectors are the only cheap way
     * to catch it.
     *
     * Three things about the parameters are worth stating outright:
     *
     * - **An iteration count of 0 is invalid, not "no iterations".** RFC 8018 defines `c` as a
     *   positive integer, and `T(i)` is the XOR of at least `U(1)`; a count of 0 would leave
     *   the block undefined rather than leaving the derivation unstretched. It is rejected with
     *   `ERET_BADREQ`, since the one thing it must not do is silently become a cheap derivation.
     * - **The output length is bounded**, at `(2^32 - 1) * hLen`, because `INT(i)` is a 32-bit
     *   counter. See `maxDeriveBytes()`; the bound is astronomically larger than any real
     *   request, and is checked anyway so that a length computed from attacker-supplied data
     *   cannot wrap the counter back round to block 1 and repeat the keystream.
     * - **The salt is not secret, but it must be unique per derivation.** Two keys derived from
     *   one password and one salt are the same key, and a salt shared across users turns one
     *   precomputation into a break of all of them. RFC 8018 4.1 asks for at least 64 bits
     *   from a random source; this class does not enforce a minimum, because a caller
     *   reproducing somebody else's container has to accept whatever salt is in it.
     *
     * There is no `IKdf` interface here yet, for the reason `CHkdf`'s doc comment gives: the two
     * KDFs in this library take parameters that do not line up (salt plus iteration count
     * against salt plus `info`), and an interface wide enough for both would describe neither.
     * The shared shape is a static `derive()` taking spans, which is enough.
     */
    class CERTPP_API CPbkdf2 {
    public:
        /**
         * PBKDF2 (RFC 8018 5.2).
         *
         * @param hasherType The hash to run HMAC over as the PRF.
         * @param password The password; any length, including empty. Passed as bytes, so the
         * caller owns the encoding question -- a password containing non-ASCII characters
         * derives different keys under UTF-8 and UTF-16, and an interoperating implementation
         * has to agree.
         * @param salt The salt; non-secret, but see this class's doc comment on uniqueness. May
         * be empty, which is permitted and inadvisable.
         * @param iterations The iteration count; must be at least 1.
         * @param out Receives the derived key; at most `maxDeriveBytes()` bytes, and must not
         * be empty.
         * @return ERET_OK on success; ERET_NOTSUP if HMAC is not defined over hasherType;
         * ERET_BADREQ if iterations is 0, out is empty, or out is longer than the counter
         * allows.
         */
        static ERetCode derive(
            EHashers hasherType, const SReadOnlyByteSpan& password,
            const SReadOnlyByteSpan& salt, uint32_t iterations, const SByteSpan& out
        );

        /**
         * The largest output `derive()` can produce for a hash: `(2^32 - 1) * hLen`, saturated
         * to `size_t` where that product does not fit.
         *
         * @param hasherType The hash algorithm.
         * @return The limit in bytes, or 0 if HMAC is not defined over hasherType.
         */
        static size_t maxDeriveBytes(EHashers hasherType);
    };

} // namespace crypto
} // namespace certpp

#endif
