#ifndef __INCLUDE_CERTPP_CRYPTO_HKDF_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HKDF_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * HKDF (RFC 5869), the extract-then-expand key derivation function, over any hash `CHmac`
     * supports.
     *
     * A concrete utility rather than one implementation of an `IKdf` family, for the same reason
     * `CRng` is: there is no second KDF here yet, and HKDF's two-step shape does not generalize
     * to a password-based KDF like PBKDF2 (salt plus iteration count, no `info`) without an
     * interface that fits neither well. If PBKDF2 arrives, introduce the interface then.
     *
     * The two steps are separate on purpose, because RFC 5869 2 is explicit that they serve
     * different jobs and callers sometimes need only one:
     *
     * - `extract()` turns a non-uniform secret -- a Diffie-Hellman shared secret, say, whose
     *   bytes are not uniformly distributed -- into a uniform pseudorandom key of the hash's
     *   output length. The salt is optional and *non-secret*; RFC 5869 3.1 recommends one
     *   anyway, since it pins the derivation to a context.
     * - `expand()` stretches that key to any length up to 255 * hashLen, separating uses by the
     *   `info` label.
     *
     * `derive()` is the two together, which is what most callers want.
     *
     * The `info` label is the part worth getting right. Two different uses of one shared secret
     * must pass different `info`, or they derive the same bytes -- which is how a protocol ends
     * up using one key in both directions and loses the guarantee that a reflected record cannot
     * be replayed back at its sender.
     */
    class CERTPP_API CHkdf {
    public:
        /**
         * HKDF-Extract (RFC 5869 2.2): `HMAC(salt, inputKey)`.
         *
         * Note the argument order against HMAC's: the *salt* is the HMAC key and the input key
         * material is the message, which reads backwards until you remember that extract's job
         * is to condense the secret rather than to authenticate it.
         * @param hasherType The hash to run HMAC over.
         * @param salt Optional, non-secret; an empty span means a string of hashLen zero bytes,
         * which is what RFC 5869 specifies for "not provided".
         * @param inputKey The input keying material.
         * @param out Exactly the hash's output length.
         * @return ERET_OK on success; ERET_NOTSUP if HMAC is not defined over hasherType.
         */
        static ERetCode extract(
            EHashers hasherType, const SReadOnlyByteSpan& salt,
            const SReadOnlyByteSpan& inputKey, const SByteSpan& out
        );

        /**
         * HKDF-Expand (RFC 5869 2.3).
         *
         * `T(n) = HMAC(pseudoKey, T(n-1) || info || n)`, with the counter starting at 1 and each
         * block feeding the next -- so the blocks are chained, not independent, and a reader who
         * drops `T(n-1)` gets output that looks fine and matches nothing.
         * @param hasherType The hash to run HMAC over.
         * @param pseudoKey The pseudorandom key, normally extract()'s output; must be at least
         * the hash's output length (RFC 5869 2.3).
         * @param info Context/application label; may be empty. Distinct uses must pass distinct
         * labels -- see this class's doc comment.
         * @param out Receives the derived bytes; at most 255 * the hash's output length.
         * @return ERET_OK on success; ERET_BADREQ if out is too long or pseudoKey too short.
         */
        static ERetCode expand(
            EHashers hasherType, const SReadOnlyByteSpan& pseudoKey,
            const SReadOnlyByteSpan& info, const SByteSpan& out
        );

        /**
         * Extract then expand, which is HKDF as most callers mean it.
         * @param hasherType The hash to run HMAC over.
         * @param salt Optional, non-secret.
         * @param inputKey The input keying material.
         * @param info Context/application label.
         * @param out Receives the derived bytes; at most 255 * the hash's output length.
         * @return ERET_OK on success.
         */
        static ERetCode derive(
            EHashers hasherType, const SReadOnlyByteSpan& salt,
            const SReadOnlyByteSpan& inputKey, const SReadOnlyByteSpan& info,
            const SByteSpan& out
        );

        /**
         * The largest output expand() can produce for a hash: 255 * its output length.
         * @param hasherType The hash algorithm.
         * @return The limit in bytes, or 0 if HMAC is not defined over hasherType.
         */
        static size_t maxExpandBytes(EHashers hasherType);
    };

} // namespace crypto
} // namespace certpp

#endif
