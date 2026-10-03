#ifndef __SRC_CRYPTO_ASYMS_MLDSASCHEME_HPP__
#define __SRC_CRYPTO_ASYMS_MLDSASCHEME_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include "mldsaparams.hpp"
#include "mldsaring.hpp"

namespace certpp {
namespace crypto {

    /**
     * ML-DSA itself (FIPS 204 5-6): the key and signature encoders of 7.2, and KeyGen/Sign/
     * Verify in both their internal and external forms, over raw byte spans. Private to the
     * ML-DSA implementation, so no type prefix.
     *
     * This is the layer a test vector drives directly -- it takes xi and rnd as parameters
     * rather than drawing them, and has no opinion about key objects, contexts or CRng. `CMlDsa`
     * (crypto/asyms/mldsa.hpp) is the `IAsymmetric` built on top, and is the only part of the
     * implementation that touches the CSPRNG.
     *
     * Unlike ML-KEM, whose raw-span form is public as `CMlKem`, this stays under `src/`. The
     * reason is `MlDsaParams`: every entry point here is parameterized by it, and it is already
     * a tested private header whose `static_assert`s pin it against FIPS 204 Table 2. Exporting
     * these signatures would mean either moving that header into the public API or duplicating
     * it, and the public surface callers actually need -- a signature algorithm an X.509
     * certificate can carry -- is `IAsymmetric`-shaped anyway.
     *
     * **There are two message conventions and they are not interchangeable.** FIPS 204 draws a
     * hard line between them, and the distinction decides whether a real certificate verifies:
     *
     * - The *internal* interface (Algorithms 6-8) signs `M'` exactly as given. ACVP's
     *   `signatureInterface: "internal"` groups exercise this.
     * - The *external* interface (Algorithms 2-3) prepends a domain separator first:
     *   `M' = IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx || M`. This is what
     *   RFC 9881's `id-ml-dsa-44/65/87` mean, with an empty context -- so an X.509 signature
     *   covers `0x00 || 0x00 || tbsCertificate`, not the TBS bytes alone. Handing the raw
     *   message to the internal form instead fails to verify every genuine certificate, and
     *   round-trips perfectly against itself.
     *
     * Only the pure (non-prehashed) variant is here. HashML-DSA has its own separate OIDs
     * (`id-hash-ml-dsa-*`), appears in no certificate this library is meant to read, and would
     * drag in a hash-OID table for no present caller.
     *
     * The `externalMu` parameter on signInternal()/verifyInternal() corresponds to ACVP's
     * `externalMu: true` groups: mu is supplied rather than derived from `tr || M'`. It exists
     * because those groups are half of the vector set, and it is two branches rather than a
     * second copy of the signing loop.
     *
     * Signing is a **rejection loop**. Each iteration draws a fresh masking vector and discards
     * everything if any of four bounds fails, so the number of iterations depends on the key and
     * the message -- there is no constant-time story to tell here, and FIPS 204 does not offer
     * one. See docs/pqc-review.md.
     */
    class MlDsaScheme {
    public:
        /** The ring element every vector here is made of. */
        using Poly = MlDsaRing::Poly;

        /** KeyGen's seed length, xi (FIPS 204 Algorithm 1). */
        static constexpr size_t SEED_BYTES = 32;

        /** The signing randomness rnd's length; all zero for deterministic signing. */
        static constexpr size_t RND_BYTES = 32;

        /** mu's length, and tr's: H's 64-byte outputs (FIPS 204 Algorithm 7). */
        static constexpr size_t MU_BYTES = 64;

        /** rho's length, and K's. */
        static constexpr size_t RHO_BYTES = 32;

        /** The largest context string the external interface accepts (FIPS 204 Algorithm 2). */
        static constexpr size_t MAX_CONTEXT_BYTES = 255;

    public:
        /**
         * pkEncode (FIPS 204 Algorithm 22): rho followed by k packed t1 polynomials.
         * @param params The parameter set.
         * @param rho The 32-byte matrix seed.
         * @param t1 k polynomials with coefficients in [0, 2^10).
         * @param out Receives exactly params.publicKeyBytes() bytes.
         * @return true on success; false on a size mismatch or an out-of-range coefficient.
         */
        static bool pkEncode(
            const MlDsaParams& params, const SReadOnlyByteSpan& rho, const Poly* t1,
            const SByteSpan& out
        );

        /**
         * pkDecode (FIPS 204 Algorithm 23).
         *
         * Needs no range check: t1's bound is 2^10 - 1 and its field is exactly 10 bits wide, so
         * every byte string of the right length decodes to a legal t1 (see MlDsaCodec's own doc
         * comment on which of ML-DSA's decodes are safe and which are not).
         * @param params The parameter set.
         * @param pk Exactly params.publicKeyBytes() bytes.
         * @param rho Receives the 32-byte seed.
         * @param t1 Receives k polynomials.
         * @return true on success; false on a size mismatch.
         */
        static bool pkDecode(
            const MlDsaParams& params, const SReadOnlyByteSpan& pk, const SByteSpan& rho,
            Poly* t1
        );

        /**
         * skEncode (FIPS 204 Algorithm 24): rho || K || tr, then s1, s2 and t0 packed.
         * @param params The parameter set.
         * @param rho The 32-byte matrix seed.
         * @param k The 32-byte signing seed.
         * @param tr The 64-byte public-key hash.
         * @param s1 l polynomials with coefficients in [-eta, eta].
         * @param s2 k polynomials with coefficients in [-eta, eta].
         * @param t0 k polynomials with coefficients in (-2^12, 2^12].
         * @param out Receives exactly params.privateKeyBytes() bytes.
         * @return true on success; false on a size mismatch or an out-of-range coefficient.
         */
        static bool skEncode(
            const MlDsaParams& params, const SReadOnlyByteSpan& rho, const SReadOnlyByteSpan& k,
            const SReadOnlyByteSpan& tr, const Poly* s1, const Poly* s2, const Poly* t0,
            const SByteSpan& out
        );

        /**
         * skDecode (FIPS 204 Algorithm 25), **including the s1/s2 range check**.
         *
         * That check is not optional. 2*eta + 1 is 5 or 9, neither a power of two, so the
         * etaBitWidth()-bit field reaches values outside [-eta, eta] -- down to -5 at eta = 2 and
         * -11 at eta = 4. FIPS 204 Algorithm 25 lines 9-10 reject such a key, and this does too:
         * a private key arriving from storage or from a peer is untrusted input, and signing with
         * an out-of-range s1 produces signatures outside the scheme's security argument while
         * still verifying against the matching public key.
         * @param params The parameter set.
         * @param sk Exactly params.privateKeyBytes() bytes.
         * @param rho Receives the 32-byte matrix seed.
         * @param k Receives the 32-byte signing seed.
         * @param tr Receives the 64-byte public-key hash.
         * @param s1 Receives l polynomials.
         * @param s2 Receives k polynomials.
         * @param t0 Receives k polynomials.
         * @return true if the key was well formed; false on a size mismatch or an s1/s2
         * coefficient outside [-eta, eta].
         */
        static bool skDecode(
            const MlDsaParams& params, const SReadOnlyByteSpan& sk, const SByteSpan& rho,
            const SByteSpan& k, const SByteSpan& tr, Poly* s1, Poly* s2, Poly* t0
        );

        /**
         * sigEncode (FIPS 204 Algorithm 26): c-tilde, l packed z polynomials, then the hint.
         * @param params The parameter set.
         * @param commitment c-tilde, exactly params.commitmentBytes() bytes.
         * @param z l polynomials with coefficients in [-gamma1 + 1, gamma1].
         * @param hints k polynomials with 0/1 coefficients, at most omega set in total.
         * @param out Receives exactly params.signatureBytes() bytes.
         * @return true on success; false on a size mismatch or an out-of-range coefficient.
         */
        static bool sigEncode(
            const MlDsaParams& params, const SReadOnlyByteSpan& commitment, const Poly* z,
            const Poly* hints, const SByteSpan& out
        );

        /**
         * sigDecode (FIPS 204 Algorithm 27).
         *
         * z needs no range check (gamma1's field is exactly 1 + bitlen(gamma1 - 1) bits wide), but
         * the hint does, and a false return here is one of the ways a signature is rejected --
         * see MlDsaCodec::hintBitUnpack() for the three conditions.
         * @param params The parameter set.
         * @param signature Exactly params.signatureBytes() bytes.
         * @param commitment Receives params.commitmentBytes() bytes.
         * @param z Receives l polynomials.
         * @param hints Receives k polynomials with 0/1 coefficients.
         * @return true if the encoding was well formed; false on a size mismatch or a malformed
         * hint.
         */
        static bool sigDecode(
            const MlDsaParams& params, const SReadOnlyByteSpan& signature,
            const SByteSpan& commitment, Poly* z, Poly* hints
        );

        /**
         * w1Encode (FIPS 204 Algorithm 28): the commitment's hash input.
         * @param params The parameter set.
         * @param w1 k polynomials with coefficients in [0, highBitsRange()).
         * @param out Receives exactly 32 * k * bitlen(highBitsRange() - 1) bytes.
         * @return true on success; false on a size mismatch or an out-of-range coefficient.
         */
        static bool w1Encode(const MlDsaParams& params, const Poly* w1, const SByteSpan& out);

        /**
         * The exact length w1Encode() writes, so a caller can size its buffer.
         * @param params The parameter set.
         * @return The size in bytes.
         */
        static size_t w1EncodedBytes(const MlDsaParams& params);

        /**
         * ML-DSA.KeyGen_internal (FIPS 204 Algorithm 6): expands one 32-byte seed into a key pair.
         * @param params The parameter set.
         * @param seed The 32-byte seed xi.
         * @param pk Receives params.publicKeyBytes() bytes.
         * @param sk Receives params.privateKeyBytes() bytes.
         * @return true on success; false if params is not a FIPS 204 set or a span is the wrong
         * size.
         */
        static bool keyGenInternal(
            const MlDsaParams& params, const SReadOnlyByteSpan& seed, const SByteSpan& pk,
            const SByteSpan& sk
        );

        /**
         * ML-DSA.Sign_internal (FIPS 204 Algorithm 7).
         *
         * Signs `message` verbatim -- no domain separator is prepended. See this class's doc
         * comment: for an X.509 or CMS signature, sign() is the entry point, not this one.
         * @param params The parameter set.
         * @param sk The private key, params.privateKeyBytes() bytes.
         * @param message M', the formatted message, taken exactly as given. Ignored when
         * externalMu is supplied.
         * @param externalMu Empty for normal operation; otherwise exactly MU_BYTES bytes, used in
         * place of H(tr || M', 64) (ACVP's `externalMu: true`).
         * @param rnd Exactly RND_BYTES bytes: fresh CSPRNG output for the hedged variant, or all
         * zero for deterministic signing.
         * @param out Receives params.signatureBytes() bytes.
         * @return true on success; false if params is invalid, a span is the wrong size, or the
         * private key failed skDecode()'s range check.
         */
        static bool signInternal(
            const MlDsaParams& params, const SReadOnlyByteSpan& sk,
            const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& externalMu,
            const SReadOnlyByteSpan& rnd, const SByteSpan& out
        );

        /**
         * ML-DSA.Verify_internal (FIPS 204 Algorithm 8).
         *
         * Verifies against `message` verbatim; see signInternal().
         * @param params The parameter set.
         * @param pk The public key, params.publicKeyBytes() bytes.
         * @param message M', taken exactly as given. Ignored when externalMu is supplied.
         * @param externalMu Empty for normal operation; otherwise exactly MU_BYTES bytes.
         * @param signature The signature, params.signatureBytes() bytes.
         * @return true if the signature is valid under pk for this message.
         */
        static bool verifyInternal(
            const MlDsaParams& params, const SReadOnlyByteSpan& pk,
            const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& externalMu,
            const SReadOnlyByteSpan& signature
        );

        /**
         * ML-DSA.Sign (FIPS 204 Algorithm 2), the pure external interface: prepends
         * `0x00 || |ctx| || ctx` to the message before signing it.
         * @param params The parameter set.
         * @param sk The private key, params.privateKeyBytes() bytes.
         * @param message The message M.
         * @param context The context string, at most MAX_CONTEXT_BYTES bytes; empty for X.509.
         * @param rnd Exactly RND_BYTES bytes; all zero for deterministic signing.
         * @param out Receives params.signatureBytes() bytes.
         * @return true on success; false if params is invalid, context is too long, a span is the
         * wrong size, or the private key failed skDecode()'s range check.
         */
        static bool sign(
            const MlDsaParams& params, const SReadOnlyByteSpan& sk,
            const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& context,
            const SReadOnlyByteSpan& rnd, const SByteSpan& out
        );

        /**
         * ML-DSA.Verify (FIPS 204 Algorithm 3), the pure external interface.
         * @param params The parameter set.
         * @param pk The public key, params.publicKeyBytes() bytes.
         * @param message The message M.
         * @param context The context string, at most MAX_CONTEXT_BYTES bytes; empty for X.509.
         * @param signature The signature, params.signatureBytes() bytes.
         * @return true if the signature is valid under pk for this message and context.
         */
        static bool verify(
            const MlDsaParams& params, const SReadOnlyByteSpan& pk,
            const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& context,
            const SReadOnlyByteSpan& signature
        );

        /**
         * Reports whether a public key is structurally usable: the right length for this
         * parameter set.
         *
         * There is nothing else to check. pkDecode() cannot fail on a correctly sized input (see
         * its own doc comment), unlike ML-KEM's encapsulation key, whose 12-bit fields can encode
         * values at or above q. The method exists so a caller does not have to know that.
         * @param params The parameter set.
         * @param pk The candidate public key.
         * @return true if params is a FIPS 204 set and pk is usable under it.
         */
        static bool checkPublicKey(const MlDsaParams& params, const SReadOnlyByteSpan& pk);

        /**
         * Reports whether a private key is structurally usable: the right length, and with every
         * s1/s2 coefficient inside [-eta, eta].
         * @param params The parameter set.
         * @param sk The candidate private key.
         * @return true if params is a FIPS 204 set and sk is usable under it.
         */
        static bool checkPrivateKey(const MlDsaParams& params, const SReadOnlyByteSpan& sk);

        /**
         * Recovers the public key a private key corresponds to, by re-deriving t1 from the key's
         * own rho, s1, s2 and t0 rather than trusting anything stored alongside it.
         *
         * A private key does not carry its public key, so this is how `IPrivateKey::publicKey()`
         * is answered. It is also the only consistency check available on a decoded private key:
         * rho, s1, s2 and t0 jointly determine t1, and the key's own `tr` is H(pk), so a tr that
         * disagrees with the re-derived pk means the key is internally inconsistent.
         * @param params The parameter set.
         * @param sk The private key, params.privateKeyBytes() bytes.
         * @param pk Receives params.publicKeyBytes() bytes.
         * @param consistent Receives whether the key's three parts agree with each other:
         * the re-derived public key hashes to the stored tr, and the stored t0 is the one
         * Power2Round produces. A false here is not a decode failure -- the key is well formed
         * and its parts simply contradict each other -- so the return value stays true and the
         * caller decides.
         * @return true on success; false if params is invalid, a span is the wrong size, or
         * skDecode() rejected the key.
         */
        static bool publicKeyOf(
            const MlDsaParams& params, const SReadOnlyByteSpan& sk, const SByteSpan& pk,
            bool& consistent
        );
    };

} // namespace crypto
} // namespace certpp

#endif
