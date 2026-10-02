#ifndef __INCLUDE_CERTPP_CRYPTO_PQ_MLKEM_HPP__
#define __INCLUDE_CERTPP_CRYPTO_PQ_MLKEM_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {
namespace crypto {

    /**
     * One element of ML-KEM's polynomial ring R_q = Z_q[X]/(X^256 + 1), q = 3329 (FIPS 203 2.4.4),
     * held as 256 coefficients each reduced into [0, MODULUS).
     *
     * The same layout also carries NTT-domain values, which are 128 degree-1 blocks rather than a
     * polynomial. FIPS 203 itself does not distinguish the two representations in its data types
     * either, so which one an instance holds is the caller's to track.
     *
     * Two properties of this ring drive everything built on it. It is *negacyclic*: X^256 == -1,
     * so a product overflowing degree 255 wraps round negated rather than simply wrapping. And q
     * was chosen so that 17 has order exactly 256, which is what makes a Number-Theoretic
     * Transform possible and multiplication cheap.
     */
    struct SMlKemPoly {
        /** Coefficients per polynomial. */
        static constexpr size_t COEFFICIENTS = 256;

        /** The prime modulus, q. */
        static constexpr int32_t MODULUS = 3329;

        /** A primitive 256th root of unity mod MODULUS, from which the NTT twiddles derive. */
        static constexpr int32_t ROOT_OF_UNITY = 17;

        int16_t coeffs[COEFFICIENTS];
    };

    /**
     * One of ML-KEM's three parameter sets (FIPS 203 Table 2), with the sizes it implies.
     *
     * Only the five tabulated parameters are stored; every size is derived from them. That is
     * deliberate -- a mistyped key or ciphertext length is exactly the sort of error that stays
     * internally consistent and is caught only by an external test vector, so the sizes are made
     * impossible to write down incorrectly. The derived figures are asserted against FIPS 203's
     * own published table in the test suite.
     *
     * Note that `k` doubles as the domain-separation byte appended to the seed in K-PKE key
     * generation's `G(d || k)`. That byte was added after FIPS 203's initial public draft, so
     * round-3 Kyber code omits it -- and omitting it yields a scheme that works perfectly with
     * itself and interoperates with nothing.
     */
    struct SMlKemParams {
        size_t k;      /**< Module rank: 2, 3 or 4; also the G() domain-separation byte. */
        size_t eta1;   /**< CBD parameter for the secret and the encryption randomness. */
        size_t eta2;   /**< CBD parameter for the error terms. */
        size_t du;     /**< Compression width for the ciphertext's u component. */
        size_t dv;     /**< Compression width for the ciphertext's v component. */

        /**
         * Encapsulation key size: 384*k for the encoded t-hat, plus the 32-byte seed rho.
         * @return The size in bytes (800, 1184 or 1568).
         */
        constexpr size_t ekBytes() const { return 384 * k + 32; }

        /**
         * Decapsulation key size: dk_PKE || ek || H(ek) || z.
         * @return The size in bytes (1632, 2400 or 3168).
         */
        constexpr size_t dkBytes() const { return 768 * k + 96; }

        /**
         * The K-PKE decapsulation key size, which is the leading portion of dkBytes().
         * @return The size in bytes.
         */
        constexpr size_t dkPkeBytes() const { return 384 * k; }

        /**
         * Ciphertext size: 32*du*k for the compressed u, plus 32*dv for the compressed v.
         * @return The size in bytes (768, 1088 or 1568).
         */
        constexpr size_t ciphertextBytes() const { return 32 * du * k + 32 * dv; }

        /**
         * Shared secret size, 32 bytes for every parameter set.
         * @return The size in bytes.
         */
        constexpr size_t sharedSecretBytes() const { return 32; }

        /**
         * Seed and message size, 32 bytes for every parameter set.
         * @return The size in bytes.
         */
        constexpr size_t seedBytes() const { return 32; }

        /**
         * ML-KEM-512 (k=2, eta1=3, eta2=2, du=10, dv=4).
         * @return The parameter set.
         */
        static constexpr SMlKemParams mlKem512() { return SMlKemParams{ 2, 3, 2, 10, 4 }; }

        /**
         * ML-KEM-768 (k=3, eta1=2, eta2=2, du=10, dv=4).
         * @return The parameter set.
         */
        static constexpr SMlKemParams mlKem768() { return SMlKemParams{ 3, 2, 2, 10, 4 }; }

        /**
         * ML-KEM-1024 (k=4, eta1=2, eta2=2, du=11, dv=5).
         * @return The parameter set.
         */
        static constexpr SMlKemParams mlKem1024() { return SMlKemParams{ 4, 2, 2, 11, 5 }; }

        /**
         * Field-by-field equality.
         * @param other The parameter set to compare against.
         * @return true if every parameter matches.
         */
        constexpr bool equals(const SMlKemParams& other) const {
            return k == other.k && eta1 == other.eta1 && eta2 == other.eta2
                && du == other.du && dv == other.dv;
        }

        /**
         * Reports whether this is one of FIPS 203's three parameter sets.
         *
         * Every CMlKem entry point rejects anything else outright rather than trying to
         * accommodate it, and that is a safety requirement rather than pedantry: the
         * implementation sizes its fixed-capacity buffers from MAX_K and maxCiphertextBytes(), so
         * a hand-built set with a larger k or wider du/dv would overflow them. The standard
         * defines no fourth set, so refusing is both the safe answer and the correct one.
         * @return true if this equals mlKem512(), mlKem768() or mlKem1024().
         */
        constexpr bool isValid() const {
            return equals(mlKem512()) || equals(mlKem768()) || equals(mlKem1024());
        }

        /** The largest module rank any parameter set uses, for sizing fixed-capacity buffers. */
        static constexpr size_t MAX_K = 4;

        /**
         * The largest ciphertext any parameter set produces, for sizing fixed-capacity buffers.
         *
         * Derived from ML-KEM-1024 rather than written out, for the same reason the sizes above
         * are: du and dv both grow with k, so the largest set is also the largest ciphertext.
         * @return 1568 bytes.
         */
        static constexpr size_t maxCiphertextBytes() { return mlKem1024().ciphertextBytes(); }
    };

    /**
     * ML-KEM's two samplers: `SampleNTT` (FIPS 203 Algorithm 7), which rejection-samples a uniform
     * NTT-domain polynomial from a SHAKE128 stream, and `SamplePolyCBD` (Algorithm 8), which turns
     * PRF output into the small-coefficient "noise" the Module-LWE assumption needs.
     *
     * `sampleNtt()` is why `SHAKE128::squeeze()` exists. It consumes the XOF three bytes at a time
     * and keeps going until 256 coefficients have been *accepted*, so the amount of stream it needs
     * is not known in advance -- between 453 and 498 bytes in practice, about three SHAKE128 rate
     * blocks, varying with the seed. A fixed-length `finish()` cannot express that.
     *
     * Both are deterministic functions of their inputs, and the byte order in which the seed, the
     * indices and the stream are consumed is part of ML-KEM's wire format rather than an
     * implementation detail.
     */
    class CERTPP_API CMlKemSampler {
    public:
        /**
         * Rejection-samples a uniform polynomial in the NTT domain from SHAKE128(seed || first ||
         * second) (FIPS 203 Algorithm 7).
         *
         * Note the index order. FIPS 203's matrix expansion calls this as
         * `SampleNTT(rho || j || i)` -- the indices transposed relative to the natural loop order,
         * which the standard's own margin note calls out. This function appends exactly what it is
         * given, in order, so passing them the right way round is the caller's responsibility.
         * @param seed A 32-byte seed (FIPS 203's rho).
         * @param firstIndex The byte appended at offset 32.
         * @param secondIndex The byte appended at offset 33.
         * @param out Receives 256 coefficients, each in [0, SMlKemPoly::MODULUS).
         * @return true on success; false if seed is not 32 bytes or the XOF failed.
         */
        static bool sampleNtt(
            const SReadOnlyByteSpan& seed, uint8_t firstIndex, uint8_t secondIndex,
            SMlKemPoly& out
        );

        /**
         * Samples a polynomial from the centered binomial distribution with parameter eta
         * (FIPS 203 Algorithm 8): each coefficient is the difference of two sums of eta bits, so it
         * lands in [-eta, eta] before being reduced into [0, SMlKemPoly::MODULUS).
         * @param eta The distribution parameter; ML-KEM uses 2 or 3.
         * @param prfOutput Exactly 64*eta bytes of PRF output.
         * @param out Receives 256 coefficients.
         * @return true on success; false if eta is out of range or prfOutput is the wrong size.
         */
        static bool samplePolyCbd(
            size_t eta, const SReadOnlyByteSpan& prfOutput, SMlKemPoly& out
        );
    };

    /**
     * ML-KEM (FIPS 203) and the K-PKE scheme underneath it, over raw byte spans.
     *
     * This is the algorithm itself, with no opinion about key objects or contexts, so it can be
     * driven straight from a test vector. The `IKem`/`IKemContext` interface
     * (`certpp/crypto/kem.hpp`) is the shape most callers should prefer; this class is what sits
     * behind it, and is public because the raw-span form is genuinely useful on its own -- for
     * interoperability testing, for a caller that already owns its buffers, and for anyone who
     * needs K-PKE rather than the KEM.
     *
     * The structure follows the standard. K-PKE is an IND-CPA public-key encryption scheme, and
     * ML-KEM is the Fujisaki-Okamoto transform applied to it, which is what upgrades it to
     * IND-CCA2. The FO part is small but carries all the subtlety:
     *
     * `decapsulate()` derives a shared secret from the recovered message, then **re-encrypts** and
     * compares against the ciphertext it was given. If they differ it returns `J(z || ciphertext)`
     * instead -- a secret derived from the private key's own rejection seed. This is *implicit
     * rejection*: a malformed ciphertext yields a well-formed but unrelated shared secret rather
     * than an error, so an attacker learns nothing about whether their ciphertext decrypted.
     * Reporting failure there, or skipping the re-encryption, would reduce ML-KEM to the
     * chosen-ciphertext-breakable scheme underneath it. That is why `decapsulate()` has no failure
     * mode for a bad ciphertext at all -- only for a structurally wrong-sized one.
     *
     * Validated against NIST's ACVP vectors for all three parameter sets, including the
     * `modified ciphertext` decapsulation cases that exercise exactly that rejection path.
     */
    class CERTPP_API CMlKem {
    public:
        /**
         * ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16): expands two 32-byte seeds into an
         * encapsulation and a decapsulation key.
         * @param params The parameter set.
         * @param d The 32-byte key-generation seed.
         * @param z The 32-byte implicit-rejection seed, retained inside the decapsulation key.
         * @param ek Receives params.ekBytes() bytes.
         * @param dk Receives params.dkBytes() bytes.
         * @return true on success; false if params is not a FIPS 203 set or a span is the wrong size.
         */
        static bool generateKeyPair(
            const SMlKemParams& params, const SReadOnlyByteSpan& d, const SReadOnlyByteSpan& z,
            const SByteSpan& ek, const SByteSpan& dk
        );

        /**
         * ML-KEM.Encaps_internal (FIPS 203 Algorithm 17): derives a shared secret from a 32-byte
         * message and wraps it for the holder of the matching decapsulation key.
         *
         * Takes the message explicitly rather than drawing it internally, so it can be driven from
         * a test vector. **A caller outside the tests must pass fresh CSPRNG output**: reusing a
         * message reuses the shared secret.
         * @param params The parameter set.
         * @param ek The encapsulation key, params.ekBytes() bytes.
         * @param message The 32-byte message.
         * @param ciphertext Receives params.ciphertextBytes() bytes.
         * @param sharedSecret Receives 32 bytes.
         * @return true on success; false if params is not a FIPS 203 set or a span is the wrong size.
         */
        static bool encapsulate(
            const SMlKemParams& params, const SReadOnlyByteSpan& ek,
            const SReadOnlyByteSpan& message, const SByteSpan& ciphertext,
            const SByteSpan& sharedSecret
        );

        /**
         * ML-KEM.Decaps_internal (FIPS 203 Algorithm 18): recovers the shared secret, falling back
         * to the implicit-rejection secret when the ciphertext does not re-encrypt to itself.
         *
         * Succeeds for any correctly-sized ciphertext, valid or not -- see this class's own doc
         * comment for why that is the required behaviour rather than a missing check.
         * @param params The parameter set.
         * @param dk The decapsulation key, params.dkBytes() bytes.
         * @param ciphertext The ciphertext, params.ciphertextBytes() bytes.
         * @param sharedSecret Receives 32 bytes.
         * @return true on success; false only if params is invalid or a span is the wrong size.
         */
        static bool decapsulate(
            const SMlKemParams& params, const SReadOnlyByteSpan& dk,
            const SReadOnlyByteSpan& ciphertext, const SByteSpan& sharedSecret
        );

        /**
         * Reports whether an encapsulation key is well formed: the right length, and with every
         * 12-bit segment of its encoded t-hat below q.
         *
         * FIPS 203 requires this before using a key received from elsewhere, because ByteDecode at
         * d=12 reduces mod q and would otherwise silently accept an encoding no encoder could have
         * produced.
         * @param params The parameter set.
         * @param ek The candidate encapsulation key.
         * @return true if params is a FIPS 203 set and ek is usable under it.
         */
        static bool checkEncapsulationKey(
            const SMlKemParams& params, const SReadOnlyByteSpan& ek
        );

        /**
         * Reports whether a decapsulation key is well formed: the right length, and with its
         * embedded H(ek) actually matching the encapsulation key it carries.
         * @param params The parameter set.
         * @param dk The candidate decapsulation key.
         * @return true if params is a FIPS 203 set and dk is usable under it.
         */
        static bool checkDecapsulationKey(
            const SMlKemParams& params, const SReadOnlyByteSpan& dk
        );

        /**
         * K-PKE.KeyGen (FIPS 203 Algorithm 13), the IND-CPA scheme ML-KEM is built on. Exposed for
         * interoperability testing; a caller wanting a KEM wants generateKeyPair().
         * @param params The parameter set.
         * @param d The 32-byte seed.
         * @param ekPke Receives params.ekBytes() bytes.
         * @param dkPke Receives params.dkPkeBytes() bytes.
         * @return true on success; false if params is not a FIPS 203 set or a span is the wrong size.
         */
        static bool kpkeKeyGen(
            const SMlKemParams& params, const SReadOnlyByteSpan& d,
            const SByteSpan& ekPke, const SByteSpan& dkPke
        );

        /**
         * K-PKE.Encrypt (FIPS 203 Algorithm 14).
         *
         * This is IND-CPA only: it offers no protection against a chosen-ciphertext attack, which
         * is what the KEM above adds. Do not use it directly to encrypt anything.
         * @param params The parameter set.
         * @param ekPke The K-PKE encapsulation key.
         * @param message The 32-byte message.
         * @param randomness 32 bytes of encryption randomness.
         * @param ciphertext Receives params.ciphertextBytes() bytes.
         * @return true on success; false if params is not a FIPS 203 set or a span is the wrong size.
         */
        static bool kpkeEncrypt(
            const SMlKemParams& params, const SReadOnlyByteSpan& ekPke,
            const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& randomness,
            const SByteSpan& ciphertext
        );

        /**
         * K-PKE.Decrypt (FIPS 203 Algorithm 15).
         * @param params The parameter set.
         * @param dkPke The K-PKE decapsulation key.
         * @param ciphertext The ciphertext.
         * @param message Receives the recovered 32-byte message.
         * @return true on success; false if params is not a FIPS 203 set or a span is the wrong size.
         */
        static bool kpkeDecrypt(
            const SMlKemParams& params, const SReadOnlyByteSpan& dkPke,
            const SReadOnlyByteSpan& ciphertext, const SByteSpan& message
        );

    private:
        /* H(x) = SHA3-256(x), FIPS 203 4.1. */
        static bool hashH(const SReadOnlyByteSpan& input, const SByteSpan& out);

        /* G(x) = SHA3-512(x), split into two 32-byte halves. */
        static bool hashG(
            const SReadOnlyByteSpan& input, const SByteSpan& firstHalf, const SByteSpan& secondHalf
        );

        /* J(x) = SHAKE256(x, 32), the implicit-rejection PRF. */
        static bool hashJ(const SReadOnlyByteSpan& input, const SByteSpan& out);

        /* PRF_eta(s, b) = SHAKE256(s || b, 64*eta). */
        static bool prf(
            size_t eta, const SReadOnlyByteSpan& seed, uint8_t counter, const SByteSpan& out
        );
    };

} // namespace crypto
} // namespace certpp

#endif
