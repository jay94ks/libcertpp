#ifndef __INCLUDE_CERTPP_CRYPTO_ECCURVE_HPP__
#define __INCLUDE_CERTPP_CRYPTO_ECCURVE_HPP__

#include <certpp/utils/bignum.hpp>
#include <certpp/utils/montgomery.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/span.hpp>
#include <certpp/crypto/keys.hpp>
#include <utility>

namespace certpp {
namespace crypto {

    /**
     * The known curves CEcCurve::knownCurves() can retrieve by identifier, in the same order
     * they're defined in CEcCurve::_knownCurves.
     */
    enum EEcKnownCurves {
        ECURVE_UNKNOWN = 0,  /**< Not a valid curve identifier. */
        ECURVE_P192,         /**< NIST P-192 (secp192r1). */
        ECURVE_P224,         /**< NIST P-224 (secp224r1). */
        ECURVE_P256,         /**< NIST P-256 (secp256r1). */
        ECURVE_P384,         /**< NIST P-384 (secp384r1). */
        ECURVE_P521,         /**< NIST P-521 (secp521r1). */
        ECURVE_SECP256K1,    /**< secp256k1 (the Bitcoin/Ethereum curve; SEC 2). */
        ECURVE_BPOOL160R1,   /**< brainpoolP160r1 (RFC 5639). */
        ECURVE_BPOOL192R1,   /**< brainpoolP192r1 (RFC 5639). */
        ECURVE_BPOOL224R1,   /**< brainpoolP224r1 (RFC 5639). */
        ECURVE_BPOOL256R1,   /**< brainpoolP256r1 (RFC 5639). */
        ECURVE_BPOOL320R1,   /**< brainpoolP320r1 (RFC 5639). */
        ECURVE_BPOOL384R1,   /**< brainpoolP384r1 (RFC 5639). */
        ECURVE_BPOOL512R1,   /**< brainpoolP512r1 (RFC 5639). */
        ECURVE_BPOOL160T1,   /**< brainpoolP160t1 (RFC 5639, the "twisted" counterpart of brainpoolP160r1). */
        ECURVE_BPOOL192T1,   /**< brainpoolP192t1 (RFC 5639, the "twisted" counterpart of brainpoolP192r1). */
        ECURVE_BPOOL224T1,   /**< brainpoolP224t1 (RFC 5639, the "twisted" counterpart of brainpoolP224r1). */
        ECURVE_BPOOL256T1,   /**< brainpoolP256t1 (RFC 5639, the "twisted" counterpart of brainpoolP256r1). */
        ECURVE_BPOOL320T1,   /**< brainpoolP320t1 (RFC 5639, the "twisted" counterpart of brainpoolP320r1). */
        ECURVE_BPOOL384T1,   /**< brainpoolP384t1 (RFC 5639, the "twisted" counterpart of brainpoolP384r1). */
        ECURVE_BPOOL512T1,   /**< brainpoolP512t1 (RFC 5639, the "twisted" counterpart of brainpoolP512r1). */

        // --> GOST R 34.10-2012 parameter sets (see src/crypto/eccurve.cpp for each one's
        // authoritative source). Unlike every curve above, two of these have a cofactor of 4
        // rather than 1, so a point can legitimately lie on the curve without belonging to the
        // order-n subgroup -- which is why decodePoint()'s subgroup check is not redundant.
        ECURVE_GOST256TEST,  /**< id-GostR3410-2001-TestParamSet (RFC 7091 section 7.1). Testing only. */
        ECURVE_GOST256A,     /**< id-tc26-gost-3410-2012-256-paramSetA (RFC 7836 appendix A.2). */
        ECURVE_GOST256B,     /**< id-tc26-gost-3410-2012-256-paramSetB, a.k.a. id-GostR3410-2001-CryptoPro-A-ParamSet. */
        ECURVE_GOST256C,     /**< id-tc26-gost-3410-2012-256-paramSetC, a.k.a. id-GostR3410-2001-CryptoPro-B-ParamSet. */
        ECURVE_GOST256D,     /**< id-tc26-gost-3410-2012-256-paramSetD, a.k.a. id-GostR3410-2001-CryptoPro-C-ParamSet. */
        ECURVE_GOST512TEST,  /**< id-tc26-gost-3410-2012-512-paramSetTest (RFC 9215 appendix E). Testing only. */
        ECURVE_GOST512A,     /**< id-tc26-gost-3410-12-512-paramSetA (RFC 7836 appendix A.1). */
        ECURVE_GOST512B,     /**< id-tc26-gost-3410-12-512-paramSetB (RFC 7836 appendix A.1). */
        ECURVE_GOST512C,     /**< id-tc26-gost-3410-2012-512-paramSetC (RFC 7836 appendix A.2). */

        ECURVE_MAX /**< Sentinel value representing the maximum known curve ID. */
    };

    /**
     * A point on a short Weierstrass curve (y^2 = x^3 + a*x + b mod p), in affine coordinates.
     * The point at infinity (the group identity) is represented by infinity=true, with x/y left
     * at their default-constructed value (zero).
     */
    struct SEcPoint {
        CBigNum x; /**< The point's x-coordinate; meaningless if infinity is true. */
        CBigNum y; /**< The point's y-coordinate; meaningless if infinity is true. */
        bool infinity; /**< True if this is the point at infinity (the group identity). */

        /**
         * Default constructor; the point at infinity.
         */
        SEcPoint() : infinity(true) {
        }

        /**
         * Constructs a finite point.
         * @param x The point's x-coordinate.
         * @param y The point's y-coordinate.
         */
        SEcPoint(CBigNum x, CBigNum y) : x(std::move(x)), y(std::move(y)), infinity(false) {
        }

        /**
         * @param other The other point to compare with.
         * @return true if both points are the point at infinity, or both are the same finite point.
         */
        inline bool equals(const SEcPoint& other) const {
            if (infinity || other.infinity) {
                return infinity == other.infinity;
            }

            return x == other.x && y == other.y;
        }
    };

    /**
     * A short Weierstrass curve's domain parameters (y^2 = x^3 + a*x + b mod p), plus its base
     * point g and subgroup order n (the cofactor isn't tracked separately: it's 1 for every
     * NIST/Brainpool curve this library ships, and the two GOST parameter sets where it's 4 --
     * ECURVE_GOST256A and ECURVE_GOST512C -- need it only for the VKO key agreement this
     * library doesn't implement, not for signing). Backs the P256/P384/P521 concrete IAsymmetric
     * implementations, each of which owns one static CEcCurve instance describing its specific
     * curve; public rather than a src/-only implementation detail since the underlying group
     * arithmetic isn't tied to any one algorithm (matching CBigNum's own reasoning).
     *
     * All arithmetic is affine (no projective-coordinate optimization to avoid a modular
     * inversion per point operation) and branches directly on scalar bits in scalarMul()'s
     * double-and-add loop -- correctness and simplicity over performance/timing-side-channel
     * hardening, consistent with this library's early-stage priorities (schoolbook CBigNum
     * arithmetic already isn't constant-time either).
     */
    class CERTPP_API CEcCurve {
    private:
        /**
         * Known curves (e.g., NIST P-256, P-384, P-521, the GOST R 34.10-2012 parameter sets).
         */
        static const CEcCurve _knownCurves[ECURVE_MAX - 1];

        /**
         * Lazily-built table of small multiples of g, for scalarMulBase()'s windowed method;
         * empty until scalarMulBase() first needs it. mutable so scalarMulBase() can stay a
         * logically-const query; deep-copied like any other member on copy-construction (e.g.
         * when a generated key's private-key class stores its own CEcCurve copy), so a
         * caller that keeps reusing an already-warmed CEcCurve (directly, or copied from one)
         * reuses the table too -- only a still-cold copy pays to rebuild it, on its own first
         * use.
         */
        mutable TArray<SEcPoint> _baseTable;

        /* Parses a curve's hardcoded hex constant into a CBigNum at static-init time -- the
         * strings are trusted literals (see _knownCurves), so a parse failure (which fromHex
         * only reports via its bool return) can't actually happen here. */
        static CBigNum parseHex(const char* hex);

        /* A short-Weierstrass point in Jacobian coordinates: affine (x, y) = (X/Z^2, Y/Z^3),
         * with Z == 0 representing the point at infinity. Unlike edwards25519/edwards448's
         * extended coordinates (crypto/asyms/ed25519.cpp / ed448.cpp), short-Weierstrass addition
         * has no complete formula -- doubling, negation (same x, opposite y), and the point at
         * infinity still need explicit special-casing, exactly like affine add()/doublePoint()
         * already do. Only scalarMul()/scalarMulBase() use this representation -- everywhere else
         * deals in affine SEcPoint, converting at the boundary (toJacobian()/toAffineFromJac()).
         *
         * Its coordinates are held in *Montgomery* form (see CMontgomery), not as ordinary
         * residues: that is what lets a scalar multiplication's thousands of field multiplications
         * run without a single big-number division. toJacobian()/toAffineFromJac() are the
         * conversion boundary in both directions, so nothing outside these five functions ever
         * sees a Montgomery-form value. */
        struct ECPointJac {
            CBigNum x, y, z;
        };

        static ECPointJac infinityJac(const CMontgomery& field);
        static ECPointJac toJacobian(const SEcPoint& pt, const CMontgomery& field);
        static SEcPoint toAffineFromJac(const ECPointJac& pt, const CMontgomery& field);

        /* Jacobian doubling (dbl-2007-bl, Bernstein/Lange, general a -- this library's curves
         * span both a == -3, the NIST/Brainpool r1 default, and arbitrary a for secp256k1/the
         * Brainpool t1 curves, so the a == -3 shortcut isn't used). aMont is the curve's `a`
         * coefficient in Montgomery form, which the caller converts once per scalar
         * multiplication rather than once per doubling. */
        static ECPointJac doublePointJac(
            const ECPointJac& pt, const CMontgomery& field, const CBigNum& aMont
        );

        /* Jacobian addition (add-2007-bl, Bernstein/Lange, general Z1/Z2). Falls back to
         * doublePointJac() when both points share the same x-coordinate and the same y (P1 ==
         * P2), and to the point at infinity when they share x but differ in y (P1 == -P2). */
        static ECPointJac addJac(
            const ECPointJac& p1, const ECPointJac& p2, const CMontgomery& field,
            const CBigNum& aMont
        );

        static void condSwapJac(bool doSwap, ECPointJac& a, ECPointJac& b);

    public:
        CBigNum p; /**< The field prime. */
        CBigNum a; /**< Curve coefficient a. */
        CBigNum b; /**< Curve coefficient b. */
        CBigNum n; /**< The base point's subgroup order. */
        SEcPoint g; /**< The base point (generator). */

    public:
        /**
         * Default constructor; a zero-valued, invalid curve. Only meaningful once filled in via
         * knownCurves() or copy-assigned from a properly constructed instance.
         */
        CEcCurve() = default;

        /**
         * @param pHex Field prime p, as a hex string (with or without a leading "0x").
         * @param aHex Curve coefficient a, as a hex string.
         * @param bHex Curve coefficient b, as a hex string.
         * @param gxHex Base point G's x-coordinate, as a hex string.
         * @param gyHex Base point G's y-coordinate, as a hex string.
         * @param nHex Subgroup order n, as a hex string.
         */
        CEcCurve(
            const char* pHex, const char* aHex, const char* bHex,
            const char* gxHex, const char* gyHex, const char* nHex
        );

        /**
         * Maps a known curve identifier to the EAsymmetrics identifying it -- CEcCurve itself
         * carries only domain parameters (p, a, b, n, g), no identity, so this is the one place
         * that connection is made (CEcdsa's own constructor calls this to set its _which).
         * Written as an explicit switch, not ordinal arithmetic between the two
         * (differently-ordered) enums, so a future reordering of either can't silently miswire
         * this.
         * @param which The known curve identifier.
         * @return The corresponding EAsymmetrics; EASYM_P256 for an identifier not among the
         * known curves (unreachable for a validly-constructed CEcdsa).
         */
        static EAsymmetrics identify(EEcKnownCurves which);

        /**
         * Retrieves a known curve by its enum identifier.
         * @param curve The known curve identifier.
         * @param out Receives the corresponding CEcCurve instance.
         * @return true if curve was a valid, known identifier; false otherwise (out is left unchanged).
         */
        static inline bool knownCurves(EEcKnownCurves curve, CEcCurve& out) {
            if (curve <= ECURVE_UNKNOWN || curve >= ECURVE_MAX) {
                return false;
            }

            out = _knownCurves[curve - 1];
            return true;
        }

        /**
         * @return The width, in bytes, of one field element (ceil(bitLength(p) / 8)) -- the
         * fixed width SEC1 point encoding pads x/y coordinates to.
         */
        size_t fieldByteLen() const;

        /**
         * @param pt The point to test.
         * @return true if pt satisfies the curve equation (the point at infinity trivially does).
         */
        bool isOnCurve(const SEcPoint& pt) const;

        /**
         * @param p1 One point.
         * @param p2 The other point.
         * @return p1 + p2, per the curve's group law.
         */
        SEcPoint add(const SEcPoint& p1, const SEcPoint& p2) const;

        /**
         * @param pt The point to double.
         * @return pt + pt, per the curve's group law.
         */
        SEcPoint doublePoint(const SEcPoint& pt) const;

        /**
         * Computes k*pt via MSB-first double-and-add.
         * @param pt The point to multiply.
         * @param k The scalar to multiply by.
         * @return k*pt.
         */
        SEcPoint scalarMul(const SEcPoint& pt, const CBigNum& k) const;

        /**
         * Computes k*g (the base point specifically, not an arbitrary point) via a windowed
         * method over a table of small multiples of g, built lazily on first call and cached in
         * this instance (see _baseTable's own comment) -- faster than scalarMul(g, k) for
         * repeated calls against the same CEcCurve instance (or a copy descended from an
         * already-warmed one), such as every ECDSA sign()/verify() call's k*g/u1*g term. Not
         * meaningfully faster for a single one-off call, and not applicable to a caller-supplied
         * arbitrary point (e.g. the other party's public key in verify()'s u2*Q term) -- use
         * scalarMul() for that.
         * @param k The scalar to multiply g by.
         * @return k*g.
         */
        SEcPoint scalarMulBase(const CBigNum& k) const;

        /**
         * Encodes pt in SEC1 form: a single 0x00 byte for the point at infinity, otherwise
         * 0x04 || X || Y with X/Y padded to fieldByteLen() bytes each (uncompressed form).
         * @param pt The point to encode.
         * @param out The destination array, replacing any content it previously held.
         * @return true on success; false on failure.
         */
        bool encodePoint(const SEcPoint& pt, TArray<uint8_t>& out) const;

        /**
         * Decodes a SEC1-encoded point (see encodePoint()), validating it lies on the curve.
         * @param data The SEC1-encoded point.
         * @param out Receives the decoded point.
         * @return true if data was a well-formed, on-curve point; false otherwise.
         */
        bool decodePoint(SReadOnlyByteSpan data, SEcPoint& out) const;
    };

} // namespace crypto
} // namespace certpp

#endif
