#ifndef __INCLUDE_CERTPP_CRYPTO_EC2CURVE_HPP__
#define __INCLUDE_CERTPP_CRYPTO_EC2CURVE_HPP__

#include <certpp/utils/bignum.hpp>
#include <certpp/utils/gf2m.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/span.hpp>
#include <certpp/crypto/keys.hpp>
#include <utility>

namespace certpp {
namespace crypto {

    /**
     * The known binary curves CEc2Curve::knownCurves() can retrieve by identifier, in the same
     * order they're defined in CEc2Curve::_knownCurves. A "B" (random) and "K" (Koblitz) curve
     * of the same bit size share the same underlying GF(2^m) field (see CGf2m::knownField()) --
     * only their curve coefficients a/b and base point/order differ.
     */
    enum EEc2KnownCurves {
        ECURVE2_UNKNOWN = 0, /**< Not a valid curve identifier. */
        ECURVE2_B163,        /**< NIST B-163 (sect163r2). */
        ECURVE2_K163,        /**< NIST K-163 (sect163k1). */
        ECURVE2_B233,        /**< NIST B-233 (sect233r1). */
        ECURVE2_K233,        /**< NIST K-233 (sect233k1). */
        ECURVE2_B283,        /**< NIST B-283 (sect283r1). */
        ECURVE2_K283,        /**< NIST K-283 (sect283k1). */
        ECURVE2_B409,        /**< NIST B-409 (sect409r1). */
        ECURVE2_K409,        /**< NIST K-409 (sect409k1). */
        ECURVE2_B571,        /**< NIST B-571 (sect571r1). */
        ECURVE2_K571,        /**< NIST K-571 (sect571k1). */

        ECURVE2_MAX /**< Sentinel value representing the maximum known curve ID. */
    };

    /**
     * A point on a binary curve (y^2 + x*y = x^3 + a*x^2 + b over GF(2^m)), in affine
     * coordinates. The point at infinity (the group identity) is represented by infinity=true,
     * with x/y left at their default-constructed value.
     */
    struct SEc2Point {
        CGf2m x; /**< The point's x-coordinate; meaningless if infinity is true. */
        CGf2m y; /**< The point's y-coordinate; meaningless if infinity is true. */
        bool infinity; /**< True if this is the point at infinity (the group identity). */

        /**
         * Default constructor; the point at infinity.
         */
        SEc2Point() : infinity(true) {
        }

        /**
         * Constructs a finite point.
         * @param x The point's x-coordinate.
         * @param y The point's y-coordinate.
         */
        SEc2Point(CGf2m x, CGf2m y) : x(std::move(x)), y(std::move(y)), infinity(false) {
        }

        /**
         * @param other The other point to compare with.
         * @return true if both points are the point at infinity, or both are the same finite point.
         */
        inline bool equals(const SEc2Point& other) const {
            if (infinity || other.infinity) {
                return infinity == other.infinity;
            }

            return x == other.x && y == other.y;
        }
    };

    /**
     * A binary curve's domain parameters (y^2 + x*y = x^3 + a*x^2 + b over GF(2^m)), plus its
     * base point g and subgroup order n. The prime-field counterpart of CEcCurve -- see that
     * class's doc comment for the shared reasoning (public rather than a src/-only
     * implementation detail; affine, non-constant-time, correctness/simplicity over
     * performance) -- but over a binary field, so an entirely different group law (no formula
     * is shared with CEcCurve).
     *
     * Unlike CEcCurve (whose CBigNum-valued a/b/n/g are owned by value, since each prime-field
     * curve's parameters are unique to it), a CEc2Curve's `field` is always one of CGf2m's five
     * shared static singletons -- a "B" and "K" curve of the same bit size use the identical
     * field, only a/b/g/n differ -- so `field` is a non-owning pointer, exactly like CGf2m's own
     * field pointer (see its doc comment for why this doesn't carry the dangling-pointer risk
     * CEcdsa's key classes had to fix). Cofactor h (1 for the prime-field curves this library
     * ships, so not tracked there) is 2 or 4 for these curves, but isn't tracked separately
     * either: it only matters for key generation's scalar range and is folded into the
     * scalar-generation logic in crypto/asyms/, not the curve's own domain parameters.
     */
    class CERTPP_API CEc2Curve {
    private:
        /**
         * Known curves (B-163/K-163 .. B-571/K-571).
         */
        static const CEc2Curve _knownCurves[ECURVE2_MAX - 1];

        /**
         * Lazily-built table of small multiples of g, for scalarMulBase()'s windowed method --
         * see CEcCurve::_baseTable's identical doc comment (eccurve.hpp) for the lazy-build/
         * copy-propagation reasoning, which applies here unchanged.
         */
        mutable TArray<SEc2Point> _baseTable;

        /* Parses a curve constant into a CGf2m/CBigNum. Only used for this module's hardcoded
         * domain parameters, each independently verified (on-curve base point, correct subgroup
         * order) before hardcoding -- see _knownCurves's own comment -- so a parse failure here
         * would indicate a bug in this file, not bad runtime input. */
        static CGf2m parseGf2mHex(const SGf2mField& field, const char* hex);
        static CBigNum parseHexBigNum(const char* hex);

        /* A binary-curve point in Lopez-Dahab projective coordinates: affine (x, y) =
         * (X/Z, Y/Z^2), with Z == 0 representing the point at infinity -- the binary-curve
         * counterpart of CEcCurve::ECPointJac (crypto/eccurve.hpp). Only scalarMul()/
         * scalarMulBase() use this representation -- everywhere else deals in affine SEc2Point,
         * converting at the boundary (toLD()/toAffineFromLD()). */
        struct EC2PointLD {
            CGf2m x, y, z;
        };

        static EC2PointLD infinityLD();
        static EC2PointLD toLD(const SEc2Point& pt, const SGf2mField& field);
        static SEc2Point toAffineFromLD(const EC2PointLD& pt);
        static EC2PointLD doublePointLD(const EC2PointLD& pt, const CGf2m& a, const CGf2m& b);
        static EC2PointLD addLD(const EC2PointLD& p1, const EC2PointLD& p2, const CGf2m& a, const CGf2m& b);
        static void condSwapLD(bool doSwap, EC2PointLD& a, EC2PointLD& b);

    public:
        const SGf2mField* field; /**< The GF(2^m) field this curve is defined over (a program-lifetime singleton; see class doc comment). */
        CGf2m a; /**< Curve coefficient a. */
        CGf2m b; /**< Curve coefficient b. */
        CBigNum n; /**< The base point's subgroup order. */
        SEc2Point g; /**< The base point (generator). */

    public:
        /**
         * Default constructor; an invalid curve with a null field. Only meaningful once filled
         * in via knownCurves() or copy-assigned from a properly constructed instance.
         */
        CEc2Curve() : field(nullptr) {
        }

        /**
         * @param fieldId The known GF(2^m) field this curve is defined over.
         * @param aHex Curve coefficient a, as a hex string (with or without a leading "0x").
         * @param bHex Curve coefficient b, as a hex string.
         * @param gxHex Base point G's x-coordinate, as a hex string.
         * @param gyHex Base point G's y-coordinate, as a hex string.
         * @param nHex Subgroup order n, as a hex string.
         */
        CEc2Curve(
            EGf2mKnownField fieldId, const char* aHex, const char* bHex,
            const char* gxHex, const char* gyHex, const char* nHex
        );

        /**
         * Maps a known binary curve identifier to the EAsymmetrics identifying it -- see
         * CEcCurve::identify()'s own doc comment for why this is an explicit switch (CEcdsa2's
         * own constructor calls this to set its _which).
         * @param which The known curve identifier.
         * @return The corresponding EAsymmetrics; EASYM_B163 for an identifier not among the
         * known curves (unreachable for a validly-constructed CEcdsa2).
         */
        static EAsymmetrics identify(EEc2KnownCurves which);

        /**
         * Retrieves a known curve by its enum identifier.
         * @param curve The known curve identifier.
         * @param out Receives the corresponding CEc2Curve instance.
         * @return true if curve was a valid, known identifier; false otherwise (out is left unchanged).
         */
        static inline bool knownCurves(EEc2KnownCurves curve, CEc2Curve& out) {
            if (curve <= ECURVE2_UNKNOWN || curve >= ECURVE2_MAX) {
                return false;
            }

            out = _knownCurves[curve - 1];
            return true;
        }

        /**
         * @return The width, in bytes, of one field element (ceil(field->m / 8)) -- the fixed
         * width the uncompressed point encoding pads x/y coordinates to.
         */
        size_t fieldByteLen() const;

        /**
         * @param pt The point to test.
         * @return true if pt satisfies the curve equation (the point at infinity trivially does).
         */
        bool isOnCurve(const SEc2Point& pt) const;

        /**
         * @param p1 One point.
         * @param p2 The other point.
         * @return p1 + p2, per the curve's group law.
         */
        SEc2Point add(const SEc2Point& p1, const SEc2Point& p2) const;

        /**
         * @param pt The point to double.
         * @return pt + pt, per the curve's group law.
         */
        SEc2Point doublePoint(const SEc2Point& pt) const;

        /**
         * Computes k*pt via MSB-first double-and-add.
         * @param pt The point to multiply.
         * @param k The scalar to multiply by.
         * @return k*pt.
         */
        SEc2Point scalarMul(const SEc2Point& pt, const CBigNum& k) const;

        /**
         * Computes k*g (the base point specifically, not an arbitrary point) -- see
         * CEcCurve::scalarMulBase()'s identical doc comment (eccurve.hpp) for the full
         * rationale, which applies here unchanged.
         * @param k The scalar to multiply g by.
         * @return k*g.
         */
        SEc2Point scalarMulBase(const CBigNum& k) const;

        /**
         * Encodes pt in SEC1 form: a single 0x00 byte for the point at infinity, otherwise
         * 0x04 || X || Y with X/Y padded to fieldByteLen() bytes each (uncompressed form).
         * @param pt The point to encode.
         * @param out The destination array, replacing any content it previously held.
         * @return true on success; false on failure.
         */
        bool encodePoint(const SEc2Point& pt, TArray<uint8_t>& out) const;

        /**
         * Decodes a SEC1-encoded point (see encodePoint()), validating it lies on the curve.
         * @param data The SEC1-encoded point.
         * @param out Receives the decoded point.
         * @return true if data was a well-formed, on-curve point; false otherwise.
         */
        bool decodePoint(SReadOnlyByteSpan data, SEc2Point& out) const;
    };

} // namespace crypto
} // namespace certpp

#endif
