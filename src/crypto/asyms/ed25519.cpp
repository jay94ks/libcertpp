#include <certpp/crypto/asyms/ed25519.hpp>
#include <certpp/utils/secure.hpp>
#include <certpp/utils/bignum.hpp>
#include "fe25519.hpp"
#include <certpp/crypto/rng.hpp>
#include <certpp/crypto/hashers/sha512.hpp>
#include <array>
#include <cstring>
#include <memory>
#include <utility>

namespace certpp {
namespace crypto {

    namespace {

        // --> Ed25519 works with TWO moduli, and conflating them produces a signature that
        // verifies against itself and against nothing else in the world:
        //
        //   * the field prime p = 2^255 - 19, for point coordinates. That is Fe25519's modulus,
        //     and every coordinate in this file is an Fe25519.
        //   * the group order L = 2^252 + 27742317777372353535851937790883648493, for scalars --
        //     the clamped private scalar, signing's nonce r, the reduced hash k, and the S half
        //     of a signature. Those stay on CBigNum, every one of them reduced mod groupOrder().
        //
        // The split is carried by the type system rather than by discipline: EdPoint and
        // EdPointProj hold nothing but Fe25519, so a scalar cannot be stored in a point;
        // Fe25519 has no constructor, conversion or assignment from CBigNum, and vice versa, so
        // the only route between the two is an explicit 32-byte encode/decode that appears
        // nowhere in this file. Routing a scalar through Fe25519 therefore does not compile, and
        // routing a coordinate through CBigNum mod L does not either.
        //
        // The one place the two meet is the scalar-multiplication helpers, which take a mod-L
        // scalar and return a mod-p point -- and they read the scalar only as bits or bytes,
        // never as a field element.

        /* An edwards25519 field element of the small integer `value`, for the derived constants
         * below. Deliberately not a general CBigNum-to-Fe25519 bridge -- see the note above; it
         * goes through the byte encoding, which is the only conversion Fe25519 has. */
        Fe25519 feSmall(uint32_t value) {
            uint8_t bytes[32] = { 0 };
            bytes[0] = uint8_t(value);
            bytes[1] = uint8_t(value >> 8);
            bytes[2] = uint8_t(value >> 16);
            bytes[3] = uint8_t(value >> 24);

            Fe25519 out;
            out.fromBytes(bytes);
            return out;
        }

        /* A point on edwards25519 (or any twisted Edwards curve with a = -1), in affine
         * coordinates. Unlike a short-Weierstrass SEcPoint, there is no separate point at
         * infinity -- the group identity (0, 1) is an ordinary finite point. */
        struct EdPoint {
            Fe25519 x;
            Fe25519 y;
        };

        /* An edwards25519 point in extended projective coordinates (Hisil/Wong/Carter/Dawson,
         * "Twisted Edwards Curves Revisited", eprint 2008/522): x = X/Z, y = Y/Z, with the
         * auxiliary T = X*Y/Z maintained alongside so pointAddProj() below needs no inversion.
         * Scalar multiplication and its cached tables use this representation, converting to
         * affine only at their external boundaries. */
        struct EdPointProj {
            Fe25519 x, y, z, t;
        };

        /* Cached projective and affine-precomputed forms used by public verification and the
         * fixed-base table. Keeping y+x, y-x and 2*d*x*y ready removes one or two field
         * multiplications from every addition compared with two generic projective points. */
        struct EdPointCached {
            Fe25519 yPlusX, yMinusX, z, t2d;
        };

        struct EdPointPrecomp {
            Fe25519 yPlusX, yMinusX, xy2d;
        };

        struct EdPointP2 {
            Fe25519 x, y, z;
        };

        /* Completed coordinates: affine x = X/Z and y = Y/T. They let a doubling remain in
         * its four-square form until the next addition decision, saving one field multiply per
         * bit in verification-time scalar multiplication. */
        struct EdPointP1P1 {
            Fe25519 x, y, z, t;
        };

        /* Everything specific to implementing edwards25519 (RFC 8032): field/group constants,
         * point arithmetic (affine and extended-projective), point encode/decode, and the
         * SHA-512-based key-derivation RFC 8032 ties to this specific curve -- bundled into one
         * class rather than left as file-scope free functions, mirroring how AesCore/DesCore/
         * ChaCha20Core (crypto/syms/) each own everything their algorithm needs.
         *
         * --> The coordinate arithmetic here used to run on CBigNum, and that was the library's
         * single worst performance bug rather than a matter of taste. CBigNum::mulMod() is mul()
         * then mod(), and mod() calls divMod() -- so every field multiplication in the point
         * arithmetic performed a full big-number division, and a 255-bit ladder performs tens of
         * thousands of them. Measured on this machine: sign 11.4 ms and verify 37.9 ms, against
         * X25519's 0.25 ms for a scalar multiplication on the *same curve in the same build*,
         * the difference being that X25519 had already been migrated onto Fe25519. Doing the
         * same here is what this file's arithmetic now is. The extended-coordinate formulas and
         * fixed-base table below have since been tightened further without changing that split. */
        class Edwards25519 {
        private:
            static constexpr size_t BASE_TABLE_POSITIONS = 32;
            static constexpr size_t BASE_TABLE_ENTRIES = 8;

            /* --> Scalar bit count, fixed rather than taken from the scalar's own bitLength().
             * Both scalar multiplications below used to loop over CBigNum::bitLength() bits,
             * which is the position of the scalar's top set bit -- for signing's nonce r, a
             * secret, that made the *number of iterations* leak how large r is. The clamped
             * private scalar is always 255 bits by construction so it never leaked, but r and
             * k*s are reduced mod L and vary. 256 covers both (L < 2^253, the clamped scalar <
             * 2^255), and CBigNum::testBit() reads false past the top limb, so the extra leading
             * zero bits cost two ladder steps and change nothing: a zero bit adds the identity
             * to r0 and leaves the r1 - r0 == P invariant intact. */
            static constexpr size_t SCALAR_BITS = 256;

            /* The edwards25519 curve equation's d = -121665/121666 mod p (RFC 8032 5.1), derived
             * from the two small integers rather than hardcoded as a 255-bit constant. */
            static const Fe25519& curveD() {
                static const Fe25519 d = [] {
                    Fe25519 inv121666;
                    Fe25519::invert(inv121666, feSmall(121666));

                    Fe25519 value;
                    Fe25519::mul(value, feSmall(121665), inv121666);
                    Fe25519::neg(value, value);
                    return value;
                }();

                return d;
            }

            static EdPoint identityPoint() {
                EdPoint out;
                out.x.setZero();
                out.y.setOne();
                return out;
            }

            static EdPointProj toProjective(const EdPoint& pt) {
                EdPointProj out;
                out.x = pt.x;
                out.y = pt.y;
                out.z.setOne();
                Fe25519::mul(out.t, pt.x, pt.y);
                return out;
            }

            static EdPoint toAffine(const EdPointProj& pt) {
                Fe25519 zInv;
                Fe25519::invert(zInv, pt.z);

                EdPoint out;
                Fe25519::mul(out.x, pt.x, zInv);
                Fe25519::mul(out.y, pt.y, zInv);
                return out;
            }

            static EdPoint toAffine(const EdPointP2& pt) {
                Fe25519 zInv;
                Fe25519::invert(zInv, pt.z);

                EdPoint out;
                Fe25519::mul(out.x, pt.x, zInv);
                Fe25519::mul(out.y, pt.y, zInv);
                return out;
            }

            static EdPointProj identityPointProj() {
                EdPointProj out;
                out.x.setZero();
                out.y.setOne();
                out.z.setOne();
                out.t.setZero();
                return out;
            }

            static EdPointP2 identityPointP2() {
                EdPointP2 out;
                out.x.setZero();
                out.y.setOne();
                out.z.setOne();
                return out;
            }

            /* 2*d, precomputed once for pointAddProj()'s "C" term (RFC 8032 5.1's d, see
             * curveD()). */
            static const Fe25519& twoCurveD() {
                static const Fe25519 v = [] {
                    Fe25519 value;
                    Fe25519::add(value, curveD(), curveD());
                    return value;
                }();

                return v;
            }

            /* Extended-coordinates unified addition ("add-2008-hwcd-3"): this formula handles
             * P1 + P1 (doubling) too -- it is a direct
             * coordinate transform of the same complete twisted Edwards addition law, just
             * avoiding a modular inversion per call by carrying the common denominator in Z
             * instead of dividing it out immediately. pointDoubleProj() handles the much more
             * frequent same-point case with its cheaper dedicated formula.
             *
             * Nine field multiplications and seven additions/subtractions, all on Fe25519, and
             * no general modular reduction step of its own. The loose sums feed directly into a
             * multiplication; each multiplied result is carry-reduced for the next formula. */
            static EdPointProj pointAddProj(const EdPointProj& p1, const EdPointProj& p2) {
                Fe25519 lhs, rhs;

                Fe25519::subLoose(lhs, p1.y, p1.x);
                Fe25519::subLoose(rhs, p2.y, p2.x);

                Fe25519 A;
                Fe25519::mul(A, lhs, rhs);

                Fe25519::addLoose(lhs, p1.y, p1.x);
                Fe25519::addLoose(rhs, p2.y, p2.x);

                Fe25519 B;
                Fe25519::mul(B, lhs, rhs);

                Fe25519 C;
                Fe25519::mul(C, p1.t, p2.t);
                Fe25519::mul(C, C, twoCurveD());

                Fe25519 D;
                Fe25519::mul(D, p1.z, p2.z);
                Fe25519::add(D, D, D);

                Fe25519 E, F, G, H;
                Fe25519::subLoose(E, B, A);
                Fe25519::subLoose(F, D, C);
                Fe25519::addLoose(G, D, C);
                Fe25519::addLoose(H, B, A);

                EdPointProj out;
                Fe25519::mul(out.x, E, F);
                Fe25519::mul(out.y, G, H);
                Fe25519::mul(out.z, F, G);
                Fe25519::mul(out.t, E, H);
                return out;
            }

            static EdPointCached toCached(const EdPointProj& pt) {
                EdPointCached out;
                Fe25519::addLoose(out.yPlusX, pt.y, pt.x);
                Fe25519::subLoose(out.yMinusX, pt.y, pt.x);
                out.z = pt.z;
                Fe25519::mul(out.t2d, pt.t, twoCurveD());
                return out;
            }

            static EdPointProj pointAddCached(
                const EdPointProj& p1, const EdPointCached& p2
            ) {
                Fe25519 lhs, rhs;
                Fe25519::subLoose(lhs, p1.y, p1.x);
                Fe25519::addLoose(rhs, p1.y, p1.x);

                Fe25519 A, B, C, D;
                Fe25519::mul(A, lhs, p2.yMinusX);
                Fe25519::mul(B, rhs, p2.yPlusX);
                Fe25519::mul(C, p1.t, p2.t2d);
                Fe25519::mul(D, p1.z, p2.z);
                Fe25519::add(D, D, D);

                Fe25519 E, F, G, H;
                Fe25519::subLoose(E, B, A);
                Fe25519::subLoose(F, D, C);
                Fe25519::addLoose(G, D, C);
                Fe25519::addLoose(H, B, A);

                EdPointProj out;
                Fe25519::mul(out.x, E, F);
                Fe25519::mul(out.y, G, H);
                Fe25519::mul(out.z, F, G);
                Fe25519::mul(out.t, E, H);
                return out;
            }

            static EdPointProj pointAddPrecomp(
                const EdPointProj& p1, const EdPointPrecomp& p2
            ) {
                Fe25519 lhs, rhs;
                Fe25519::subLoose(lhs, p1.y, p1.x);
                Fe25519::addLoose(rhs, p1.y, p1.x);

                Fe25519 A, B, C, D;
                Fe25519::mul(A, lhs, p2.yMinusX);
                Fe25519::mul(B, rhs, p2.yPlusX);
                Fe25519::mul(C, p1.t, p2.xy2d);
                Fe25519::add(D, p1.z, p1.z);

                Fe25519 E, F, G, H;
                Fe25519::subLoose(E, B, A);
                Fe25519::subLoose(F, D, C);
                Fe25519::addLoose(G, D, C);
                Fe25519::addLoose(H, B, A);

                EdPointProj out;
                Fe25519::mul(out.x, E, F);
                Fe25519::mul(out.y, G, H);
                Fe25519::mul(out.z, F, G);
                Fe25519::mul(out.t, E, H);
                return out;
            }

            static EdPointCached negate(const EdPointCached& pt) {
                EdPointCached out;
                out.yPlusX = pt.yMinusX;
                out.yMinusX = pt.yPlusX;
                out.z = pt.z;
                Fe25519::neg(out.t2d, pt.t2d);
                return out;
            }

            static EdPointPrecomp negate(const EdPointPrecomp& pt) {
                EdPointPrecomp out;
                out.yPlusX = pt.yMinusX;
                out.yMinusX = pt.yPlusX;
                Fe25519::neg(out.xy2d, pt.xy2d);
                return out;
            }

            static EdPointP2 toP2(const EdPointP1P1& pt) {
                EdPointP2 out;
                Fe25519::mul(out.x, pt.x, pt.t);
                Fe25519::mul(out.y, pt.y, pt.z);
                Fe25519::mul(out.z, pt.z, pt.t);
                return out;
            }

            static EdPointProj toP3(const EdPointP1P1& pt) {
                EdPointProj out;
                Fe25519::mul(out.x, pt.x, pt.t);
                Fe25519::mul(out.y, pt.y, pt.z);
                Fe25519::mul(out.z, pt.z, pt.t);
                Fe25519::mul(out.t, pt.x, pt.y);
                return out;
            }

            static EdPointP1P1 pointDoubleP2(const EdPointP2& pt) {
                EdPointP1P1 out;
                Fe25519::square(out.x, pt.x);
                Fe25519::square(out.z, pt.y);
                Fe25519::square(out.t, pt.z);
                Fe25519::add(out.t, out.t, out.t);

                Fe25519 sum, sumSquared;
                Fe25519::addLoose(sum, pt.x, pt.y);
                Fe25519::square(sumSquared, sum);
                Fe25519::add(out.y, out.z, out.x);
                Fe25519::sub(out.z, out.z, out.x);
                Fe25519::sub(out.x, sumSquared, out.y);
                Fe25519::sub(out.t, out.t, out.z);
                return out;
            }

            static EdPointP1P1 pointAddCachedP1P1(
                const EdPointProj& p1, const EdPointCached& p2
            ) {
                Fe25519 yMinusX, yPlusX;
                Fe25519::subLoose(yMinusX, p1.y, p1.x);
                Fe25519::addLoose(yPlusX, p1.y, p1.x);

                Fe25519 A, B, C, D;
                Fe25519::mul(A, yMinusX, p2.yMinusX);
                Fe25519::mul(B, yPlusX, p2.yPlusX);
                Fe25519::mul(C, p1.t, p2.t2d);
                Fe25519::mul(D, p1.z, p2.z);
                Fe25519::add(D, D, D);

                EdPointP1P1 out;
                Fe25519::subLoose(out.x, B, A);
                Fe25519::addLoose(out.y, B, A);
                Fe25519::addLoose(out.z, D, C);
                Fe25519::subLoose(out.t, D, C);
                return out;
            }

            static EdPointP1P1 pointAddPrecompP1P1(
                const EdPointProj& p1, const EdPointPrecomp& p2
            ) {
                Fe25519 yMinusX, yPlusX;
                Fe25519::subLoose(yMinusX, p1.y, p1.x);
                Fe25519::addLoose(yPlusX, p1.y, p1.x);

                Fe25519 A, B, C;
                Fe25519::mul(A, yMinusX, p2.yMinusX);
                Fe25519::mul(B, yPlusX, p2.yPlusX);
                Fe25519::mul(C, p1.t, p2.xy2d);

                Fe25519 D;
                Fe25519::add(D, p1.z, p1.z);

                EdPointP1P1 out;
                Fe25519::subLoose(out.x, B, A);
                Fe25519::addLoose(out.y, B, A);
                Fe25519::addLoose(out.z, D, C);
                Fe25519::subLoose(out.t, D, C);
                return out;
            }

            /* Extended-coordinate doubling ("dbl-2008-hwcd") for a = -1. The unified
             * addition above is complete and can double a point, but doing so spends nine
             * general field multiplications. This formula uses four multiplications and four
             * squarings instead. Scalar multiplication doubles once per bit, so keeping the
             * operation separate removes work from every fixed-base path and from the default
             * field layout's arbitrary-point path while preserving the complete addition formula
             * for unlike points. */
            static EdPointProj pointDoubleProj(const EdPointProj& pt) {
                Fe25519 A, B, C, D, E, F, G, H;
                Fe25519::square(A, pt.x);
                Fe25519::square(B, pt.y);
                Fe25519::square(C, pt.z);
                Fe25519::add(C, C, C);
                Fe25519::neg(D, A);

                Fe25519 sum;
                Fe25519::addLoose(sum, pt.x, pt.y);
                Fe25519::square(E, sum);
                Fe25519::sub(E, E, A);
                Fe25519::sub(E, E, B);

                Fe25519::add(G, D, B);
                Fe25519::sub(F, G, C);
                Fe25519::sub(H, D, B);

                EdPointProj out;
                Fe25519::mul(out.x, E, F);
                Fe25519::mul(out.y, G, H);
                Fe25519::mul(out.t, E, H);
                Fe25519::mul(out.z, F, G);
                return out;
            }

            /* The ladder's conditional exchange, under an all-ones/all-zero mask rather than a
             * bool. This used to be CBigNum::condSwap, whose own documentation admits it is a
             * plain branch -- and the condition here *is* a bit of a secret scalar, so the branch
             * leaked one bit of it per iteration. Fe25519::condSwap is arithmetic. */
            static void condSwapPointProj(uint32_t mask, EdPointProj& a, EdPointProj& b) {
                Fe25519::condSwap(mask, a.x, b.x);
                Fe25519::condSwap(mask, a.y, b.y);
                Fe25519::condSwap(mask, a.z, b.z);
                Fe25519::condSwap(mask, a.t, b.t);
            }

            /* Branch-free double-and-add over EdPointProj -- same R0/R1 ladder invariant as
             * CEcCurve::scalarMul() (crypto/eccurve.cpp), just entirely in extended projective
             * coordinates so the loop itself never pays for a modular inversion; toAffine() below
             * pays for exactly one, at the very end, replacing the one-inversion-per-step affine
             * version used to have.
             *
             * `k` is a scalar mod L, read only as bits -- never as a field element. */
            static EdPointProj scalarMulProj(const EdPointProj& pt, const CBigNum& k) {
                EdPointProj r0 = identityPointProj();
                EdPointProj r1 = pt;

                for (size_t i = SCALAR_BITS; i-- > 0; ) {
                    // 0 or 0xFFFFFFFF, computed rather than branched on.
                    const uint32_t mask = uint32_t(0) - uint32_t(k.testBit(i) ? 1u : 0u);

                    condSwapPointProj(mask, r0, r1);
                    EdPointProj sum = pointAddProj(r0, r1);
#if defined(CERTPP_FE25519_RADIX51)
                    // See scalarMulPublic(): this opt-in layout keeps the proven unified formula
                    // across a full 256-step arbitrary-point ladder.
                    EdPointProj doubled = pointAddProj(r0, r0);
#else
                    EdPointProj doubled = pointDoubleProj(r0);
#endif
                    r1 = sum;
                    r0 = doubled;
                    condSwapPointProj(mask, r0, r1);
                }

                return r0;
            }

            /* Recovers x from y and a desired sign (parity) bit, per RFC 8032 5.1.3: x^2 =
             * (y^2-1) / (d*y^2+1), then the root with the wrong parity is negated. Used both for
             * decoding a compressed point and for deriving the base point's x-coordinate from its
             * y.
             *
             * The square root itself is Fe25519::squareRoot(), which is where the old fieldSqrt()
             * went: the p == 5 (mod 8) algorithm is a property of the field, not of the curve. */
            static bool recoverX(const Fe25519& y, bool signBit, Fe25519& outX) {
                Fe25519 one;
                one.setOne();

                Fe25519 yy;
                Fe25519::square(yy, y);

                Fe25519 u;
                Fe25519::sub(u, yy, one);

                Fe25519 v;
                Fe25519::mul(v, curveD(), yy);
                Fe25519::add(v, v, one);

                // Fe25519::invert() returns zero for a zero input rather than failing, which
                // keeps it branch-free -- so a v with no inverse has to be caught here instead.
                // (No edwards25519 y actually produces one, but a decode must not depend on
                // that being true.)
                if (v.isZero()) {
                    return false;
                }

                Fe25519 x;
                if (!Fe25519::squareRootRatio(x, u, v)) {
                    return false;
                }

                if (x.isZero() && signBit) {
                    return false; // RFC 8032 5.1.3: x == 0 must pair with a clear sign bit
                }

                if (x.isOdd() != signBit) {
                    Fe25519::neg(x, x);
                }

                outX = x;
                return true;
            }

            /* The edwards25519 base point B, derived from By = 4/5 (mod p) (RFC 8032 5.1) rather
             * than hardcoded, avoiding a second 255-bit constant to transcribe -- recoverX()
             * (needed anyway for point decoding) does the rest. RFC 8032 encodes B with a clear
             * sign bit. */
            static const EdPoint& basePoint() {
                static const EdPoint b = [] {
                    Fe25519 inv5;
                    Fe25519::invert(inv5, feSmall(5));

                    Fe25519 by;
                    Fe25519::mul(by, feSmall(4), inv5);

                    Fe25519 bx;
                    bool ok = recoverX(by, false, bx);
                    (void)ok; // recoverX() always succeeds for edwards25519's actual base point

                    return EdPoint{ bx, by };
                }();

                return b;
            }

            using BaseTableRow = std::array<EdPointPrecomp, BASE_TABLE_ENTRIES>;
            using BaseTable = std::array<BaseTableRow, BASE_TABLE_POSITIONS>;

            /* Row i contains (1..8) * 256^i * B. This is the standard signed-radix-16 Ed25519
             * layout: sum the odd nibbles, multiply the accumulator by 16, then sum the even
             * nibbles. It replaces 256 point doublings per fixed-base multiplication with four.
             * The table is derived once from B rather than transcribed as thousands of limbs. */
            static const BaseTable& baseTable() {
                static const BaseTable table = [] {
                    BaseTable t;
                    std::array<EdPointProj, BASE_TABLE_POSITIONS * BASE_TABLE_ENTRIES> points;
                    EdPointProj positionBase = toProjective(basePoint());

                    for (size_t position = 0; position < BASE_TABLE_POSITIONS; ++position) {
                        const size_t offset = position * BASE_TABLE_ENTRIES;
                        points[offset] = positionBase;
                        for (size_t multiple = 1; multiple < BASE_TABLE_ENTRIES; ++multiple) {
                            points[offset + multiple] =
                                pointAddProj(points[offset + multiple - 1], positionBase);
                        }

                        if (position + 1 < BASE_TABLE_POSITIONS) {
                            for (size_t doubling = 0; doubling < 8; ++doubling) {
                                positionBase = pointDoubleProj(positionBase);
                            }
                        }
                    }

                    /* Batch-normalize the 256 generated points with one inversion. The table is
                     * initialized once; each subsequent mixed addition saves two field
                     * multiplications and the stored table is smaller than its projective form. */
                    std::array<Fe25519, BASE_TABLE_POSITIONS * BASE_TABLE_ENTRIES> prefixes;
                    Fe25519 product;
                    product.setOne();
                    for (size_t i = 0; i < points.size(); ++i) {
                        prefixes[i] = product;
                        Fe25519::mul(product, product, points[i].z);
                    }
                    Fe25519::invert(product, product);

                    for (size_t i = points.size(); i-- > 0; ) {
                        Fe25519 zInv;
                        Fe25519::mul(zInv, product, prefixes[i]);
                        Fe25519::mul(product, product, points[i].z);

                        Fe25519 x, y, xy;
                        Fe25519::mul(x, points[i].x, zInv);
                        Fe25519::mul(y, points[i].y, zInv);
                        Fe25519::mul(xy, x, y);

                        EdPointPrecomp& out =
                            t[i / BASE_TABLE_ENTRIES][i % BASE_TABLE_ENTRIES];
                        Fe25519::add(out.yPlusX, y, x);
                        Fe25519::sub(out.yMinusX, y, x);
                        Fe25519::mul(out.xy2d, xy, twoCurveD());
                    }

                    return t;
                }();

                return table;
            }

            /* Returns all ones when a == b and zero otherwise, without a branch. */
            static uint32_t equalMask(uint32_t a, uint32_t b) {
                uint32_t difference = a ^ b;
                uint32_t nonZero = (difference | (uint32_t(0) - difference)) >> 31;
                return uint32_t(0) - (nonZero ^ 1u);
            }

            static void conditionalAssign(
                uint32_t mask, Fe25519& target, const Fe25519& source
            ) {
                const Fe25519::Limb limbMask = Fe25519::Limb(int32_t(mask));
                for (size_t i = 0; i < Fe25519::LIMBS; ++i) {
                    target.limbs[i] ^= limbMask & (target.limbs[i] ^ source.limbs[i]);
                }
            }

            /* Selects digit * 256^position * B by scanning the full row. digit is in [-8, 8].
             * Neither the table address nor the operation count depends on the secret digit. */
            static EdPointPrecomp selectBasePoint(size_t position, int16_t digit) {
                const uint32_t encoded = uint32_t(int32_t(digit));
                const uint32_t negative = encoded >> 31;
                const uint32_t signMask = uint32_t(0) - negative;
                const uint32_t magnitude = (encoded ^ signMask) + negative;

                EdPointPrecomp selected;
                selected.yPlusX.setOne();
                selected.yMinusX.setOne();
                selected.xy2d.setZero();
                const BaseTableRow& row = baseTable()[position];
                for (uint32_t i = 1; i <= BASE_TABLE_ENTRIES; ++i) {
                    const uint32_t mask = equalMask(magnitude, i);
                    conditionalAssign(mask, selected.yPlusX, row[i - 1].yPlusX);
                    conditionalAssign(mask, selected.yMinusX, row[i - 1].yMinusX);
                    conditionalAssign(mask, selected.xy2d, row[i - 1].xy2d);
                }

                EdPointPrecomp negated = negate(selected);
                conditionalAssign(signMask, selected.yPlusX, negated.yPlusX);
                conditionalAssign(signMask, selected.yMinusX, negated.yMinusX);
                conditionalAssign(signMask, selected.xy2d, negated.xy2d);
                return selected;
            }

        public:
            /* The edwards25519 base point's subgroup order L = 2^252 +
             * 0x14DEF9DEA2F79CD65812631A5CF5D3ED (RFC 8032 5.1; independently confirmed against a
             * second source before hardcoding -- see this module's asyms/ siblings for why that
             * matters). The addend has no simpler closed form, unlike the field prime.
             *
             * This is the *scalar* modulus and the only modulus in this file that is not p, so it
             * is the only one that is still a CBigNum -- Fe25519 is valid for p alone, and
             * reducing a scalar with it would silently produce a signature that verifies against
             * itself and nothing else. There is deliberately no edwards25519 equivalent of
             * fieldPrime() here any more: p now lives inside Fe25519, which is the only thing
             * that needs it. */
            static const CBigNum& groupOrder() {
                static const CBigNum l = [] {
                    CBigNum addend;
                    CBigNum::fromHex("14DEF9DEA2F79CD65812631A5CF5D3ED", addend);
                    return CBigNum(uint64_t(1)).shl(252).add(addend);
                }();
                return l;
            }

            static bool isIdentity(const EdPoint& pt) {
                Fe25519 one;
                one.setOne();

                return pt.x.isZero() && pt.y.isEqual(one);
            }

            static bool isIdentity(const EdPointProj& pt) {
                Fe25519 difference;
                Fe25519::sub(difference, pt.y, pt.z);
                return pt.x.isZero() && difference.isZero();
            }

            static bool isIdentity(const EdPointP2& pt) {
                Fe25519 difference;
                Fe25519::sub(difference, pt.y, pt.z);
                return pt.x.isZero() && difference.isZero();
            }

            static bool isEqual(const EdPointProj& projective, const EdPoint& affine) {
                Fe25519 x, y;
                Fe25519::mul(x, affine.x, projective.z);
                Fe25519::mul(y, affine.y, projective.z);
                return projective.x.isEqual(x) && projective.y.isEqual(y);
            }

            static bool isEqual(const EdPointP2& projective, const EdPoint& affine) {
                Fe25519 x, y;
                Fe25519::mul(x, affine.x, projective.z);
                Fe25519::mul(y, affine.y, projective.z);
                return projective.x.isEqual(x) && projective.y.isEqual(y);
            }

            /* Checks -x^2 + y^2 == 1 + d*x^2*y^2 (mod p), i.e. edwards25519's curve equation
             * (RFC 8032 5.1). Stated in that literal form rather than the rearrangement the
             * CBigNum version used, which existed only to dodge a modNeg(); over signed limbs a
             * subtraction is no more expensive than an addition, so the detour is gone. */
            static bool isOnCurve(const Fe25519& x, const Fe25519& y) {
                Fe25519 one;
                one.setOne();

                Fe25519 xx, yy;
                Fe25519::square(xx, x);
                Fe25519::square(yy, y);

                Fe25519 lhs;
                Fe25519::sub(lhs, yy, xx);              // -x^2 + y^2

                Fe25519 rhs;
                Fe25519::mul(rhs, curveD(), xx);
                Fe25519::mul(rhs, rhs, yy);
                Fe25519::add(rhs, rhs, one);            // 1 + d*x^2*y^2

                return lhs.isEqual(rhs);
            }

            static EdPoint scalarMul(const EdPoint& pt, const CBigNum& k) {
                return toAffine(scalarMulProj(toProjective(pt), k));
            }

            static void slidePublic(std::array<int8_t, SCALAR_BITS>& out, const CBigNum& k) {
                for (size_t i = 0; i < SCALAR_BITS; ++i) {
                    out[i] = k.testBit(i) ? int8_t(1) : int8_t(0);
                }

                for (size_t i = 0; i < SCALAR_BITS; ++i) {
                    if (out[i] == 0) {
                        continue;
                    }
                    for (size_t distance = 1;
                         distance <= 6 && i + distance < SCALAR_BITS; ++distance) {
                        if (out[i + distance] == 0) {
                            continue;
                        }

                        const int shifted = int(out[i + distance]) << distance;
                        if (int(out[i]) + shifted <= 15) {
                            out[i] = int8_t(int(out[i]) + shifted);
                            out[i + distance] = 0;
                        } else if (int(out[i]) - shifted >= -15) {
                            out[i] = int8_t(int(out[i]) - shifted);
                            for (size_t carry = i + distance; carry < SCALAR_BITS; ++carry) {
                                if (out[carry] == 0) {
                                    out[carry] = 1;
                                    break;
                                }
                                out[carry] = 0;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }

            /* Windowed multiplication for verification-time public scalars and points. Unlike
             * scalarMulProj(), this indexes a table with scalar bits, so it must never receive a
             * private scalar. Its current callers use either the fixed public group order L or
             * k = SHA-512(R || A || message) mod L. Avoiding the ladder's unconditional addition
             * for every bit is safe there and replaces most additions with a public sliding-window
             * table lookup.
             *
             * The optional radix-51 field layout retains the ladder. The fixed-base vectors pass
             * there, but the dedicated-doubling/window combination does not retain the correct
             * result across a full arbitrary-point multiplication. Keeping the proven path is
             * preferable to making an opt-in layout silently reject a valid signature. */
            static EdPointP2 scalarMulPublicProj(const EdPoint& pt, const CBigNum& k) {
#if defined(CERTPP_FE25519_RADIX51)
                const EdPointProj result = scalarMulProj(toProjective(pt), k);
                return EdPointP2{ result.x, result.y, result.z };
#else
                std::array<int8_t, SCALAR_BITS> digits;
                slidePublic(digits, k);

                const std::array<EdPointCached, 8> oddTable = publicOddTable(pt);

                size_t top = SCALAR_BITS;
                while (top != 0 && digits[top - 1] == 0) {
                    --top;
                }

                EdPointP2 result = identityPointP2();
                while (top-- != 0) {
                    EdPointP1P1 completed = pointDoubleP2(result);
                    const int digit = digits[top];
                    if (digit != 0) {
                        const size_t index = size_t((digit < 0 ? -digit : digit) / 2);
                        EdPointCached selected = oddTable[index];
                        if (digit < 0) {
                            selected = negate(selected);
                        }
                        completed = pointAddCachedP1P1(toP3(completed), selected);
                    }
                    result = toP2(completed);
                }

                return result;
#endif
            }

            static EdPoint scalarMulPublic(const EdPoint& pt, const CBigNum& k) {
                return toAffine(scalarMulPublicProj(pt, k));
            }

            static EdPointPrecomp toPrecomp(const EdPointProj& pt) {
                const EdPoint affine = toAffine(pt);
                EdPointPrecomp out;
                Fe25519::add(out.yPlusX, affine.y, affine.x);
                Fe25519::sub(out.yMinusX, affine.y, affine.x);
                Fe25519 xy;
                Fe25519::mul(xy, affine.x, affine.y);
                Fe25519::mul(out.xy2d, xy, twoCurveD());
                return out;
            }

            static const std::array<EdPointPrecomp, 8>& baseOddTable() {
                static const std::array<EdPointPrecomp, 8> table = [] {
                    std::array<EdPointPrecomp, 8> out;
                    EdPointProj odd = toProjective(basePoint());
                    const EdPointCached twice = toCached(pointDoubleProj(odd));
                    for (size_t i = 0; i < out.size(); ++i) {
                        out[i] = toPrecomp(odd);
                        if (i + 1 != out.size()) {
                            odd = pointAddCached(odd, twice);
                        }
                    }
                    return out;
                }();
                return table;
            }

            static std::array<EdPointCached, 8> publicOddTable(const EdPoint& pt) {
                std::array<EdPointCached, 8> out;
                EdPointProj odd = toProjective(pt);
                const EdPointCached twice = toCached(pointDoubleProj(odd));
                for (size_t i = 0; i < out.size(); ++i) {
                    out[i] = toCached(odd);
                    if (i + 1 != out.size()) {
                        odd = pointAddCached(odd, twice);
                    }
                }
                return out;
            }

            /* Computes baseScalar*B - pointScalar*pt with the verification scalars' sliding
             * windows sharing one doubling chain. Both scalars are public, so table indices,
             * signs and skipped zero digits carry no secret information. The odd multiples of
             * the public key are prepared once when that key is created and reused by every
             * verification through the key. */
            static EdPointP2 doubleScalarMulPublic(
                const CBigNum& baseScalar,
                const std::array<EdPointCached, 8>& pointOdd,
                const CBigNum& pointScalar
            ) {
                std::array<int8_t, SCALAR_BITS> pointDigits;
                std::array<int8_t, SCALAR_BITS> baseDigits;
                slidePublic(pointDigits, pointScalar);
                slidePublic(baseDigits, baseScalar);

                size_t top = SCALAR_BITS;
                while (top != 0 && pointDigits[top - 1] == 0 && baseDigits[top - 1] == 0) {
                    --top;
                }

                EdPointP2 result = identityPointP2();
                const std::array<EdPointPrecomp, 8>& baseOdd = baseOddTable();
                while (top-- != 0) {
                    EdPointP1P1 completed = pointDoubleP2(result);

                    const int pointDigit = pointDigits[top];
                    if (pointDigit != 0) {
                        const size_t index = size_t((pointDigit < 0 ? -pointDigit : pointDigit) / 2);
                        EdPointCached selected = pointOdd[index];
                        // The equation subtracts k*A, reversing the digit's own sign.
                        if (pointDigit > 0) {
                            selected = negate(selected);
                        }
                        completed = pointAddCachedP1P1(toP3(completed), selected);
                    }

                    const int baseDigit = baseDigits[top];
                    if (baseDigit != 0) {
                        const size_t index = size_t((baseDigit < 0 ? -baseDigit : baseDigit) / 2);
                        EdPointPrecomp selected = baseOdd[index];
                        if (baseDigit < 0) {
                            selected = negate(selected);
                        }
                        completed = pointAddPrecompP1P1(toP3(completed), selected);
                    }

                    result = toP2(completed);
                }

                return result;
            }

            /* Fixed-base multiplication via the signed-radix-16 table above. Every digit scans
             * all eight entries and every digit performs an addition, including zero, so signing
             * does not expose its nonce through a secret-indexed table access or skipped work. */
            static EdPoint scalarMulBase(const CBigNum& k) {
                uint8_t scalarBytes[32] = { 0 };
                const bool encoded = k.toLittleEndian(SByteSpan(scalarBytes, sizeof(scalarBytes)));
                (void)encoded; // All callers provide a scalar below 2^255, so 32 bytes always fit.

                int16_t digits[64];
                for (size_t i = 0; i < 32; ++i) {
                    digits[2 * i] = int16_t(scalarBytes[i] & 0x0F);
                    digits[2 * i + 1] = int16_t(scalarBytes[i] >> 4);
                }
                for (size_t i = 0; i < 63; ++i) {
                    const int16_t carry = int16_t((digits[i] + 8) >> 4);
                    digits[i] = int16_t(digits[i] - (carry << 4));
                    digits[i + 1] = int16_t(digits[i + 1] + carry);
                }

                EdPointProj result = identityPointProj();
                for (size_t position = 0; position < BASE_TABLE_POSITIONS; ++position) {
                    result = pointAddPrecomp(
                        result, selectBasePoint(position, digits[2 * position + 1]));
                }
                for (size_t i = 0; i < 4; ++i) {
                    result = pointDoubleProj(result);
                }
                for (size_t position = 0; position < BASE_TABLE_POSITIONS; ++position) {
                    result = pointAddPrecomp(
                        result, selectBasePoint(position, digits[2 * position]));
                }

                CSecure::zero(SByteSpan(scalarBytes, sizeof(scalarBytes)));
                CSecure::zero(SByteSpan(
                    reinterpret_cast<uint8_t*>(digits), sizeof(digits)));
                return toAffine(result);
            }

            /* Encodes pt per RFC 8032 5.1.2: y as a 32-byte little-endian integer, with the sign
             * (parity) of x placed in the top bit of the last byte.
             *
             * Cannot fail, unlike the CBigNum version it replaces -- Fe25519::toBytes() always
             * emits exactly 32 canonical bytes with bit 255 clear, where CBigNum::toLittleEndian()
             * had to report a value too large for the buffer. The callers' dead error paths went
             * with it. */
            static void encodePoint(const EdPoint& pt, uint8_t out[32]) {
                pt.y.toBytes(out);

                if (pt.x.isOdd()) {
                    out[31] |= 0x80;
                }
            }

            /* Decodes a point per RFC 8032 5.1.3, validating it lies on the curve (recoverX()
             * already guarantees this by construction, but the check is cheap and explicit).
             * Imported public keys require the prime-order subgroup. Verification may skip the
             * repeated subgroup multiplication for R because A is already in that subgroup and
             * the exact equation S*B == R + k*A can hold only when R is there too. */
            static bool decodePoint(
                SReadOnlyByteSpan bytes32, EdPoint& out, bool requireMainSubgroup = true
            ) {
                if (bytes32.size != 32) {
                    return false;
                }

                uint8_t yBytes[32];
                std::memcpy(yBytes, bytes32.data, 32);

                bool signBit = (yBytes[31] & 0x80) != 0;
                yBytes[31] &= 0x7F;

                Fe25519 y;
                y.fromBytes(yBytes);

                // RFC 8032 5.1.3 *rejects* a y at or above p rather than reducing it -- the
                // opposite of RFC 7748's rule for an X25519 u-coordinate, which X25519's
                // decodeUCoordinate() follows. Fe25519::toBytes() emits the canonical
                // representative in [0, p), so a y that does not re-encode to the bytes it came
                // from was not canonical; that replaces the old `y >= fieldPrime()` comparison
                // without needing a CBigNum copy of p to compare against.
                uint8_t canonical[32];
                y.toBytes(canonical);
                if (std::memcmp(canonical, yBytes, 32) != 0) {
                    return false;
                }

                Fe25519 x;
                if (!recoverX(y, signBit, x)) {
                    return false;
                }

                EdPoint candidate{ x, y };

                // --> Reject the identity and every other low-order (order dividing the curve's
                // cofactor, 8) point -- without this, a public key encoding the identity point,
                // combined with a signature of R == identity/S == 0, verifies against *any*
                // message (lhs == scalarMul(0) == identity, rhs == pointAdd(identity,
                // scalarMul(identity, k)) == identity for every k) -- a universal forgery in the
                // same spirit as CVE-2022-21449's missing r/s == 0 checks, just via an unchecked
                // low-order point instead of a raw zero. Public-key decoding also performs the
                // full subgroup check below. Verification decodes R with requireMainSubgroup ==
                // false and relies on its exact, uncofactored equation to reject every R outside
                // the subgroup; the identity remains an explicit rejection on both paths.
                if (isIdentity(candidate)) {
                    return false; // the identity has order 1, which trivially "divides" L too --
                                   // the subgroup check below can't tell it apart from a real point.
                }

                // A legitimate point's order always divides L (it's s*B for some scalar s, and B
                // has order exactly L), so L*point == identity for a legitimate point;
                // edwards25519's cofactor is 8 and gcd(8, L) == 1, so for a genuine low-order
                // point of order h' | 8 (h' > 1), L mod h' is invertible and L*point != identity.
                if (requireMainSubgroup
                    && !isIdentity(scalarMulPublicProj(candidate, groupOrder()))) {
                    return false;
                }

                out = candidate;
                return true;
            }

            /* Computes SHA-512(parts[0] || parts[1] || ...) in one call. */
            static void sha512(std::initializer_list<SReadOnlyByteSpan> parts, uint8_t out[64]) {
                SHA512 hasher;
                for (const SReadOnlyByteSpan& part : parts) {
                    hasher.push(part);
                }

                SByteSpan outSpan(out, 64);
                hasher.finish(outSpan);
            }

            /* Derives the clamped scalar s and signing prefix from a 32-byte seed, per RFC 8032
             * 5.1.5's key generation steps 1-2. The scalar is a CBigNum because it is a scalar:
             * it is reduced and multiplied mod L, never mod p. */
            static void deriveFromSeed(const uint8_t seed[32], CBigNum& outScalar, uint8_t outPrefix[32]) {
                uint8_t h[64];
                sha512({ SReadOnlyByteSpan(seed, 32) }, h);

                uint8_t aBytes[32];
                std::memcpy(aBytes, h, 32);
                aBytes[0] &= 0xF8;
                aBytes[31] &= 0x7F;
                aBytes[31] |= 0x40;

                outScalar = CBigNum::fromLittleEndian(SReadOnlyByteSpan(aBytes, 32));

                std::memcpy(outPrefix, h + 32, 32);

                // h is the whole expanded private key -- the scalar in its first half and the
                // signing prefix in its second -- and aBytes is the scalar itself. Both have been
                // copied where they are needed; neither belongs in this frame afterwards.
                CSecure::zero(SByteSpan(h, sizeof(h)));
                CSecure::zero(SByteSpan(aBytes, sizeof(aBytes)));
            }
        };

        class EdPublicKey : public IPublicKey {
        private:
            EdPoint _point;
            std::array<EdPointCached, 8> _oddTable;
            uint8_t _encoded[32];

        public:
            EdPublicKey(EdPoint point, const uint8_t encoded[32])
                : _point(std::move(point)),
                  _oddTable(Edwards25519::publicOddTable(_point)) {
                algorithm(EASYM_ED25519);
                std::memcpy(_encoded, encoded, 32);
            }

            SKeySize keySize() const override {
                return 256;
            }

            ERetCode serialize(COctet& out) const override {
                out = COctet(_encoded, 32);
                return ERET_OK;
            }

            int32_t compare(const IKeyBasePtr& other) const override {
                if (!other) {
                    return 1;
                }

                auto o = std::dynamic_pointer_cast<EdPublicKey>(other);
                if (!o) {
                    auto otherAsym = std::dynamic_pointer_cast<IAsymmetricKeyBase>(other);
                    return otherAsym ? (int32_t(keySize()) - int32_t(otherAsym->keySize())) : 1;
                }

                return int32_t(std::memcmp(_encoded, o->_encoded, 32));
            }

            const EdPoint& point() const { return _point; }
            const std::array<EdPointCached, 8>& oddTable() const { return _oddTable; }
            const uint8_t* encoded() const { return _encoded; }
        };

        class EdPrivateKey : public IPrivateKey {
        private:
            uint8_t _seed[32];
            CBigNum _scalar;
            uint8_t _prefix[32];
            IPublicKeyPtr _publicKey;

        public:
            EdPrivateKey(const uint8_t seed[32], IPublicKeyPtr publicKey) : _publicKey(std::move(publicKey)) {
                algorithm(EASYM_ED25519);
                std::memcpy(_seed, seed, 32);
                Edwards25519::deriveFromSeed(seed, _scalar, _prefix);
            }

            ~EdPrivateKey() override {
                CSecure::zero(SByteSpan(_seed, sizeof(_seed)));
                _scalar.secureClear();
                CSecure::zero(SByteSpan(_prefix, sizeof(_prefix)));
            }

            SKeySize keySize() const override {
                return 256;
            }

            ERetCode serialize(COctet& out) const override {
                out = COctet(_seed, 32);
                return ERET_OK;
            }

            int32_t compare(const IKeyBasePtr& other) const override {
                if (!other) {
                    return 1;
                }

                auto o = std::dynamic_pointer_cast<EdPrivateKey>(other);
                if (!o) {
                    auto otherAsym = std::dynamic_pointer_cast<IAsymmetricKeyBase>(other);
                    return otherAsym ? (int32_t(keySize()) - int32_t(otherAsym->keySize())) : 1;
                }

                return int32_t(std::memcmp(_seed, o->_seed, 32));
            }

            IPublicKeyPtr publicKey() const override {
                return _publicKey;
            }

            const uint8_t* seed() const { return _seed; }
            const CBigNum& scalar() const { return _scalar; }
            const uint8_t* prefix() const { return _prefix; }
        };

    } // namespace

    /* Builds the matching public key for a 32-byte seed (shared by generateKeyPair() and
     * createPrivateKey(), which both need to derive A from d/s). */
    IPublicKeyPtr Ed25519::publicKeyFromSeed(const uint8_t seed[32]) {
        CBigNum s;
        uint8_t prefix[32];
        Edwards25519::deriveFromSeed(seed, s, prefix);

        EdPoint a = Edwards25519::scalarMulBase(s);

        uint8_t aEncoded[32];
        Edwards25519::encodePoint(a, aEncoded);

        return std::make_shared<EdPublicKey>(a, aEncoded);
    }

    namespace {

        class EdContext : public IAsymmetricContext {
        public:
            using IAsymmetricContext::IAsymmetricContext;

        protected:
            void onReset() override {
                if (privateKey() || publicKey()) {
                    sizeOfSign(64);
                }
            }

        public:
            ERetCode sign(const SReadOnlyByteSpan& message, SByteSpan& out) override {
                if (!privateKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto priv = std::dynamic_pointer_cast<EdPrivateKey>(privateKey());
                if (!priv) {
                    return ERET_KEY_FORMAT;
                }

                auto pub = std::dynamic_pointer_cast<EdPublicKey>(priv->publicKey());
                if (!pub) {
                    return ERET_KEY_ERROR; // priv's own linked public key is missing/wrong type
                }

                if (out.size < 64) {
                    return ERET_NOSPC;
                }

                // Everything from here to the encoded signature is scalar arithmetic mod L, not
                // field arithmetic mod p -- hence CBigNum throughout. The only mod-p values in
                // this function are inside scalarMulBase(), which never sees a reduced scalar as
                // a field element.
                const CBigNum& L = Edwards25519::groupOrder();

                CBigNum s(priv->scalar());

                // --> EdDSA's per-signature nonce r is as sensitive as the key: the signature
                // publishes S = r + k*s mod L with k public, so anyone who learns r for one
                // signature recovers s. prefix and rHash are what determine r, so they count as
                // the same secret. The expanded prefix is retained inside the private-key object
                // and cleared by its destructor; the per-signature hash is cleared here.
                uint8_t rHash[64];
                Edwards25519::sha512({ SReadOnlyByteSpan(priv->prefix(), 32), message }, rHash);
                CBigNum r = CBigNum::fromLittleEndian(SReadOnlyByteSpan(rHash, 64)).mod(L);

                CSecure::zero(SByteSpan(rHash, sizeof(rHash)));

                EdPoint rPoint = Edwards25519::scalarMulBase(r);
                uint8_t rEncoded[32];
                Edwards25519::encodePoint(rPoint, rEncoded);

                uint8_t kHash[64];
                Edwards25519::sha512({ SReadOnlyByteSpan(rEncoded, 32), SReadOnlyByteSpan(pub->encoded(), 32), message }, kHash);
                CBigNum k = CBigNum::fromLittleEndian(SReadOnlyByteSpan(kHash, 64)).mod(L);

                // k itself is a hash of public values, but k*s is not -- k is public, so k*s
                // hands over s. It holds that product from here until it is consumed just below.
                k.mulMod(s, L);
                s.secureClear();

                r.add(k);
                r.mod(L);
                k.secureClear();

                // r now holds the signature's own S, which is published -- so what moves into
                // sBig is public, and the nonce it used to hold was overwritten in place above.
                CBigNum sBig = std::move(r);

                uint8_t sEncoded[32];
                if (!sBig.toLittleEndian(SByteSpan(sEncoded, 32))) {
                    return ERET_UNKNOWN;
                }

                std::memcpy(out.data, rEncoded, 32);
                std::memcpy(out.data + 32, sEncoded, 32);
                out = SByteSpan(out.data, 64);

                return ERET_OK;
            }

            ERetCode verify(const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& signature) override {
                if (!publicKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto pub = std::dynamic_pointer_cast<EdPublicKey>(publicKey());
                if (!pub) {
                    return ERET_KEY_FORMAT;
                }

                if (signature.size != 64) {
                    return ERET_BADREQ;
                }

                SReadOnlyByteSpan rEncoded = signature.slice(0, 32);
                SReadOnlyByteSpan sEncoded = signature.slice(32, 32);

                EdPoint rPoint;
                /* The public key was checked for main-subgroup membership when it was imported
                 * (and a generated key is s*B). The exact, uncofactored equation checked below
                 * therefore implies that any accepted R equals S*B-k*A and is itself in the
                 * main subgroup. Repeating L*R here cannot reject anything the equation accepts;
                 * skip only that redundant multiplication while retaining canonical decoding,
                 * on-curve recovery and the explicit identity rejection. */
                if (!Edwards25519::decodePoint(rEncoded, rPoint, false)) {
                    return ERET_BADREQ;
                }

                // S is a scalar, so it is range-checked against L and never against p.
                const CBigNum& L = Edwards25519::groupOrder();
                CBigNum sBig = CBigNum::fromLittleEndian(sEncoded);
                if (sBig >= L) {
                    return ERET_BADREQ;
                }

                uint8_t kHash[64];
                Edwards25519::sha512({ rEncoded, SReadOnlyByteSpan(pub->encoded(), 32), message }, kHash);
                CBigNum k = CBigNum::fromLittleEndian(SReadOnlyByteSpan(kHash, 64)).mod(L);

                EdPointP2 expectedR = Edwards25519::doubleScalarMulPublic(
                    sBig, pub->oddTable(), k);
                return Edwards25519::isEqual(expectedR, rPoint) ? ERET_OK : ERET_BADREQ;
            }

            ERetCode createEncrypter(IAsymmetricTransformerPtr&) override {
                return ERET_NOTSUP;
            }

            ERetCode createDecrypter(IAsymmetricTransformerPtr&) override {
                return ERET_NOTSUP;
            }
        };

    } // namespace

    Ed25519::Ed25519() {
        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(256));
        keySizes(specs);
    }

    ERetCode Ed25519::generateKeyPair(const IRng& rng, SKeySize keySize, SKeyPair& out) {
        out = SKeyPair();

        if (keySize != 256) {
            return ERET_KEY_SIZE;
        }

        uint8_t seed[32];
        if (rng.fillTo(SByteSpan(seed, 32)) != ERET_OK) {
            return ERET_UNKNOWN;
        }

        IPublicKeyPtr pub = publicKeyFromSeed(seed);
        if (!pub) {
            return ERET_UNKNOWN;
        }

        auto priv = std::make_shared<EdPrivateKey>(seed, pub);

        if (checkPrivateKey(priv) != ERET_OK) {
            return ERET_AGAIN;
        }

        out = SKeyPair(pub, priv);
        return ERET_OK;
    }

    ERetCode Ed25519::checkPrivateKey(const IPrivateKeyPtr& key) const {
        auto priv = std::dynamic_pointer_cast<EdPrivateKey>(key);
        if (!priv) {
            return ERET_KEY_FORMAT;
        }

        auto pub = std::dynamic_pointer_cast<EdPublicKey>(priv->publicKey());
        if (!pub) {
            return ERET_KEY_ERROR;
        }

        const EdPoint& q = pub->point();

        // Unlike ECDSA's scalar d, EdDSA's clamped scalar s (RFC 8032 5.1.5) is deliberately NOT
        // meant to be < the group order L -- clamping fixes it into [2^254, 2^255), which is
        // larger than L (~2^252.x) by construction -- so there's no "s in [1, L-1]" range to
        // check here, unlike CEcdsa/CEcdsa2's d.

        // 1. "Point at infinity" analogue: EdDSA's identity (0, 1) is an ordinary finite point
        // (no separate infinity representation), so the degenerate case to reject is the derived
        // public key being exactly that identity -- only possible if the clamped scalar happened
        // to be an exact multiple of the group order, astronomically unlikely for an honestly
        // derived key, but still checked here for a key parsed from untrusted storage.
        if (Edwards25519::isIdentity(q)) {
            return ERET_KEY_PARAM;
        }

        // 2. Field range: there is nothing left to check. A coordinate is an Fe25519, which
        // stands for an element of GF(p) and has no representation outside it -- what used to be
        // a `q.x >= p || q.y >= p` test is now a property of the type, the same way X25519's
        // validatePublicValue() lost its own u >= p check. The only way a y at or above p can
        // enter is through decodePoint(), which rejects it there (RFC 8032 5.1.3) before an
        // EdPoint ever exists.

        // 3. Curve equation.
        if (!Edwards25519::isOnCurve(q.x, q.y)) {
            return ERET_KEY_PARAM;
        }

        // 4. Correct (order-L) subgroup: L*Q must be the identity.
        EdPoint check = Edwards25519::scalarMulPublic(q, Edwards25519::groupOrder());
        if (!Edwards25519::isIdentity(check)) {
            return ERET_KEY_PARAM;
        }

        // 5. Q must actually be s*B (s the seed's derived scalar) -- the checks above only
        // establish that Q is *some* legitimate point in the right subgroup, not that it's
        // *this key's* point; without this, a seed could be paired with an unrelated (but
        // otherwise well-formed) public point and still pass every check above.
        CBigNum s;
        uint8_t prefix[32];
        Edwards25519::deriveFromSeed(priv->seed(), s, prefix);

        EdPoint expectedQ = Edwards25519::scalarMulBase(s);
        if (!expectedQ.x.isEqual(q.x) || !expectedQ.y.isEqual(q.y)) {
            return ERET_KEY_ERROR;
        }

        return ERET_OK;
    }

    ERetCode Ed25519::createPublicKey(
        IPublicKeyPtr& out, const SReadOnlyByteSpan& keyData
    ) const {
        out.reset();
        if (keyData.size != 32) {
            return ERET_KEY_SIZE;
        }

        EdPoint point;
        if (!Edwards25519::decodePoint(keyData, point)) {
            return ERET_KEY_FORMAT;
        }

        uint8_t encoded[32];
        std::memcpy(encoded, keyData.data, 32);

        try {
            out = std::make_shared<EdPublicKey>(point, encoded);
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        return ERET_OK;
    }

    ERetCode Ed25519::createPrivateKey(
        IPrivateKeyPtr& out, const SReadOnlyByteSpan& keyData
    ) const {
        out.reset();
        if (keyData.size != 32) {
            return ERET_KEY_SIZE;
        }

        uint8_t seed[32];
        std::memcpy(seed, keyData.data, 32);

        try {
            IPublicKeyPtr pub = publicKeyFromSeed(seed);
            if (!pub) return ERET_KEY_ERROR;
            out = std::make_shared<EdPrivateKey>(seed, pub);
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        return ERET_OK;
    }

    ERetCode Ed25519::createContext(
        IAsymmetricContextPtr& out, const std::shared_ptr<IRng>& rng
    ) const {
        out.reset();
        if (!rng) return ERET_BADREQ;
        try {
            out = std::make_shared<EdContext>(rng);
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        return ERET_OK;
    }

} // namespace crypto
} // namespace certpp
