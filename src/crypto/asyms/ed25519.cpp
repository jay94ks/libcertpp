#include <certpp/crypto/asyms/ed25519.hpp>
#include <certpp/utils/secure.hpp>
#include <certpp/utils/bignum.hpp>
#include "fe25519.hpp"
#include <certpp/crypto/rng.hpp>
#include <certpp/crypto/hashers/sha512.hpp>
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
        // The one place the two meet is scalarMul()/scalarMulBase(), which take a mod-L scalar
        // and return a mod-p point -- and they read the scalar only as a sequence of bits, never
        // as a field element.

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
         * Only scalarMul() uses this representation -- everywhere else in this file still deals
         * in affine EdPoint, converting at the boundary (toProjective()/toAffine()). */
        struct EdPointProj {
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
         * same here is what this file's arithmetic now is; the curve itself (extended
         * coordinates, the fixed-base window table) was already sound and is unchanged. */
        class Edwards25519 {
        private:
            static constexpr size_t BASE_TABLE_WINDOW = 4;
            static constexpr size_t BASE_TABLE_SIZE = size_t(1) << BASE_TABLE_WINDOW; // 16

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

            static EdPointProj identityPointProj() {
                EdPointProj out;
                out.x.setZero();
                out.y.setOne();
                out.z.setOne();
                out.t.setZero();
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

            /* Extended-coordinates unified addition ("add-2008-hwcd-3"): like the affine
             * pointAdd() below, this same formula handles P1 + P1 (doubling) too -- it's a direct
             * coordinate transform of the same complete twisted Edwards addition law, just
             * avoiding a modular inversion per call by carrying the common denominator in Z
             * instead of dividing it out immediately. A dedicated (cheaper) doubling formula
             * exists but isn't used here, for the same correctness/simplicity-over-performance
             * reason the rest of this module gives.
             *
             * Nine field multiplications and seven additions/subtractions, all on Fe25519, and
             * no reduction step of its own -- every Fe25519 entry point leaves its result
             * carry-reduced, which is what removed the mod() that used to follow each one. */
            static EdPointProj pointAddProj(const EdPointProj& p1, const EdPointProj& p2) {
                Fe25519 lhs, rhs;

                Fe25519::sub(lhs, p1.y, p1.x);
                Fe25519::sub(rhs, p2.y, p2.x);

                Fe25519 A;
                Fe25519::mul(A, lhs, rhs);

                Fe25519::add(lhs, p1.y, p1.x);
                Fe25519::add(rhs, p2.y, p2.x);

                Fe25519 B;
                Fe25519::mul(B, lhs, rhs);

                Fe25519 C;
                Fe25519::mul(C, p1.t, p2.t);
                Fe25519::mul(C, C, twoCurveD());

                Fe25519 D;
                Fe25519::mul(D, p1.z, p2.z);
                Fe25519::add(D, D, D);

                Fe25519 E, F, G, H;
                Fe25519::sub(E, B, A);
                Fe25519::sub(F, D, C);
                Fe25519::add(G, D, C);
                Fe25519::add(H, B, A);

                EdPointProj out;
                Fe25519::mul(out.x, E, F);
                Fe25519::mul(out.y, G, H);
                Fe25519::mul(out.z, F, G);
                Fe25519::mul(out.t, E, H);
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
                    EdPointProj doubled = pointAddProj(r0, r0);
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

                Fe25519 vInv;
                Fe25519::invert(vInv, v);

                Fe25519 x2;
                Fe25519::mul(x2, u, vInv);

                Fe25519 x;
                if (!Fe25519::squareRoot(x, x2)) {
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

            /* table[i] = i*B (table[0] is the identity), built once via the already-verified
             * affine pointAdd() -- a one-time cost of 14 additions, amortized across every future
             * call to scalarMulBase() below for the lifetime of the process. */
            static const TArray<EdPoint>& baseTable() {
                static const TArray<EdPoint> table = [] {
                    TArray<EdPoint> t;
                    t.resize(BASE_TABLE_SIZE);

                    t[0] = identityPoint();
                    t[1] = basePoint();
                    for (size_t i = 2; i < BASE_TABLE_SIZE; ++i) {
                        t[i] = pointAdd(t[i - 1], basePoint());
                    }

                    return t;
                }();

                return table;
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

            /* Twisted Edwards addition (a = -1). Unconditionally complete (no exceptional input
             * pairs, including P + P) since d is not a square mod p for edwards25519 -- unlike
             * short-Weierstrass addition, this same formula handles doubling.
             *
             * Two inversions per call, so this is for the places that add a handful of points and
             * want the result in affine form (building the base table, and combining verify()'s
             * two terms); everything in a loop uses pointAddProj() instead. */
            static EdPoint pointAdd(const EdPoint& p1, const EdPoint& p2) {
                Fe25519 one;
                one.setOne();

                Fe25519 x1y2, y1x2, y1y2, x1x2;
                Fe25519::mul(x1y2, p1.x, p2.y);
                Fe25519::mul(y1x2, p1.y, p2.x);
                Fe25519::mul(y1y2, p1.y, p2.y);
                Fe25519::mul(x1x2, p1.x, p2.x);

                Fe25519 dxxyy;
                Fe25519::mul(dxxyy, curveD(), x1x2);
                Fe25519::mul(dxxyy, dxxyy, y1y2);

                Fe25519 xNum, xDen, yNum, yDen;
                Fe25519::add(xNum, x1y2, y1x2);
                Fe25519::add(xDen, one, dxxyy);
                Fe25519::add(yNum, y1y2, x1x2);
                Fe25519::sub(yDen, one, dxxyy);

                Fe25519 xDenInv, yDenInv;
                Fe25519::invert(xDenInv, xDen);
                Fe25519::invert(yDenInv, yDen);

                EdPoint out;
                Fe25519::mul(out.x, xNum, xDenInv);
                Fe25519::mul(out.y, yNum, yDenInv);
                return out;
            }

            static EdPoint scalarMul(const EdPoint& pt, const CBigNum& k) {
                return toAffine(scalarMulProj(toProjective(pt), k));
            }

            /* Fixed-base scalar multiplication of the base point B by k: a left-to-right windowed
             * method over baseTable() above, for signing's/verification's B*r, B*s terms (a
             * fixed, public point repeatedly multiplied by a fresh scalar) -- unlike the general
             * scalarMul() above (built for an arbitrary point, via a branch-free ladder), this
             * amortizes B's table across every call instead of rebuilding per-call state, and
             * still runs every window's addition unconditionally (table[0] is the identity, so an
             * all-zero window still costs an addition, just of the identity) rather than
             * branching on whether the window is zero -- the same "always do the expensive step"
             * shape the branch-free ladder uses, just replacing "conditionally add B" with
             * "always add a table-selected multiple of B". Uses the fast EdPointProj arithmetic
             * internally, converting to affine only once at the end. */
            static EdPoint scalarMulBase(const CBigNum& k) {
                const TArray<EdPoint>& table = baseTable();

                EdPointProj result = identityPointProj();

                for (size_t w = SCALAR_BITS / BASE_TABLE_WINDOW; w-- > 0; ) {
                    for (size_t i = 0; i < BASE_TABLE_WINDOW; ++i) {
                        result = pointAddProj(result, result);
                    }

                    size_t base = w * BASE_TABLE_WINDOW;
                    size_t windowValue = 0;
                    for (size_t b = 0; b < BASE_TABLE_WINDOW; ++b) {
                        if (k.testBit(base + b)) {
                            windowValue |= (size_t(1) << b);
                        }
                    }

                    result = pointAddProj(result, toProjective(table[windowValue]));
                }

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
             * already guarantees this by construction, but the check is cheap and explicit). */
            static bool decodePoint(SReadOnlyByteSpan bytes32, EdPoint& out) {
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
                // low-order point instead of a raw zero. Both checks already existed in
                // checkPrivateKey() for self-generated keys (see its own identical pair, #1 and
                // #4); this extends them to every decoded point (both an imported public key via
                // createPublicKey(), and the signature's own R component in verify()).
                if (isIdentity(candidate)) {
                    return false; // the identity has order 1, which trivially "divides" L too --
                                   // the subgroup check below can't tell it apart from a real point.
                }

                // A legitimate point's order always divides L (it's s*B for some scalar s, and B
                // has order exactly L), so L*point == identity for a legitimate point;
                // edwards25519's cofactor is 8 and gcd(8, L) == 1, so for a genuine low-order
                // point of order h' | 8 (h' > 1), L mod h' is invertible and L*point != identity.
                if (!isIdentity(scalarMul(candidate, groupOrder()))) {
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
            uint8_t _encoded[32];

        public:
            EdPublicKey(EdPoint point, const uint8_t encoded[32]) : _point(std::move(point)) {
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
            const uint8_t* encoded() const { return _encoded; }
        };

        class EdPrivateKey : public IPrivateKey {
        private:
            uint8_t _seed[32];
            IPublicKeyPtr _publicKey;

        public:
            EdPrivateKey(const uint8_t seed[32], IPublicKeyPtr publicKey) : _publicKey(std::move(publicKey)) {
                algorithm(EASYM_ED25519);
                std::memcpy(_seed, seed, 32);
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

                CBigNum s;
                uint8_t prefix[32];
                Edwards25519::deriveFromSeed(priv->seed(), s, prefix);

                // --> EdDSA's per-signature nonce r is as sensitive as the key: the signature
                // publishes S = r + k*s mod L with k public, so anyone who learns r for one
                // signature recovers s. prefix and rHash are what determine r, so they count as
                // the same secret. Each of these is cleared at the point it stops being needed,
                // which leaves only one exit below where any of them is still live.
                uint8_t rHash[64];
                Edwards25519::sha512({ SReadOnlyByteSpan(prefix, 32), message }, rHash);
                CBigNum r = CBigNum::fromLittleEndian(SReadOnlyByteSpan(rHash, 64)).mod(L);

                CSecure::zero(SByteSpan(rHash, sizeof(rHash)));
                CSecure::zero(SByteSpan(prefix, sizeof(prefix)));

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
                if (!Edwards25519::decodePoint(rEncoded, rPoint)) {
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

                EdPoint lhs = Edwards25519::scalarMulBase(sBig);
                EdPoint rhs = Edwards25519::pointAdd(rPoint, Edwards25519::scalarMul(pub->point(), k));

                return (lhs.x.isEqual(rhs.x) && lhs.y.isEqual(rhs.y)) ? ERET_OK : ERET_BADREQ;
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

    ERetCode Ed25519::generateKeyPair(SKeySize keySize, SKeyPair& out) {
        out = SKeyPair();

        if (keySize != 256) {
            return ERET_KEY_SIZE;
        }

        uint8_t seed[32];
        if (CRng::fill(SByteSpan(seed, 32)) != ERET_OK) {
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
        EdPoint check = Edwards25519::scalarMul(q, Edwards25519::groupOrder());
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

    IPublicKeyPtr Ed25519::createPublicKey(const SReadOnlyByteSpan& keyData) const {
        if (keyData.size != 32) {
            return nullptr;
        }

        EdPoint point;
        if (!Edwards25519::decodePoint(keyData, point)) {
            return nullptr;
        }

        uint8_t encoded[32];
        std::memcpy(encoded, keyData.data, 32);

        return std::make_shared<EdPublicKey>(point, encoded);
    }

    IPrivateKeyPtr Ed25519::createPrivateKey(const SReadOnlyByteSpan& keyData) const {
        if (keyData.size != 32) {
            return nullptr;
        }

        uint8_t seed[32];
        std::memcpy(seed, keyData.data, 32);

        IPublicKeyPtr pub = publicKeyFromSeed(seed);
        if (!pub) {
            return nullptr;
        }

        return std::make_shared<EdPrivateKey>(seed, pub);
    }

    IAsymmetricContextPtr Ed25519::createContext() const {
        return std::make_shared<EdContext>();
    }

} // namespace crypto
} // namespace certpp
