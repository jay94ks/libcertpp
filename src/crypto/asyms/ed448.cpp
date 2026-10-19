#include <certpp/crypto/asyms/ed448.hpp>
#include <certpp/utils/secure.hpp>
#include <certpp/utils/bignum.hpp>
#include <certpp/crypto/rng.hpp>
#include <certpp/crypto/hashers/shake256.hpp>
#include "fe448.hpp"
#include <array>
#include <cstring>
#include <memory>
#include <utility>

namespace certpp {
namespace crypto {

    namespace {

        /* A point on edwards448 (untwisted Edwards, a = 1), in affine coordinates. Unlike a
         * short-Weierstrass SEcPoint, there is no separate point at infinity -- the group
         * identity (0, 1) is an ordinary finite point. */
        struct EdPoint {
            Fe448 x;
            Fe448 y;
        };

        /* An edwards448 point in extended projective coordinates (Hisil/Wong/Carter/Dawson,
         * "Twisted Edwards Curves Revisited", eprint 2008/522, the general a-parametrized
         * addition law -- edwards448 is untwisted, a = 1, unlike edwards25519's a = -1, so the
         * cheaper a = -1-specialized formula ed25519.cpp uses doesn't apply here). x = X/Z,
         * y = Y/Z, with the auxiliary T = X*Y/Z maintained alongside so pointAddProj() below
         * needs no inversion. Scalar multiplication and precomputation use this representation;
         * public boundaries convert to and from affine EdPoint values.
         *
         * Its four coordinates are fixed-width Fe448 values. That keeps scalar multiplication's
         * thousands of field operations free of dynamic allocation and general big-number
         * division; toAffine() performs the one fixed-exponent inversion needed at the boundary. */
        struct EdPointProj {
            Fe448 x, y, z, t;
        };

        struct EdPointPrecomp {
            Fe448 x, y, xyD;
        };

        /* Everything specific to implementing edwards448 (RFC 8032): field/group constants,
         * point arithmetic (affine and extended-projective), point encode/decode, and the
         * SHAKE256-based key-derivation RFC 8032 ties to this specific curve -- bundled into one
         * class rather than left as file-scope free functions, mirroring Edwards25519
         * (ed25519.cpp) and AesCore/DesCore/ChaCha20Core (crypto/syms/). */
        class Edwards448 {
        public:
            static constexpr size_t COMB_WIDTH = 10;
            static constexpr size_t COMB_SPACING = 45;
            static constexpr size_t COMB_TABLE_SIZE = size_t(1) << COMB_WIDTH;
            using CombTable = std::array<EdPointPrecomp, COMB_TABLE_SIZE>;

        private:
            static constexpr size_t PUBLIC_WINDOW = 4;
            static constexpr size_t PUBLIC_TABLE_SIZE = size_t(1) << PUBLIC_WINDOW; // 16
            static constexpr size_t SCALAR_BITS = 448;

            /* The edwards448 curve equation's d = -39081 mod p (RFC 8032 5.2), derived from the
             * small integer rather than hardcoded as a 448-bit constant. */
            static const Fe448& curveD() {
                static const Fe448 d = [] {
                    Fe448 value, small;
                    value.setZero();
                    small.setZero();
                    small.limbs[0] = 39081;
                    Fe448::sub(value, value, small);
                    return value;
                }();
                return d;
            }

            static EdPointProj toProjective(const EdPoint& pt) {
                EdPointProj out;
                out.x = pt.x;
                out.y = pt.y;
                out.z.setOne();
                Fe448::mul(out.t, pt.x, pt.y);
                return out;
            }

            static EdPoint toAffine(const EdPointProj& pt) {
                Fe448 zInv, x, y;
                Fe448::invert(zInv, pt.z);
                Fe448::mul(x, pt.x, zInv);
                Fe448::mul(y, pt.y, zInv);
                return EdPoint{ x, y };
            }

            static EdPointProj identityPointProj() {
                EdPointProj identity;
                identity.x.setZero();
                identity.y.setOne();
                identity.z.setOne();
                identity.t.setZero();
                return identity;
            }

            /* Extended-coordinates unified addition for a = 1 (derived directly from the affine
             * addition law x3=(x1y2+y1x2)/(1+d*x1x2y1y2), y3=(y1y2-a*x1x2)/(1-d*x1x2y1y2):
             * writing both numerators/denominators over the common X/Y/Z/T substitution gives
             * Z3=(Z1Z2+d*T1T2)*(Z1Z2-d*T1T2), X3=(X1Y2+Y1X2)*(Z1Z2-d*T1T2),
             * Y3=(Y1Y2-a*X1X2)*(Z1Z2+d*T1T2), T3=(X1Y2+Y1X2)*(Y1Y2-a*X1X2) -- then the standard
             * (X1+Y1)*(X2+Y2)-X1X2-Y1Y2 trick replaces the two X1Y2/Y1X2 multiplies with one.
             * Like the affine pointAdd() below, this same formula also handles P1 + P1
             * (doubling): it's a direct coordinate transform of the same complete addition law,
             * just avoiding a modular inversion per call by carrying the common denominator in Z
             * instead of dividing it out immediately. pointDoubleProj() uses the cheaper
             * dedicated formula when both operands are the same point. */
            static EdPointProj pointAddProj(const EdPointProj& p1, const EdPointProj& p2) {
                Fe448 A, B, C, D, E, F, G, H, x1PlusY1, x2PlusY2;
                Fe448::mul(A, p1.x, p2.x);
                Fe448::mul(B, p1.y, p2.y);
                Fe448::mul(C, p1.t, p2.t);
                Fe448::mul(C, C, curveD());
                Fe448::mul(D, p1.z, p2.z);
                Fe448::add(x1PlusY1, p1.x, p1.y);
                Fe448::add(x2PlusY2, p2.x, p2.y);
                Fe448::mul(E, x1PlusY1, x2PlusY2);
                Fe448::sub(E, E, A);
                Fe448::sub(E, E, B);
                Fe448::sub(F, D, C);
                Fe448::add(G, D, C);
                Fe448::sub(H, B, A);

                EdPointProj out;
                Fe448::mul(out.x, E, F);
                Fe448::mul(out.y, G, H);
                Fe448::mul(out.t, E, H);
                Fe448::mul(out.z, F, G);
                return out;
            }

            static EdPointProj pointAddPrecomp(
                const EdPointProj& p1, const EdPointPrecomp& p2
            ) {
                Fe448 A, B, C, E, F, G, H, x1PlusY1, x2PlusY2;
                Fe448::mul(A, p1.x, p2.x);
                Fe448::mul(B, p1.y, p2.y);
                Fe448::mul(C, p1.t, p2.xyD);
                Fe448::add(x1PlusY1, p1.x, p1.y);
                Fe448::add(x2PlusY2, p2.x, p2.y);
                Fe448::mul(E, x1PlusY1, x2PlusY2);
                Fe448::sub(E, E, A);
                Fe448::sub(E, E, B);
                Fe448::sub(F, p1.z, C);
                Fe448::add(G, p1.z, C);
                Fe448::sub(H, B, A);

                EdPointProj out;
                Fe448::mul(out.x, E, F);
                Fe448::mul(out.y, G, H);
                Fe448::mul(out.t, E, H);
                Fe448::mul(out.z, F, G);
                return out;
            }

            static void negate(EdPointPrecomp& point) {
                Fe448::neg(point.x, point.x);
                Fe448::neg(point.xyD, point.xyD);
            }

            /* Extended-coordinate doubling for a = 1. The unified addition formula above is
             * complete and can double a point, but it spends ten field multiplications.
             * This general Edwards doubling formula needs four squares and four multiplies.
             * Fe448 currently uses the same primitive for a square and a multiply, so this
             * removes two field products from every scalar bit without changing coordinates or
             * introducing an exceptional case. */
            static EdPointProj pointDoubleProj(const EdPointProj& pt) {
                Fe448 A, B, C, E, F, G, H;
                Fe448::square(A, pt.x);
                Fe448::square(B, pt.y);
                Fe448::square(C, pt.z);
                Fe448::add(C, C, C);
                Fe448::add(E, pt.x, pt.y);
                Fe448::square(E, E);
                Fe448::sub(E, E, A);
                Fe448::sub(E, E, B);
                Fe448::add(G, A, B);
                Fe448::sub(F, G, C);
                Fe448::sub(H, A, B);

                EdPointProj out;
                Fe448::mul(out.x, E, F);
                Fe448::mul(out.y, G, H);
                Fe448::mul(out.t, E, H);
                Fe448::mul(out.z, F, G);
                return out;
            }

            static void condSwapPointProj(bool doSwap, EdPointProj& a, EdPointProj& b) {
                Fe448::conditionalSwap(doSwap, a.x, b.x);
                Fe448::conditionalSwap(doSwap, a.y, b.y);
                Fe448::conditionalSwap(doSwap, a.z, b.z);
                Fe448::conditionalSwap(doSwap, a.t, b.t);
            }

            /* Branch-free double-and-add over EdPointProj -- same R0/R1 ladder invariant as
             * CEcCurve::scalarMul() (crypto/eccurve.cpp), just entirely in extended projective
             * coordinates so the loop itself never pays for a modular inversion; toAffine() below
             * pays for exactly one, at the very end, replacing the one-inversion-per-step affine
             * version used to have. */
            static EdPointProj scalarMulProj(const EdPointProj& pt, const CBigNum& k) {
                EdPointProj r0 = identityPointProj();
                EdPointProj r1 = pt;

                for (size_t i = k.bitLength(); i-- > 0; ) {
                    bool bit = k.testBit(i);

                    condSwapPointProj(bit, r0, r1);
                    EdPointProj sum = pointAddProj(r0, r1);
                    EdPointProj doubled = pointDoubleProj(r0);
                    r1 = std::move(sum);
                    r0 = std::move(doubled);
                    condSwapPointProj(bit, r0, r1);
                }

                return r0;
            }

            /* Recovers x from y and a desired sign (parity) bit, per RFC 8032 5.2.3: x^2 =
             * (y^2-1) / (d*y^2-1), then the root with the wrong parity is negated. Used both for
             * decoding a compressed point and for deriving the base point's x-coordinate from its
             * y. */
            static bool recoverX(const Fe448& y, bool signBit, Fe448& outX) {
                Fe448 yy, one, u, v, x;
                one.setOne();
                Fe448::square(yy, y);
                Fe448::sub(u, yy, one);
                Fe448::mul(v, curveD(), yy);
                Fe448::sub(v, v, one);

                if (!Fe448::squareRootRatio(x, u, v)) {
                    return false;
                }

                if (x.isZero() && signBit) {
                    return false; // RFC 8032 5.2.3: x == 0 must pair with a clear sign bit
                }

                if (x.isOdd() != signBit) {
                    Fe448::neg(x, x);
                }

                outX = x;
                return true;
            }

            /* The edwards448 base point B (RFC 8032 5.2 / RFC 7748's "Curve448" generator).
             * Derived from the trusted RFC 8032 TEST 1 vector (see this file's test suite) rather
             * than transcribed directly: B = [s^-1 mod L] * A, where A is TEST 1's known-correct
             * public key point and s is the (independently, arithmetically derived) clamped
             * scalar from its known-correct secret key -- verified to have order exactly L, and
             * to regenerate that exact public key when re-multiplied by s. Both coordinates
             * hardcoded here match that derivation exactly. */
            static const EdPoint& basePoint() {
                static const EdPoint b = [] {
                    CBigNum xBig, yBig;
                    CBigNum::fromHex("4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E", xBig);
                    CBigNum::fromHex("693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14", yBig);
                    uint8_t xBytes[56], yBytes[56];
                    xBig.toLittleEndian(SByteSpan(xBytes, sizeof(xBytes)));
                    yBig.toLittleEndian(SByteSpan(yBytes, sizeof(yBytes)));
                    Fe448 x, y;
                    x.fromBytes(xBytes);
                    y.fromBytes(yBytes);
                    return EdPoint{ x, y };
                }();

                return b;
            }

            /* RFC 8032 5.2's dom4(F, C) prefix, fixed here at F = 0 (pure EdDSA, not "Ed448ph")
             * and an empty context C (context strings aren't supported): "SigEd448" || 0x00 ||
             * 0x00. */
            static void appendDom4(SHAKE256& hasher) {
                static const uint8_t DOM4[] = { 'S', 'i', 'g', 'E', 'd', '4', '4', '8', 0x00, 0x00 };
                hasher.push(SReadOnlyByteSpan(DOM4, sizeof(DOM4)));
            }

        public:
            static bool isEqual(const EdPointProj& lhs, const EdPoint& rhs) {
                Fe448 rhsX, rhsY;
                Fe448::mul(rhsX, rhs.x, lhs.z);
                Fe448::mul(rhsY, rhs.y, lhs.z);
                return lhs.x.isEqual(rhsX) && lhs.y.isEqual(rhsY);
            }

            /* The edwards448 base point's subgroup order L = 2^446 -
             * 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D (RFC 7748, which RFC
             * 8032 5.2 defers to; independently confirmed against a second, differently-formatted
             * source before hardcoding -- see this module's asyms/ siblings for why that
             * matters). */
            static const CBigNum& groupOrder() {
                static const CBigNum l = [] {
                    CBigNum addend;
                    CBigNum::fromHex("8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D", addend);
                    return CBigNum(uint64_t(1)).shl(446).sub(addend);
                }();
                return l;
            }

            static bool isIdentity(const EdPoint& pt) {
                Fe448 one;
                one.setOne();
                return pt.x.isZero() && pt.y.isEqual(one);
            }

            /* Checks x^2 + y^2 == 1 + d*x^2*y^2 (mod p), i.e. edwards448's curve equation (RFC
             * 8032 5.2, a = 1). Assumes x, y are already field-reduced (0 <= x, y < p) --
             * callers check that separately. */
            static bool isOnCurve(const Fe448& x, const Fe448& y) {
                Fe448 xx, yy, lhs, rhs, dxxyy, one;
                Fe448::square(xx, x);
                Fe448::square(yy, y);
                Fe448::add(lhs, xx, yy);
                Fe448::mul(dxxyy, curveD(), xx);
                Fe448::mul(dxxyy, dxxyy, yy);
                one.setOne();
                Fe448::add(rhs, one, dxxyy);
                return lhs.isEqual(rhs);
            }

            static EdPoint scalarMul(const EdPoint& pt, const CBigNum& k) {
                return toAffine(scalarMulProj(toProjective(pt), k));
            }

            /* Windowed multiplication for verification-time public scalars. Its table access and
             * zero-window branch depend on the scalar, so private scalars must continue to use
             * scalarMul(). The current callers pass the fixed public order L or the public
             * challenge hash k, reducing the arbitrary-point work from one addition per bit to
             * at most one addition per four bits. */
            static EdPoint scalarMulPublic(const EdPoint& pt, const CBigNum& k) {
                EdPointProj table[PUBLIC_TABLE_SIZE];
                table[0] = identityPointProj();
                table[1] = toProjective(pt);
                for (size_t i = 2; i < PUBLIC_TABLE_SIZE; ++i) {
                    table[i] = pointAddProj(table[i - 1], table[1]);
                }

                EdPointProj result = identityPointProj();
                for (size_t w = SCALAR_BITS / PUBLIC_WINDOW; w-- > 0; ) {
                    for (size_t i = 0; i < PUBLIC_WINDOW; ++i) {
                        result = pointDoubleProj(result);
                    }

                    const size_t base = w * PUBLIC_WINDOW;
                    size_t windowValue = 0;
                    for (size_t b = 0; b < PUBLIC_WINDOW; ++b) {
                        if (k.testBit(base + b)) {
                            windowValue |= size_t(1) << b;
                        }
                    }

                    if (windowValue != 0) {
                        result = pointAddProj(result, table[windowValue]);
                    }
                }

                return toAffine(result);
            }

            static size_t combIndex(const CBigNum& scalar, size_t row) {
                size_t index = 0;
                for (size_t column = 0; column < COMB_WIDTH; ++column) {
                    const size_t bit = row + column * COMB_SPACING;
                    if (bit < SCALAR_BITS && scalar.testBit(bit)) {
                        index |= size_t(1) << column;
                    }
                }
                return index;
            }

            /* Computes baseScalar*B - pointScalar*pt with two comb tables and one shared
             * doubling chain. Ed448 verification exposes both S and k, so table indices and
             * zero-entry branches do not handle secrets. */
            static EdPointProj doubleScalarMulPublic(
                const CBigNum& baseScalar, const CombTable& pointTable,
                const CBigNum& pointScalar
            ) {
                const CombTable& baseTable = baseCombTable();
                EdPointProj result = identityPointProj();
                for (size_t row = COMB_SPACING; row-- > 0; ) {
                    result = pointDoubleProj(result);
                    const size_t baseIndex = combIndex(baseScalar, row);
                    if (baseIndex != 0) {
                        result = pointAddPrecomp(result, baseTable[baseIndex]);
                    }
                    const size_t pointIndex = combIndex(pointScalar, row);
                    if (pointIndex != 0) {
                        EdPointPrecomp selected = pointTable[pointIndex];
                        negate(selected);
                        result = pointAddPrecomp(result, selected);
                    }
                }
                return result;
            }

            static CombTable makeCombTable(const EdPoint& point) {
                std::array<EdPointProj, COMB_WIDTH> teeth;
                teeth[0] = toProjective(point);
                for (size_t column = 1; column < COMB_WIDTH; ++column) {
                    teeth[column] = teeth[column - 1];
                    for (size_t i = 0; i < COMB_SPACING; ++i) {
                        teeth[column] = pointDoubleProj(teeth[column]);
                    }
                }

                auto projective =
                    std::make_unique<std::array<EdPointProj, COMB_TABLE_SIZE>>();
                (*projective)[0] = identityPointProj();
                for (size_t index = 1; index < COMB_TABLE_SIZE; ++index) {
                    size_t column = 0;
                    while ((index & (size_t(1) << column)) == 0) {
                        ++column;
                    }
                    const size_t previous = index & ~(size_t(1) << column);
                    (*projective)[index] = pointAddProj(
                        (*projective)[previous], teeth[column]);
                }

                auto prefixes = std::make_unique<std::array<Fe448, COMB_TABLE_SIZE>>();
                Fe448 product;
                product.setOne();
                for (size_t index = 0; index < COMB_TABLE_SIZE; ++index) {
                    (*prefixes)[index] = product;
                    Fe448::mul(product, product, (*projective)[index].z);
                }
                Fe448::invert(product, product);

                auto out = std::make_unique<CombTable>();
                for (size_t index = COMB_TABLE_SIZE; index-- > 0; ) {
                    const EdPointProj& source = (*projective)[index];
                    Fe448 zInverse;
                    Fe448::mul(zInverse, product, (*prefixes)[index]);
                    Fe448::mul(product, product, source.z);

                    EdPointPrecomp& target = (*out)[index];
                    Fe448::mul(target.x, source.x, zInverse);
                    Fe448::mul(target.y, source.y, zInverse);
                    Fe448::mul(target.xyD, target.x, target.y);
                    Fe448::mul(target.xyD, target.xyD, curveD());
                }
                return std::move(*out);
            }

            static const CombTable& baseCombTable() {
                static const CombTable table = makeCombTable(basePoint());
                return table;
            }

            /* Fixed-base comb multiplication of B by k. The 448 scalar bits are split into ten
             * columns spaced 45 bits apart, reducing the online work to 45 doublings and 45 mixed
             * additions. Table selection depends on k, so this path is not claimed constant-time. */
            static EdPoint scalarMulBase(const CBigNum& k) {
                const CombTable& table = baseCombTable();
                EdPointProj result = identityPointProj();
                for (size_t row = COMB_SPACING; row-- > 0; ) {
                    result = pointDoubleProj(result);
                    result = pointAddPrecomp(result, table[combIndex(k, row)]);
                }
                return toAffine(result);
            }

            /* Encodes pt per RFC 8032 5.2.2: y as a 56-byte little-endian integer (edwards448's
             * 448-bit field fits exactly, unlike edwards25519's 255-bit field), followed by one
             * extra byte holding the sign (parity) of x in its top bit -- 57 bytes total. */
            static bool encodePoint(const EdPoint& pt, uint8_t out[57]) {
                pt.y.toBytes(out);
                out[56] = pt.x.isOdd() ? 0x80 : 0x00;
                return true;
            }

            /* Decodes a point per RFC 8032 5.2.3, validating it lies on the curve (recoverX()
             * already guarantees this by construction, but the check is cheap and explicit). */
            static bool decodePoint(
                SReadOnlyByteSpan bytes57, EdPoint& out, bool requireMainSubgroup = true
            ) {
                if (bytes57.size != 57) {
                    return false;
                }

                uint8_t yBytes[56];
                std::memcpy(yBytes, bytes57.data, 56);

                bool signBit = (bytes57.data[56] & 0x80) != 0;
                if ((bytes57.data[56] & 0x7F) != 0) {
                    return false; // RFC 8032 5.2.3: every bit but the sign bit must be zero
                }

                Fe448 y;
                if (!y.fromBytes(yBytes)) {
                    return false;
                }

                Fe448 x;
                if (!recoverX(y, signBit, x)) {
                    return false;
                }

                EdPoint candidate{ x, y };

                // --> Reject the identity and every other low-order (order dividing the curve's
                // cofactor, 4) point -- see ed25519.cpp's decodePoint()'s identical pair of
                // checks for the full reasoning (edwards448's cofactor is 4 instead of 8, but
                // gcd(4, L) == 1 just the same, so the argument carries over unchanged: without
                // this, a public key encoding the identity plus a signature of R == identity/S
                // == 0 verifies against any message). The identity has order 1, which trivially
                // "divides" L too, so it needs its own explicit check -- the subgroup check alone
                // can't tell it apart from a genuine point.
                if (isIdentity(candidate)) {
                    return false;
                }
                if (requireMainSubgroup && !isIdentity(scalarMulPublic(candidate, groupOrder()))) {
                    return false;
                }

                out = candidate;
                return true;
            }

            /* Computes SHAKE256(dom4 || parts[0] || parts[1] || ..., 114). */
            static void hashWithDom4(std::initializer_list<SReadOnlyByteSpan> parts, uint8_t out[114]) {
                SHAKE256 hasher(114);
                appendDom4(hasher);
                for (const SReadOnlyByteSpan& part : parts) {
                    hasher.push(part);
                }

                SByteSpan outSpan(out, 114);
                hasher.finish(outSpan);
            }

            /* Derives the clamped scalar s and signing prefix from a 57-byte seed, per RFC 8032
             * 5.2.5's key generation steps 1-2. */
            static void deriveFromSeed(const uint8_t seed[57], CBigNum& outScalar, uint8_t outPrefix[57]) {
                SHAKE256 hasher(114);
                hasher.push(SReadOnlyByteSpan(seed, 57));

                uint8_t h[114];
                SByteSpan hSpan(h, 114);
                hasher.finish(hSpan);

                uint8_t sBytes[57];
                std::memcpy(sBytes, h, 57);
                sBytes[0] &= 0xFC;
                sBytes[55] |= 0x80;
                sBytes[56] = 0x00;

                outScalar = CBigNum::fromLittleEndian(SReadOnlyByteSpan(sBytes, 57));

                std::memcpy(outPrefix, h + 57, 57);

                // h is the whole expanded private key -- the scalar in its first half and the
                // signing prefix in its second -- and sBytes is the scalar itself. Both have been
                // copied where they are needed; neither belongs in this frame afterwards.
                CSecure::zero(SByteSpan(h, sizeof(h)));
                CSecure::zero(SByteSpan(sBytes, sizeof(sBytes)));
            }
        };

        class EdPublicKey : public IPublicKey {
        private:
            EdPoint _point;
            Edwards448::CombTable _combTable;
            uint8_t _encoded[57];

        public:
            EdPublicKey(EdPoint point, const uint8_t encoded[57])
                : _point(std::move(point)),
                  _combTable(Edwards448::makeCombTable(_point)) {
                algorithm(EASYM_ED448);
                std::memcpy(_encoded, encoded, 57);
            }

            SKeySize keySize() const override {
                return 456;
            }

            ERetCode serialize(COctet& out) const override {
                out = COctet(_encoded, 57);
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

                return int32_t(std::memcmp(_encoded, o->_encoded, 57));
            }

            const EdPoint& point() const { return _point; }
            const Edwards448::CombTable& combTable() const { return _combTable; }
            const uint8_t* encoded() const { return _encoded; }
        };

        class EdPrivateKey : public IPrivateKey {
        private:
            uint8_t _seed[57];
            CBigNum _scalar;
            uint8_t _prefix[57];
            IPublicKeyPtr _publicKey;

        public:
            EdPrivateKey(const uint8_t seed[57], IPublicKeyPtr publicKey) : _publicKey(std::move(publicKey)) {
                algorithm(EASYM_ED448);
                std::memcpy(_seed, seed, 57);
                Edwards448::deriveFromSeed(seed, _scalar, _prefix);
            }

            ~EdPrivateKey() override {
                CSecure::zero(SByteSpan(_seed, sizeof(_seed)));
                _scalar.secureClear();
                CSecure::zero(SByteSpan(_prefix, sizeof(_prefix)));
            }

            SKeySize keySize() const override {
                return 456;
            }

            ERetCode serialize(COctet& out) const override {
                out = COctet(_seed, 57);
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

                return int32_t(std::memcmp(_seed, o->_seed, 57));
            }

            IPublicKeyPtr publicKey() const override {
                return _publicKey;
            }

            const uint8_t* seed() const { return _seed; }
            const CBigNum& scalar() const { return _scalar; }
            const uint8_t* prefix() const { return _prefix; }
        };

    } // namespace

    /* Builds the matching public key for a 57-byte seed (shared by generateKeyPair() and
     * createPrivateKey(), which both need to derive A from d/s). */
    IPublicKeyPtr Ed448::publicKeyFromSeed(const uint8_t seed[57]) {
        CBigNum s;
        uint8_t prefix[57];
        Edwards448::deriveFromSeed(seed, s, prefix);

        EdPoint a = Edwards448::scalarMulBase(s);

        uint8_t aEncoded[57];
        if (!Edwards448::encodePoint(a, aEncoded)) {
            return nullptr;
        }

        return std::make_shared<EdPublicKey>(a, aEncoded);
    }

    namespace {

        class EdContext : public IAsymmetricContext {
        public:
            using IAsymmetricContext::IAsymmetricContext;

        protected:
            void onReset() override {
                if (privateKey() || publicKey()) {
                    sizeOfSign(114);
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

                if (out.size < 114) {
                    return ERET_NOSPC;
                }

                const CBigNum& L = Edwards448::groupOrder();

                CBigNum s(priv->scalar());

                // --> Same reasoning as Ed25519's sign(): the nonce r is as sensitive as the
                // key, because the signature publishes S = r + k*s mod L with k public. prefix
                // and rHash determine r, so they are the same secret. Each is cleared where it
                // stops being needed.
                uint8_t rHash[114];
                Edwards448::hashWithDom4({ SReadOnlyByteSpan(priv->prefix(), 57), message }, rHash);
                CBigNum r = CBigNum::fromLittleEndian(SReadOnlyByteSpan(rHash, 114)).mod(L);

                CSecure::zero(SByteSpan(rHash, sizeof(rHash)));

                EdPoint rPoint = Edwards448::scalarMulBase(r);
                uint8_t rEncoded[57];
                if (!Edwards448::encodePoint(rPoint, rEncoded)) {
                    s.secureClear();
                    r.secureClear();
                    return ERET_UNKNOWN;
                }

                uint8_t kHash[114];
                Edwards448::hashWithDom4({ SReadOnlyByteSpan(rEncoded, 57), SReadOnlyByteSpan(pub->encoded(), 57), message }, kHash);
                CBigNum k = CBigNum::fromLittleEndian(SReadOnlyByteSpan(kHash, 114)).mod(L);

                // k is a hash of public values, but k*s is not -- k being public, k*s hands over
                // s. It holds that product until it is consumed just below.
                k.mulMod(s, L);
                s.secureClear();

                r.add(k);
                r.mod(L);
                k.secureClear();

                // r now holds the signature's own S, which is published.
                CBigNum sBig = std::move(r);

                uint8_t sEncoded[57];
                if (!sBig.toLittleEndian(SByteSpan(sEncoded, 57))) {
                    return ERET_UNKNOWN;
                }

                std::memcpy(out.data, rEncoded, 57);
                std::memcpy(out.data + 57, sEncoded, 57);
                out = SByteSpan(out.data, 114);

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

                if (signature.size != 114) {
                    return ERET_BADREQ;
                }

                SReadOnlyByteSpan rEncoded = signature.slice(0, 57);
                SReadOnlyByteSpan sEncoded = signature.slice(57, 57);

                EdPoint rPoint;
                /* The imported public key A is in the main subgroup, and generated keys are
                 * scalar multiples of B. The exact, uncofactored equation below therefore
                 * implies that every accepted R equals S*B-k*A and lies in that subgroup too.
                 * Keep canonical decoding, curve recovery and identity rejection, while avoiding
                 * the redundant L*R multiplication on every verification. */
                if (!Edwards448::decodePoint(rEncoded, rPoint, false)) {
                    return ERET_BADREQ;
                }

                const CBigNum& L = Edwards448::groupOrder();
                CBigNum sBig = CBigNum::fromLittleEndian(sEncoded);
                if (sBig >= L) {
                    return ERET_BADREQ;
                }

                uint8_t kHash[114];
                Edwards448::hashWithDom4({ rEncoded, SReadOnlyByteSpan(pub->encoded(), 57), message }, kHash);
                CBigNum k = CBigNum::fromLittleEndian(SReadOnlyByteSpan(kHash, 114)).mod(L);

                EdPointProj expectedR = Edwards448::doubleScalarMulPublic(
                    sBig, pub->combTable(), k);

                return Edwards448::isEqual(expectedR, rPoint) ? ERET_OK : ERET_BADREQ;
            }

            ERetCode createEncrypter(IAsymmetricTransformerPtr&) override {
                return ERET_NOTSUP;
            }

            ERetCode createDecrypter(IAsymmetricTransformerPtr&) override {
                return ERET_NOTSUP;
            }
        };

    } // namespace

    Ed448::Ed448() {
        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(456));
        keySizes(specs);
    }

    ERetCode Ed448::generateKeyPair(const IRng& rng, SKeySize keySize, SKeyPair& out) {
        out = SKeyPair();

        if (keySize != 456) {
            return ERET_KEY_SIZE;
        }

        uint8_t seed[57];
        if (rng.fillTo(SByteSpan(seed, 57)) != ERET_OK) {
            return ERET_UNKNOWN;
        }

        IPublicKeyPtr pub = publicKeyFromSeed(seed);
        if (!pub) {
            return ERET_UNKNOWN;
        }

        auto priv = CSecure::make<EdPrivateKey>(seed, pub);
        if (!priv) {
            return ERET_NOMEM;
        }

        if (checkPrivateKey(priv) != ERET_OK) {
            return ERET_AGAIN;
        }

        out = SKeyPair(pub, priv);
        return ERET_OK;
    }

    ERetCode Ed448::checkPrivateKey(const IPrivateKeyPtr& key) const {
        auto priv = std::dynamic_pointer_cast<EdPrivateKey>(key);
        if (!priv) {
            return ERET_KEY_FORMAT;
        }

        auto pub = std::dynamic_pointer_cast<EdPublicKey>(priv->publicKey());
        if (!pub) {
            return ERET_KEY_ERROR;
        }

        const EdPoint& q = pub->point();

        // See Ed25519::checkPrivateKey()'s identical note on why there's no "s in [1, L-1]"
        // scalar-range check here -- RFC 8032 5.2.5's clamped scalar isn't meant to be < L.

        // 1. "Point at infinity" analogue: reject a derived public key equal to the identity.
        if (Edwards448::isIdentity(q)) {
            return ERET_KEY_PARAM;
        }

        // 2. Field range is an invariant of Fe448. Non-canonical encodings are rejected before
        // an EdPoint can be constructed.

        // 3. Curve equation.
        if (!Edwards448::isOnCurve(q.x, q.y)) {
            return ERET_KEY_PARAM;
        }

        // 4. Correct (order-L) subgroup: L*Q must be the identity.
        EdPoint check = Edwards448::scalarMul(q, Edwards448::groupOrder());
        if (!Edwards448::isIdentity(check)) {
            return ERET_KEY_PARAM;
        }

        // 5. Q must actually be s*B (s the seed's derived scalar) -- the checks above only
        // establish that Q is *some* legitimate point in the right subgroup, not that it's
        // *this key's* point; without this, a seed could be paired with an unrelated (but
        // otherwise well-formed) public point and still pass every check above.
        EdPoint expectedQ = Edwards448::scalarMulBase(priv->scalar());
        if (!expectedQ.x.isEqual(q.x) || !expectedQ.y.isEqual(q.y)) {
            return ERET_KEY_ERROR;
        }

        return ERET_OK;
    }

    ERetCode Ed448::createPublicKey(
        IPublicKeyPtr& out, const SReadOnlyByteSpan& keyData
    ) const {
        out.reset();
        if (keyData.size != 57) {
            return ERET_KEY_SIZE;
        }

        EdPoint point;
        if (!Edwards448::decodePoint(keyData, point)) {
            return ERET_KEY_FORMAT;
        }

        uint8_t encoded[57];
        std::memcpy(encoded, keyData.data, 57);

        try {
            out = std::make_shared<EdPublicKey>(point, encoded);
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        return ERET_OK;
    }

    ERetCode Ed448::createPrivateKey(
        IPrivateKeyPtr& out, const SReadOnlyByteSpan& keyData
    ) const {
        out.reset();
        if (keyData.size != 57) {
            return ERET_KEY_SIZE;
        }

        uint8_t seed[57];
        std::memcpy(seed, keyData.data, 57);

        try {
            IPublicKeyPtr pub = publicKeyFromSeed(seed);
            if (!pub) return ERET_KEY_ERROR;
            out = CSecure::make<EdPrivateKey>(seed, pub);
            if (!out) return ERET_NOMEM;
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        return ERET_OK;
    }

    ERetCode Ed448::createContext(
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
