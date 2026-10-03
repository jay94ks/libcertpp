#include <certpp/crypto/asyms/ed448.hpp>
#include <certpp/utils/secure.hpp>
#include <certpp/utils/bignum.hpp>
#include <certpp/utils/montgomery.hpp>
#include <certpp/crypto/rng.hpp>
#include <certpp/crypto/hashers/shake256.hpp>
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
            CBigNum x;
            CBigNum y;
        };

        /* An edwards448 point in extended projective coordinates (Hisil/Wong/Carter/Dawson,
         * "Twisted Edwards Curves Revisited", eprint 2008/522, the general a-parametrized
         * addition law -- edwards448 is untwisted, a = 1, unlike edwards25519's a = -1, so the
         * cheaper a = -1-specialized formula ed25519.cpp uses doesn't apply here). x = X/Z,
         * y = Y/Z, with the auxiliary T = X*Y/Z maintained alongside so pointAddProj() below
         * needs no inversion. Only scalarMul() uses this representation -- everywhere else in
         * this file still deals in affine EdPoint, converting at the boundary
         * (toProjective()/toAffine()).
         *
         * Its four coordinates are held in *Montgomery* form (see CMontgomery,
         * utils/montgomery.hpp), not as ordinary residues: that is what lets a scalar
         * multiplication's thousands of field multiplications run without a single big-number
         * division. toProjective()/toAffine() are the conversion boundary in both directions, so
         * nothing outside Edwards448's projective arithmetic ever sees a Montgomery-form value. */
        struct EdPointProj {
            CBigNum x, y, z, t;
        };

        /* Everything specific to implementing edwards448 (RFC 8032): field/group constants,
         * point arithmetic (affine and extended-projective), point encode/decode, and the
         * SHAKE256-based key-derivation RFC 8032 ties to this specific curve -- bundled into one
         * class rather than left as file-scope free functions, mirroring Edwards25519
         * (ed25519.cpp) and AesCore/DesCore/ChaCha20Core (crypto/syms/). */
        class Edwards448 {
        private:
            static constexpr size_t BASE_TABLE_WINDOW = 4;
            static constexpr size_t BASE_TABLE_SIZE = size_t(1) << BASE_TABLE_WINDOW; // 16

            /* The edwards448 curve equation's d = -39081 mod p (RFC 8032 5.2), derived from the
             * small integer rather than hardcoded as a 448-bit constant. */
            static const CBigNum& curveD() {
                static const CBigNum d = CBigNum(uint64_t(39081)).modNeg(fieldPrime());
                return d;
            }

            /* The field prime's Montgomery context (utils/montgomery.hpp) -- the extended
             * projective arithmetic below runs entirely in its domain, so a scalar multiplication
             * never performs a big-number division where CBigNum::mulMod() would perform one per
             * field multiply. Built once, on first use, like every other constant in this class:
             * the context is immutable and the modulus never changes. */
            static const CMontgomery& field() {
                static const CMontgomery f(fieldPrime());
                return f;
            }

            /* curveD() in Montgomery form, since pointAddProj() multiplies by it. */
            static const CBigNum& curveDMont() {
                static const CBigNum d = field().toMont(curveD());
                return d;
            }

            static EdPoint identityPoint() {
                return EdPoint{ CBigNum(), CBigNum(uint64_t(1)) };
            }

            static EdPointProj toProjective(const EdPoint& pt) {
                const CMontgomery& f = field();

                CBigNum x = f.toMont(pt.x);
                CBigNum y = f.toMont(pt.y);

                CBigNum t(x);
                f.mul(t, y);

                return EdPointProj{ std::move(x), std::move(y), f.one(), std::move(t) };
            }

            static EdPoint toAffine(const EdPointProj& pt) {
                const CMontgomery& f = field();

                // --> The modular inversion is the one step with no Montgomery form, so Z leaves
                // the domain, is inverted, and the inverse comes straight back in; the two affine
                // coordinates are then the only values converted back out.
                CBigNum zInv;
                CBigNum::modInverse(f.fromMont(pt.z), f.modulus(), zInv);
                zInv = f.toMont(zInv);

                CBigNum x(pt.x);
                f.mul(x, zInv);

                CBigNum y(pt.y);
                f.mul(y, zInv);

                return EdPoint{ f.fromMont(x), f.fromMont(y) };
            }

            static EdPointProj identityPointProj() {
                // --> (0 : 1 : 1 : 0), with the two ones in Montgomery form (see EdPointProj).
                const CMontgomery& f = field();
                return EdPointProj{ CBigNum(), f.one(), f.one(), CBigNum() };
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
             * instead of dividing it out immediately. A dedicated (cheaper) doubling formula
             * exists but isn't used here, for the same correctness/simplicity-over-performance
             * reason the rest of this module gives. */
            static EdPointProj pointAddProj(const EdPointProj& p1, const EdPointProj& p2) {
                const CMontgomery& f = field();
                const CBigNum& d = curveDMont();

                CBigNum A(p1.x);
                f.mul(A, p2.x);

                CBigNum B(p1.y);
                f.mul(B, p2.y);

                CBigNum C(p1.t);
                f.mul(C, p2.t);
                f.mul(C, d);

                CBigNum D(p1.z);
                f.mul(D, p2.z);

                CBigNum x1PlusY1(p1.x);
                f.add(x1PlusY1, p1.y);

                CBigNum x2PlusY2(p2.x);
                f.add(x2PlusY2, p2.y);

                CBigNum E(x1PlusY1);
                f.mul(E, x2PlusY2);
                f.sub(E, A);
                f.sub(E, B);

                CBigNum F(D);
                f.sub(F, C);

                CBigNum G(D);
                f.add(G, C);

                CBigNum H(B);
                f.sub(H, A); // a = 1: H = B - a*A = B - A

                CBigNum x3(E);
                f.mul(x3, F);

                CBigNum y3(G);
                f.mul(y3, H);

                CBigNum t3(E);
                f.mul(t3, H);

                CBigNum z3(F);
                f.mul(z3, G);

                return EdPointProj{ std::move(x3), std::move(y3), std::move(z3), std::move(t3) };
            }

            static void condSwapPointProj(bool doSwap, EdPointProj& a, EdPointProj& b) {
                CBigNum::condSwap(doSwap, a.x, b.x);
                CBigNum::condSwap(doSwap, a.y, b.y);
                CBigNum::condSwap(doSwap, a.z, b.z);
                CBigNum::condSwap(doSwap, a.t, b.t);
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
                    EdPointProj doubled = pointAddProj(r0, r0);
                    r1 = std::move(sum);
                    r0 = std::move(doubled);
                    condSwapPointProj(bit, r0, r1);
                }

                return r0;
            }

            /* Computes a square root of x2 mod p for p == 3 (mod 4) (the simple case: a single
             * candidate x2^((p+1)/4) always works when x2 is a quadratic residue, unlike
             * Ed25519's p == 5 (mod 8) case, which needs a second candidate). Returns false if x2
             * is not a quadratic residue mod p (i.e. the point being decoded is invalid). */
            static bool fieldSqrt(const CBigNum& x2, CBigNum& out) {
                const CBigNum& p = fieldPrime();

                CBigNum exp(p);
                exp.add(CBigNum(uint64_t(1)));
                exp.shr(2); // exact: p + 1 == 0 (mod 4)

                // --> ~446 squarings and ~223 multiplies, each of which CBigNum::modExp() would
                // follow with a long division; in the Montgomery domain none of them divides at
                // all. This runs once per decoded point, i.e. once per verify(), and was a
                // meaningful fraction of it.
                CBigNum candidate = field().modExp(x2, exp);

                CBigNum check(candidate);
                field().mulMod(check, candidate);

                CBigNum reducedX2(x2);
                reducedX2.mod(p);

                if (check != reducedX2) {
                    return false;
                }

                out = std::move(candidate);
                return true;
            }

            /* Recovers x from y and a desired sign (parity) bit, per RFC 8032 5.2.3: x^2 =
             * (y^2-1) / (d*y^2-1), then the root with the wrong parity is negated. Used both for
             * decoding a compressed point and for deriving the base point's x-coordinate from its
             * y. */
            static bool recoverX(const CBigNum& y, bool signBit, CBigNum& outX) {
                const CBigNum& p = fieldPrime();
                const CBigNum& d = curveD();

                CBigNum yy(y);
                yy.mulMod(y, p);

                CBigNum u(yy);
                u.modSub(CBigNum(uint64_t(1)), p);

                CBigNum v(d);
                v.mulMod(yy, p);
                v.modSub(CBigNum(uint64_t(1)), p);

                CBigNum vInv;
                if (!CBigNum::modInverse(v, p, vInv)) {
                    return false;
                }

                CBigNum x2(u);
                x2.mulMod(vInv, p);

                CBigNum x;
                if (!fieldSqrt(x2, x)) {
                    return false;
                }

                if (x.isZero() && signBit) {
                    return false; // RFC 8032 5.2.3: x == 0 must pair with a clear sign bit
                }

                if (x.testBit(0) != signBit) {
                    x.modNeg(p);
                }

                outX = std::move(x);
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
                    CBigNum x, y;
                    CBigNum::fromHex("4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E", x);
                    CBigNum::fromHex("693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14", y);
                    return EdPoint{ x, y };
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

            /* RFC 8032 5.2's dom4(F, C) prefix, fixed here at F = 0 (pure EdDSA, not "Ed448ph")
             * and an empty context C (context strings aren't supported): "SigEd448" || 0x00 ||
             * 0x00. */
            static void appendDom4(SHAKE256& hasher) {
                static const uint8_t DOM4[] = { 'S', 'i', 'g', 'E', 'd', '4', '4', '8', 0x00, 0x00 };
                hasher.push(SReadOnlyByteSpan(DOM4, sizeof(DOM4)));
            }

        public:
            /* The edwards448 field prime, 2^448 - 2^224 - 1 (RFC 8032 5.2 / RFC 7748) -- cheaper
             * and safer to derive than to transcribe as a 112-hex-digit literal. */
            static const CBigNum& fieldPrime() {
                static const CBigNum p = CBigNum(uint64_t(1)).shl(448)
                    .sub(CBigNum(uint64_t(1)).shl(224))
                    .sub(CBigNum(uint64_t(1)));
                return p;
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
                return pt.x.isZero() && pt.y == CBigNum(uint64_t(1));
            }

            /* Checks x^2 + y^2 == 1 + d*x^2*y^2 (mod p), i.e. edwards448's curve equation (RFC
             * 8032 5.2, a = 1). Assumes x, y are already field-reduced (0 <= x, y < p) --
             * callers check that separately. */
            static bool isOnCurve(const CBigNum& x, const CBigNum& y) {
                const CBigNum& p = fieldPrime();
                const CBigNum& d = curveD();

                CBigNum xx(x);
                xx.mulMod(x, p);

                CBigNum yy(y);
                yy.mulMod(y, p);

                CBigNum lhs(xx);
                lhs.add(yy);
                lhs.mod(p);

                CBigNum dxxyy(d);
                dxxyy.mulMod(xx, p);
                dxxyy.mulMod(yy, p);

                CBigNum rhs(uint64_t(1));
                rhs.add(dxxyy);
                rhs.mod(p);

                return lhs == rhs;
            }

            /* Untwisted Edwards addition (a = 1). Unconditionally complete (no exceptional input
             * pairs, including P + P) since d is not a square mod p for edwards448 -- unlike
             * short-Weierstrass addition, this same formula handles doubling. */
            static EdPoint pointAdd(const EdPoint& p1, const EdPoint& p2) {
                const CBigNum& p = fieldPrime();
                const CBigNum& d = curveD();

                CBigNum x1y2(p1.x);
                x1y2.mulMod(p2.y, p);

                CBigNum y1x2(p1.y);
                y1x2.mulMod(p2.x, p);

                CBigNum y1y2(p1.y);
                y1y2.mulMod(p2.y, p);

                CBigNum x1x2(p1.x);
                x1x2.mulMod(p2.x, p);

                CBigNum dxxyy(d);
                dxxyy.mulMod(x1x2, p);
                dxxyy.mulMod(y1y2, p);

                CBigNum xNum(x1y2);
                xNum.add(y1x2);
                xNum.mod(p);

                CBigNum xDen(uint64_t(1));
                xDen.add(dxxyy);
                xDen.mod(p);

                CBigNum yNum(y1y2);
                yNum.modSub(x1x2, p);

                CBigNum yDen(uint64_t(1));
                yDen.modSub(dxxyy, p);

                CBigNum xDenInv, yDenInv;
                CBigNum::modInverse(xDen, p, xDenInv);
                CBigNum::modInverse(yDen, p, yDenInv);

                xNum.mulMod(xDenInv, p);
                yNum.mulMod(yDenInv, p);

                return EdPoint{ std::move(xNum), std::move(yNum) };
            }

            static EdPoint scalarMul(const EdPoint& pt, const CBigNum& k) {
                return toAffine(scalarMulProj(toProjective(pt), k));
            }

            /* Fixed-base scalar multiplication of the base point B by k -- see ed25519.cpp's
             * identical scalarMulBase() for the full rationale (left-to-right windowed method
             * over baseTable() above, every window's addition run unconditionally). Uses the fast
             * EdPointProj arithmetic internally, converting to affine only once at the end. */
            static EdPoint scalarMulBase(const CBigNum& k) {
                const TArray<EdPoint>& table = baseTable();

                size_t bits = k.bitLength();
                size_t numWindows = (bits + BASE_TABLE_WINDOW - 1) / BASE_TABLE_WINDOW;

                EdPointProj result = identityPointProj();

                for (size_t w = numWindows; w-- > 0; ) {
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

            /* Encodes pt per RFC 8032 5.2.2: y as a 56-byte little-endian integer (edwards448's
             * 448-bit field fits exactly, unlike edwards25519's 255-bit field), followed by one
             * extra byte holding the sign (parity) of x in its top bit -- 57 bytes total. */
            static bool encodePoint(const EdPoint& pt, uint8_t out[57]) {
                if (!pt.y.toLittleEndian(SByteSpan(out, 56))) {
                    return false;
                }

                out[56] = pt.x.testBit(0) ? 0x80 : 0x00;
                return true;
            }

            /* Decodes a point per RFC 8032 5.2.3, validating it lies on the curve (recoverX()
             * already guarantees this by construction, but the check is cheap and explicit). */
            static bool decodePoint(SReadOnlyByteSpan bytes57, EdPoint& out) {
                if (bytes57.size != 57) {
                    return false;
                }

                uint8_t yBytes[56];
                std::memcpy(yBytes, bytes57.data, 56);

                bool signBit = (bytes57.data[56] & 0x80) != 0;
                if ((bytes57.data[56] & 0x7F) != 0) {
                    return false; // RFC 8032 5.2.3: every bit but the sign bit must be zero
                }

                CBigNum y = CBigNum::fromLittleEndian(SReadOnlyByteSpan(yBytes, 56));

                if (y >= fieldPrime()) {
                    return false;
                }

                CBigNum x;
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
                if (!isIdentity(scalarMul(candidate, groupOrder()))) {
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
            uint8_t _encoded[57];

        public:
            EdPublicKey(EdPoint point, const uint8_t encoded[57]) : _point(std::move(point)) {
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
            const uint8_t* encoded() const { return _encoded; }
        };

        class EdPrivateKey : public IPrivateKey {
        private:
            uint8_t _seed[57];
            IPublicKeyPtr _publicKey;

        public:
            EdPrivateKey(const uint8_t seed[57], IPublicKeyPtr publicKey) : _publicKey(std::move(publicKey)) {
                algorithm(EASYM_ED448);
                std::memcpy(_seed, seed, 57);
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

                CBigNum s;
                uint8_t prefix[57];
                Edwards448::deriveFromSeed(priv->seed(), s, prefix);

                // --> Same reasoning as Ed25519's sign(): the nonce r is as sensitive as the
                // key, because the signature publishes S = r + k*s mod L with k public. prefix
                // and rHash determine r, so they are the same secret. Each is cleared where it
                // stops being needed.
                uint8_t rHash[114];
                Edwards448::hashWithDom4({ SReadOnlyByteSpan(prefix, 57), message }, rHash);
                CBigNum r = CBigNum::fromLittleEndian(SReadOnlyByteSpan(rHash, 114)).mod(L);

                CSecure::zero(SByteSpan(rHash, sizeof(rHash)));
                CSecure::zero(SByteSpan(prefix, sizeof(prefix)));

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
                if (!Edwards448::decodePoint(rEncoded, rPoint)) {
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

                EdPoint lhs = Edwards448::scalarMulBase(sBig);
                EdPoint rhs = Edwards448::pointAdd(rPoint, Edwards448::scalarMul(pub->point(), k));

                return (lhs.x == rhs.x && lhs.y == rhs.y) ? ERET_OK : ERET_BADREQ;
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

    ERetCode Ed448::generateKeyPair(SKeySize keySize, SKeyPair& out) {
        out = SKeyPair();

        if (keySize != 456) {
            return ERET_KEY_SIZE;
        }

        uint8_t seed[57];
        if (CRng::fill(SByteSpan(seed, 57)) != ERET_OK) {
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
        const CBigNum& p = Edwards448::fieldPrime();

        // See Ed25519::checkPrivateKey()'s identical note on why there's no "s in [1, L-1]"
        // scalar-range check here -- RFC 8032 5.2.5's clamped scalar isn't meant to be < L.

        // 1. "Point at infinity" analogue: reject a derived public key equal to the identity.
        if (Edwards448::isIdentity(q)) {
            return ERET_KEY_PARAM;
        }

        // 2. Field range: 0 <= x, y < p.
        if (q.x >= p || q.y >= p) {
            return ERET_KEY_PARAM;
        }

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
        CBigNum s;
        uint8_t prefix[57];
        Edwards448::deriveFromSeed(priv->seed(), s, prefix);

        EdPoint expectedQ = Edwards448::scalarMulBase(s);
        if (expectedQ.x != q.x || expectedQ.y != q.y) {
            return ERET_KEY_ERROR;
        }

        return ERET_OK;
    }

    IPublicKeyPtr Ed448::createPublicKey(const SReadOnlyByteSpan& keyData) const {
        if (keyData.size != 57) {
            return nullptr;
        }

        EdPoint point;
        if (!Edwards448::decodePoint(keyData, point)) {
            return nullptr;
        }

        uint8_t encoded[57];
        std::memcpy(encoded, keyData.data, 57);

        return std::make_shared<EdPublicKey>(point, encoded);
    }

    IPrivateKeyPtr Ed448::createPrivateKey(const SReadOnlyByteSpan& keyData) const {
        if (keyData.size != 57) {
            return nullptr;
        }

        uint8_t seed[57];
        std::memcpy(seed, keyData.data, 57);

        IPublicKeyPtr pub = publicKeyFromSeed(seed);
        if (!pub) {
            return nullptr;
        }

        return std::make_shared<EdPrivateKey>(seed, pub);
    }

    IAsymmetricContextPtr Ed448::createContext() const {
        return std::make_shared<EdContext>();
    }

} // namespace crypto
} // namespace certpp
