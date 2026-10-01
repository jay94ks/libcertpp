#include <certpp/crypto/asyms/ed25519.hpp>
#include <certpp/utils/bignum.hpp>
#include <certpp/crypto/rng.hpp>
#include <certpp/crypto/hashers/sha512.hpp>
#include <cstring>
#include <memory>
#include <utility>

namespace certpp {
namespace crypto {

    namespace {

        /* A point on edwards25519 (or any twisted Edwards curve with a = -1), in affine
         * coordinates. Unlike a short-Weierstrass SEcPoint, there is no separate point at
         * infinity -- the group identity (0, 1) is an ordinary finite point. */
        struct EdPoint {
            CBigNum x;
            CBigNum y;
        };

        /* An edwards25519 point in extended projective coordinates (Hisil/Wong/Carter/Dawson,
         * "Twisted Edwards Curves Revisited", eprint 2008/522): x = X/Z, y = Y/Z, with the
         * auxiliary T = X*Y/Z maintained alongside so pointAddProj() below needs no inversion.
         * Only scalarMul() uses this representation -- everywhere else in this file still deals
         * in affine EdPoint, converting at the boundary (toProjective()/toAffine()). */
        struct EdPointProj {
            CBigNum x, y, z, t;
        };

        /* Everything specific to implementing edwards25519 (RFC 8032): field/group constants,
         * point arithmetic (affine and extended-projective), point encode/decode, and the
         * SHA-512-based key-derivation RFC 8032 ties to this specific curve -- bundled into one
         * class rather than left as file-scope free functions, mirroring how AesCore/DesCore/
         * ChaCha20Core (crypto/syms/) each own everything their algorithm needs. */
        class Edwards25519 {
        private:
            static constexpr size_t BASE_TABLE_WINDOW = 4;
            static constexpr size_t BASE_TABLE_SIZE = size_t(1) << BASE_TABLE_WINDOW; // 16

            /* The edwards25519 curve equation's d = -121665/121666 mod p (RFC 8032 5.1), derived
             * from the two small integers rather than hardcoded as a 255-bit constant. */
            static const CBigNum& curveD() {
                static const CBigNum d = [] {
                    const CBigNum& p = fieldPrime();
                    CBigNum inv121666;
                    CBigNum::modInverse(CBigNum(uint64_t(121666)), p, inv121666);
                    return CBigNum(uint64_t(121665)).mulMod(inv121666, p).modNeg(p);
                }();

                return d;
            }

            static EdPoint identityPoint() {
                return EdPoint{ CBigNum(), CBigNum(uint64_t(1)) };
            }

            static EdPointProj toProjective(const EdPoint& pt) {
                CBigNum t(pt.x);
                t.mulMod(pt.y, fieldPrime());
                return EdPointProj{ pt.x, pt.y, CBigNum(uint64_t(1)), std::move(t) };
            }

            static EdPoint toAffine(const EdPointProj& pt) {
                const CBigNum& p = fieldPrime();

                CBigNum zInv;
                CBigNum::modInverse(pt.z, p, zInv);

                CBigNum x(pt.x);
                x.mulMod(zInv, p);

                CBigNum y(pt.y);
                y.mulMod(zInv, p);

                return EdPoint{ std::move(x), std::move(y) };
            }

            static EdPointProj identityPointProj() {
                return EdPointProj{ CBigNum(), CBigNum(uint64_t(1)), CBigNum(uint64_t(1)), CBigNum() };
            }

            /* 2*d, precomputed once for pointAddProj()'s "C" term (RFC 8032 5.1's d, see
             * curveD()). */
            static const CBigNum& twoCurveD() {
                static const CBigNum v = [] {
                    CBigNum d2(curveD());
                    d2.add(d2);
                    d2.mod(fieldPrime());
                    return d2;
                }();

                return v;
            }

            /* Extended-coordinates unified addition ("add-2008-hwcd-3"): like the affine
             * pointAdd() below, this same formula handles P1 + P1 (doubling) too -- it's a direct
             * coordinate transform of the same complete twisted Edwards addition law, just
             * avoiding a modular inversion per call by carrying the common denominator in Z
             * instead of dividing it out immediately. A dedicated (cheaper) doubling formula
             * exists but isn't used here, for the same correctness/simplicity-over-performance
             * reason the rest of this module gives. */
            static EdPointProj pointAddProj(const EdPointProj& p1, const EdPointProj& p2) {
                const CBigNum& p = fieldPrime();
                const CBigNum& d2 = twoCurveD();

                CBigNum y1MinusX1(p1.y);
                y1MinusX1.modSub(p1.x, p);

                CBigNum y2MinusX2(p2.y);
                y2MinusX2.modSub(p2.x, p);

                CBigNum A(y1MinusX1);
                A.mulMod(y2MinusX2, p);

                CBigNum y1PlusX1(p1.y);
                y1PlusX1.add(p1.x);
                y1PlusX1.mod(p);

                CBigNum y2PlusX2(p2.y);
                y2PlusX2.add(p2.x);
                y2PlusX2.mod(p);

                CBigNum B(y1PlusX1);
                B.mulMod(y2PlusX2, p);

                CBigNum C(p1.t);
                C.mulMod(p2.t, p);
                C.mulMod(d2, p);

                CBigNum D(p1.z);
                D.mulMod(p2.z, p);
                D.add(D);
                D.mod(p);

                CBigNum E(B);
                E.modSub(A, p);

                CBigNum F(D);
                F.modSub(C, p);

                CBigNum G(D);
                G.add(C);
                G.mod(p);

                CBigNum H(B);
                H.add(A);
                H.mod(p);

                CBigNum x3(E);
                x3.mulMod(F, p);

                CBigNum y3(G);
                y3.mulMod(H, p);

                CBigNum t3(E);
                t3.mulMod(H, p);

                CBigNum z3(F);
                z3.mulMod(G, p);

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

            /* Computes a square root of x2 mod p for p == 5 (mod 8) (RFC 8032 5.1.3's algorithm,
             * restated in the equivalent "candidate = x2^((p+3)/8)" form so it only needs one
             * modular inverse, already paid for by the caller computing x2 itself). Returns false
             * if x2 is not a quadratic residue mod p (i.e. the point being decoded is invalid). */
            static bool fieldSqrt(const CBigNum& x2, CBigNum& out) {
                const CBigNum& p = fieldPrime();

                CBigNum exp(p);
                exp.add(CBigNum(uint64_t(3)));
                exp.shr(3); // exact: p + 3 == 0 (mod 8)

                CBigNum r = CBigNum::modExp(x2, exp, p);

                CBigNum r2(r);
                r2.mulMod(r, p);

                CBigNum reducedX2(x2);
                reducedX2.mod(p);

                if (r2 == reducedX2) {
                    out = r;
                    return true;
                }

                reducedX2.modNeg(p);
                if (r2 == reducedX2) {
                    CBigNum exp2(p);
                    exp2.sub(CBigNum(uint64_t(1)));
                    exp2.shr(2);

                    CBigNum sqrtM1 = CBigNum::modExp(CBigNum(uint64_t(2)), exp2, p);
                    r.mulMod(sqrtM1, p);
                    out = std::move(r);
                    return true;
                }

                return false;
            }

            /* Recovers x from y and a desired sign (parity) bit, per RFC 8032 5.1.3: x^2 =
             * (y^2-1) / (d*y^2+1), then the root with the wrong parity is negated. Used both for
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
                v.add(CBigNum(uint64_t(1)));
                v.mod(p);

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
                    return false; // RFC 8032 5.1.3: x == 0 must pair with a clear sign bit
                }

                if (x.testBit(0) != signBit) {
                    x.modNeg(p);
                }

                outX = std::move(x);
                return true;
            }

            /* The edwards25519 base point B, derived from By = 4/5 (mod p) (RFC 8032 5.1) rather
             * than hardcoded, avoiding a second 255-bit constant to transcribe -- recoverX()
             * (needed anyway for point decoding) does the rest. RFC 8032 encodes B with a clear
             * sign bit. */
            static const EdPoint& basePoint() {
                static const EdPoint b = [] {
                    const CBigNum& p = fieldPrime();

                    CBigNum inv5;
                    CBigNum::modInverse(CBigNum(uint64_t(5)), p, inv5);
                    CBigNum by = CBigNum(uint64_t(4)).mulMod(inv5, p);

                    CBigNum bx;
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
            /* The edwards25519 field prime, 2^255 - 19 (RFC 8032 5.1) -- cheaper and safer to
             * derive than to transcribe as a 64-hex-digit literal. */
            static const CBigNum& fieldPrime() {
                static const CBigNum p = CBigNum(uint64_t(1)).shl(255).sub(CBigNum(uint64_t(19)));
                return p;
            }

            /* The edwards25519 base point's subgroup order L = 2^252 +
             * 0x14DEF9DEA2F79CD65812631A5CF5D3ED (RFC 8032 5.1; independently confirmed against a
             * second source before hardcoding -- see this module's asyms/ siblings for why that
             * matters). The addend has no simpler closed form, unlike the field prime above. */
            static const CBigNum& groupOrder() {
                static const CBigNum l = [] {
                    CBigNum addend;
                    CBigNum::fromHex("14DEF9DEA2F79CD65812631A5CF5D3ED", addend);
                    return CBigNum(uint64_t(1)).shl(252).add(addend);
                }();
                return l;
            }

            static bool isIdentity(const EdPoint& pt) {
                return pt.x.isZero() && pt.y == CBigNum(uint64_t(1));
            }

            /* Checks -x^2 + y^2 == 1 + d*x^2*y^2 (mod p), i.e. edwards25519's curve equation
             * (RFC 8032 5.1), restated as y^2 == 1 + x^2 + d*x^2*y^2 to avoid a modNeg(). Assumes
             * x, y are already field-reduced (0 <= x, y < p) -- callers check that separately. */
            static bool isOnCurve(const CBigNum& x, const CBigNum& y) {
                const CBigNum& p = fieldPrime();
                const CBigNum& d = curveD();

                CBigNum lhs(y);
                lhs.mulMod(y, p);

                CBigNum xx(x);
                xx.mulMod(x, p);

                CBigNum yy(y);
                yy.mulMod(y, p);

                CBigNum dxxyy(d);
                dxxyy.mulMod(xx, p);
                dxxyy.mulMod(yy, p);

                CBigNum rhs(uint64_t(1));
                rhs.add(xx);
                rhs.add(dxxyy);
                rhs.mod(p);

                return lhs == rhs;
            }

            /* Twisted Edwards addition (a = -1). Unconditionally complete (no exceptional input
             * pairs, including P + P) since d is not a square mod p for edwards25519 -- unlike
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
                yNum.add(x1x2);
                yNum.mod(p);

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

            /* Encodes pt per RFC 8032 5.1.2: y as a 32-byte little-endian integer, with the sign
             * (parity) of x placed in the top bit of the last byte. */
            static bool encodePoint(const EdPoint& pt, uint8_t out[32]) {
                if (!pt.y.toLittleEndian(SByteSpan(out, 32))) {
                    return false;
                }

                if (pt.x.testBit(0)) {
                    out[31] |= 0x80;
                }

                return true;
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

                CBigNum y = CBigNum::fromLittleEndian(SReadOnlyByteSpan(yBytes, 32));

                if (y >= fieldPrime()) {
                    return false;
                }

                CBigNum x;
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
             * 5.1.5's key generation steps 1-2. */
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
        if (!Edwards25519::encodePoint(a, aEncoded)) {
            return nullptr;
        }

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

                const CBigNum& L = Edwards25519::groupOrder();

                CBigNum s;
                uint8_t prefix[32];
                Edwards25519::deriveFromSeed(priv->seed(), s, prefix);

                uint8_t rHash[64];
                Edwards25519::sha512({ SReadOnlyByteSpan(prefix, 32), message }, rHash);
                CBigNum r = CBigNum::fromLittleEndian(SReadOnlyByteSpan(rHash, 64)).mod(L);

                EdPoint rPoint = Edwards25519::scalarMulBase(r);
                uint8_t rEncoded[32];
                if (!Edwards25519::encodePoint(rPoint, rEncoded)) {
                    return ERET_UNKNOWN;
                }

                uint8_t kHash[64];
                Edwards25519::sha512({ SReadOnlyByteSpan(rEncoded, 32), SReadOnlyByteSpan(pub->encoded(), 32), message }, kHash);
                CBigNum k = CBigNum::fromLittleEndian(SReadOnlyByteSpan(kHash, 64)).mod(L);

                k.mulMod(s, L);
                r.add(k);
                r.mod(L);
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
        const CBigNum& p = Edwards25519::fieldPrime();

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

        // 2. Field range: 0 <= x, y < p.
        if (q.x >= p || q.y >= p) {
            return ERET_KEY_PARAM;
        }

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
        if (expectedQ.x != q.x || expectedQ.y != q.y) {
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
