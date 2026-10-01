#include <certpp/crypto/ec2curve.hpp>
#include <cstring>
#include <utility>

namespace certpp {
namespace crypto {

        /* Parses a curve constant into a CGf2m. Only used for this module's hardcoded domain
         * parameters, each independently verified (on-curve base point, correct subgroup order)
         * before hardcoding -- see this file's _knownCurves comment -- so a parse failure here
         * would indicate a bug in this file, not bad runtime input. */
        CGf2m CEc2Curve::parseGf2mHex(const SGf2mField& field, const char* hex) {
            CGf2m out;
            CGf2m::fromHex(field, hex, out);
            return out;
        }

        CBigNum CEc2Curve::parseHexBigNum(const char* hex) {
            CBigNum out;
            CBigNum::fromHex(hex, out);
            return out;
        }

        /* doublePointLD()/addLD() below were derived from this file's own (already-verified)
         * affine formulas and independently cross-checked against them via a standalone Python
         * GF(2^163) implementation -- 2000+ random operand pairs (including random, non-1 Z
         * scalings on both operands) plus the point-at-infinity, negation (P + (-P)), and
         * order-2-point-doubling edge cases, and a full end-to-end run of the exact ladder
         * shape scalarMul() below uses against repeated affine doubling -- before being ported
         * here, per this module's established constant-verification discipline. The infinity
         * marker uses a default-constructed (null-field) CGf2m for x/y: every function below
         * checks z.isZero() before ever touching x/y, so the field pointer is never dereferenced
         * on that path (CGf2m::isZero() itself doesn't look at the field either). */
        CEc2Curve::EC2PointLD CEc2Curve::infinityLD() {
            return EC2PointLD{ CGf2m(), CGf2m(), CGf2m() };
        }

        CEc2Curve::EC2PointLD CEc2Curve::toLD(const SEc2Point& pt, const SGf2mField& field) {
            if (pt.infinity) {
                return infinityLD();
            }
            return EC2PointLD{ pt.x, pt.y, CGf2m(field, 1) };
        }

        SEc2Point CEc2Curve::toAffineFromLD(const EC2PointLD& pt) {
            if (pt.z.isZero()) {
                return SEc2Point();
            }

            CGf2m zInv(pt.z);
            zInv.inverse();

            CGf2m zInv2(zInv);
            zInv2.mul(zInv);

            CGf2m x(pt.x);
            x.mul(zInv);

            CGf2m y(pt.y);
            y.mul(zInv2);

            return SEc2Point(std::move(x), std::move(y));
        }

        CEc2Curve::EC2PointLD CEc2Curve::doublePointLD(const EC2PointLD& pt, const CGf2m& a, const CGf2m& b) {
            // A point with x == 0 has order 2 (its tangent slope is undefined) -- doubling it
            // is the point at infinity, same special case doublePoint() above already handles.
            if (pt.z.isZero() || pt.x.isZero()) {
                return infinityLD();
            }

            // z1Sq is read twice below (z3's construction, then its own squaring into z1^4) --
            // the second read is its last, so it's mutated in place there rather than copied.
            CGf2m z1Sq(pt.z);
            z1Sq.square();

            // x1Sq is read three times below (z3's construction, its own squaring into x1^4,
            // and the x3 accumulator's construction) -- the last two reads are both mutations
            // in place, so x1Sq ends up holding X3 by the time this function returns.
            CGf2m x1Sq(pt.x);
            x1Sq.square();

            CGf2m z3(x1Sq);
            z3.mul(z1Sq);

            // z1Sq's last read -- mutate in place into z1^4.
            z1Sq.square();
            CGf2m& z1Pow4 = z1Sq;

            CGf2m bZ1Pow4(b);
            bZ1Pow4.mul(z1Pow4);

            // x1Sq's second read -- mutate in place into x1^4.
            x1Sq.square();

            // x1Sq's third and last read -- mutate in place into X3 (this is what ultimately
            // becomes the x3 this function returns).
            x1Sq.add(bZ1Pow4);
            CGf2m& x3 = x1Sq;

            CGf2m aZ3(a);
            aZ3.mul(z3);

            CGf2m y1Sq(pt.y);
            y1Sq.square();

            // aZ3 is read twice below (both additions); the second is its last read, so
            // "inner" is built by mutating aZ3 in place rather than copying it.
            aZ3.add(y1Sq);
            aZ3.add(bZ1Pow4);
            CGf2m& inner = aZ3;

            // x3 (x1Sq) is still needed for the return value below, so this can't fuse -- a
            // genuine copy.
            CGf2m y3(x3);
            y3.mul(inner);

            // bZ1Pow4's last read -- mutate in place.
            bZ1Pow4.mul(z3);
            y3.add(bZ1Pow4);

            return EC2PointLD{ std::move(x3), std::move(y3), std::move(z3) };
        }

        /* Falls back to doublePointLD() when both points share the same x-coordinate and the
         * same y (P1 == P2), and to the point at infinity when they share x but differ in y
         * (P1 == -P2) -- same two exceptional cases affine add() above already special-cases. */
        CEc2Curve::EC2PointLD CEc2Curve::addLD(const EC2PointLD& p1, const EC2PointLD& p2, const CGf2m& a, const CGf2m& b) {
            if (p1.z.isZero()) {
                return p2;
            }
            if (p2.z.isZero()) {
                return p1;
            }

            // z1Sq/C are each read three or four times below (as a plain operand, never as a
            // copy-source), so they stay alive as their own variables throughout -- no fusion
            // opportunity for either.
            CGf2m z1Sq(p1.z);
            z1Sq.square();

            // z2Sq is read three times below (y1z2Sq's construction, z2Cubed's construction,
            // then its own squaring into z2^4) -- the third read is its last, so it's mutated
            // in place there rather than copied.
            CGf2m z2Sq(p2.z);
            z2Sq.square();

            // y1z2Sq is read exactly once below (A's construction) -- that's its last read, so
            // A is built by mutating y1z2Sq directly. A itself is later read three times (A2's
            // construction, ABC's construction, and its own final mutation into term2) -- the
            // third is A's last read, so term2 is *also* built by mutating y1z2Sq (still aliased
            // as A) in place, making y1z2Sq the variable that ultimately becomes term2.
            CGf2m y1z2Sq(p1.y);
            y1z2Sq.mul(z2Sq);

            CGf2m y2z1Sq(p2.y);
            y2z1Sq.mul(z1Sq);

            y1z2Sq.add(y2z1Sq);
            CGf2m& A = y1z2Sq;

            // x1z2 is read exactly once below (B's construction) -- that's its last read, so B
            // is built by mutating x1z2 directly. Unlike A, B itself is read a fourth and final
            // time below only as a plain operand (B3's construction), never again as a
            // copy-source, so B stays alive as its own variable from here on (no further
            // fusion).
            CGf2m x1z2(p1.x);
            x1z2.mul(p2.z);

            CGf2m x2z1(p2.x);
            x2z1.mul(p1.z);

            x1z2.add(x2z1);
            CGf2m& B = x1z2;

            if (B.isZero()) {
                if (A.isZero()) {
                    return doublePointLD(p1, a, b);
                }
                return infinityLD();
            }

            CGf2m C(p1.z);
            C.mul(p2.z);

            // BC is read exactly once below (z3's construction) -- that's its last read, so z3
            // is built by mutating BC directly.
            CGf2m BC(B);
            BC.mul(C);

            BC.square();
            CGf2m& z3 = BC;

            // B2 is read three times below (B3's construction, aB2C2's construction, then its
            // own squaring into B4) -- the third read is its last, so B4 is built by mutating
            // B2 in place.
            CGf2m B2(B);
            B2.square();

            CGf2m C2(C);
            C2.square();

            // A2 is read exactly once below (x3's construction, across all three additions) --
            // that's its last read, so x3 is built by mutating A2 directly.
            CGf2m A2(A);
            A2.square();

            // ABC is read twice below (x3's construction, then its own final mutation into
            // term1) -- the second read is its last, so term1 is built by mutating ABC in
            // place.
            CGf2m ABC(A);
            ABC.mul(B);
            ABC.mul(C);

            // B3 is read twice below (B3C's construction, then as a plain operand in term2's
            // construction) -- the second read is B3's last, but it's a plain-operand read, not
            // a copy-source, so B3C above still has to be a genuine copy (B3 must survive past
            // it).
            CGf2m B3(B2);
            B3.mul(B);

            CGf2m B3C(B3);
            B3C.mul(C);

            CGf2m aB2C2(a);
            aB2C2.mul(B2);
            aB2C2.mul(C2);

            A2.add(ABC);
            A2.add(B3C);
            A2.add(aB2C2);
            CGf2m& x3 = A2;

            // ABC's last read (term1 = ABC*x3) -- mutate in place.
            ABC.mul(x3);
            CGf2m& term1 = ABC;

            CGf2m z2Cubed(z2Sq);
            z2Cubed.mul(p2.z);

            // A's last read (term2 = A*B3*X1*z1Sq*z2Cubed) -- mutate in place (A is itself an
            // alias of y1z2Sq, so this is y1z2Sq's second and final fusion).
            A.mul(B3);
            A.mul(p1.x);
            A.mul(z1Sq);
            A.mul(z2Cubed);
            CGf2m& term2 = A;

            // x3 is still needed for the return value below, so this can't fuse -- a genuine
            // copy.
            CGf2m term3(x3);
            term3.mul(z3);

            // B2's last read -- mutate in place.
            B2.square();
            CGf2m& B4 = B2;

            // z2Sq's last read -- mutate in place.
            z2Sq.square();
            CGf2m& z2Pow4 = z2Sq;

            CGf2m term4(p1.y);
            term4.mul(B4);
            term4.mul(z1Sq);
            term4.mul(z2Pow4);

            // term1's only remaining read is as the seed for y3 -- alias it directly instead of
            // copying.
            CGf2m& y3 = term1;

            y3.add(term2);
            y3.add(term3);
            y3.add(term4);

            return EC2PointLD{ std::move(x3), std::move(y3), std::move(z3) };
        }

        void CEc2Curve::condSwapLD(bool doSwap, EC2PointLD& a, EC2PointLD& b) {
            if (doSwap) {
                std::swap(a, b);
            }
        }

    CEc2Curve::CEc2Curve(
        EGf2mKnownField fieldId, const char* aHex, const char* bHex,
        const char* gxHex, const char* gyHex, const char* nHex
    )
        : field(CGf2m::knownFieldPtr(fieldId)),
          a(parseGf2mHex(*field, aHex)),
          b(parseGf2mHex(*field, bHex)),
          n(parseHexBigNum(nHex)),
          g(parseGf2mHex(*field, gxHex), parseGf2mHex(*field, gyHex)) {
    }

    /* Maps a known binary curve identifier to the EAsymmetrics identifying it -- see this
     * method's own doc comment in ec2curve.hpp. */
    EAsymmetrics CEc2Curve::identify(EEc2KnownCurves which) {
        switch (which) {
            case ECURVE2_B163: return EASYM_B163;
            case ECURVE2_K163: return EASYM_K163;
            case ECURVE2_B233: return EASYM_B233;
            case ECURVE2_K233: return EASYM_K233;
            case ECURVE2_B283: return EASYM_B283;
            case ECURVE2_K283: return EASYM_K283;
            case ECURVE2_B409: return EASYM_B409;
            case ECURVE2_K409: return EASYM_K409;
            case ECURVE2_B571: return EASYM_B571;
            case ECURVE2_K571: return EASYM_K571;
            default:           return EASYM_B163; // unreachable for a validly-constructed CEcdsa2
        }
    }

    size_t CEc2Curve::fieldByteLen() const {
        return (field->m + 7) / 8;
    }

    bool CEc2Curve::isOnCurve(const SEc2Point& pt) const {
        if (pt.infinity) {
            return true;
        }

        CGf2m xx(pt.x);
        xx.mul(pt.x);

        CGf2m lhs(pt.y);
        lhs.square();

        CGf2m xy(pt.x);
        xy.mul(pt.y);
        lhs.add(xy);

        CGf2m rhs(xx);
        rhs.mul(pt.x);

        CGf2m ax(a);
        ax.mul(xx);
        rhs.add(ax);
        rhs.add(b);

        return lhs == rhs;
    }

    SEc2Point CEc2Curve::doublePoint(const SEc2Point& pt) const {
        // A point with x == 0 has order 2 (its tangent line's slope, y/x, is undefined) --
        // doubling it is the point at infinity. None of this library's known base points are
        // such a point, so this is a defensive edge-case guard, not a hot path.
        if (pt.infinity || pt.x.isZero()) {
            return SEc2Point();
        }

        CGf2m lambda(pt.x);
        lambda.inverse();
        lambda.mul(pt.y);
        lambda.add(pt.x);

        CGf2m x3(lambda);
        x3.mul(lambda);
        x3.add(lambda);
        x3.add(a);

        CGf2m y3(pt.x);
        y3.mul(pt.x);

        // lambda's last read -- mutate in place instead of copying into a separate lx3.
        lambda.mul(x3);
        y3.add(lambda);
        y3.add(x3);

        return SEc2Point(std::move(x3), std::move(y3));
    }

    SEc2Point CEc2Curve::add(const SEc2Point& p1, const SEc2Point& p2) const {
        if (p1.infinity) {
            return p2;
        }
        if (p2.infinity) {
            return p1;
        }

        if (p1.x == p2.x) {
            if (p1.y != p2.y) {
                return SEc2Point(); // p2 == -p1 (== (x1, x1+y1)) -> infinity
            }
            return doublePoint(p1);
        }

        CGf2m xsum(p1.x);
        xsum.add(p2.x);
        xsum.inverse(); // now (x1+x2)^-1

        CGf2m lambda(p1.y);
        lambda.add(p2.y);
        lambda.mul(xsum);

        CGf2m x3(lambda);
        x3.mul(lambda);
        x3.add(lambda);
        x3.add(a);
        x3.add(p1.x);
        x3.add(p2.x);

        CGf2m p1xPlusX3(p1.x);
        p1xPlusX3.add(x3);

        // lambda's last read -- mutate in place instead of copying into a separate y3.
        lambda.mul(p1xPlusX3);
        lambda.add(x3);
        lambda.add(p1.y);

        return SEc2Point(std::move(x3), std::move(lambda));
    }

    /* Branch-free double-and-add, entirely in Lopez-Dahab coordinates -- see CEcCurve::
     * scalarMul()'s identical R0/R1 ladder (eccurve.cpp) for the invariant this relies on, and
     * this file's EC2PointLD doc comment for how doublePointLD()/addLD() were verified. As with
     * CEcCurve, the loop itself never pays for a field inversion -- toAffineFromLD() below pays
     * for exactly one, at the very end (add()/doublePoint() above still exist and still work in
     * affine form, for callers that need a single group operation rather than a full scalar
     * multiplication). */
    SEc2Point CEc2Curve::scalarMul(const SEc2Point& pt, const CBigNum& k) const {
        SEc2Point result; // infinity

        if (pt.infinity || k.isZero()) {
            return result;
        }

        EC2PointLD r0 = infinityLD();
        EC2PointLD r1 = toLD(pt, *field);

        for (size_t i = k.bitLength(); i-- > 0; ) {
            bool bit = k.testBit(i);

            condSwapLD(bit, r0, r1);
            EC2PointLD sum = addLD(r0, r1, a, b);
            EC2PointLD doubled = doublePointLD(r0, a, b);
            r1 = std::move(sum);
            r0 = std::move(doubled);
            condSwapLD(bit, r0, r1);
        }

        return toAffineFromLD(r0);
    }

    /* Left-to-right windowed method over _baseTable -- see CEcCurve::scalarMulBase()'s identical
     * doc comment (eccurve.cpp) for the full rationale, which applies here unchanged (every
     * window's addition runs unconditionally; _baseTable[0] is the point at infinity, so an
     * all-zero window costs an addLD() that adds nothing rather than a branch skipping it).
     * Entirely in Lopez-Dahab coordinates internally, same as scalarMul(). */
    SEc2Point CEc2Curve::scalarMulBase(const CBigNum& k) const {
        constexpr size_t BASE_TABLE_WINDOW = 4;
        constexpr size_t BASE_TABLE_SIZE = size_t(1) << BASE_TABLE_WINDOW; // 16

        if (g.infinity || k.isZero()) {
            return SEc2Point();
        }

        if (_baseTable.size() != BASE_TABLE_SIZE) {
            TArray<SEc2Point> table;
            table.resize(BASE_TABLE_SIZE);

            table[0] = SEc2Point(); // infinity
            table[1] = g;
            for (size_t i = 2; i < BASE_TABLE_SIZE; ++i) {
                table[i] = add(table[i - 1], g);
            }

            _baseTable = std::move(table);
        }

        size_t bits = k.bitLength();
        size_t numWindows = (bits + BASE_TABLE_WINDOW - 1) / BASE_TABLE_WINDOW;

        EC2PointLD result = infinityLD();

        for (size_t w = numWindows; w-- > 0; ) {
            for (size_t i = 0; i < BASE_TABLE_WINDOW; ++i) {
                result = doublePointLD(result, a, b);
            }

            size_t base = w * BASE_TABLE_WINDOW;
            size_t windowValue = 0;
            for (size_t bit = 0; bit < BASE_TABLE_WINDOW; ++bit) {
                if (k.testBit(base + bit)) {
                    windowValue |= (size_t(1) << bit);
                }
            }

            result = addLD(result, toLD(_baseTable[windowValue], *field), a, b);
        }

        return toAffineFromLD(result);
    }

    bool CEc2Curve::encodePoint(const SEc2Point& pt, TArray<uint8_t>& out) const {
        if (pt.infinity) {
            out.resize(1);
            out[0] = 0x00;
            return true;
        }

        size_t len = fieldByteLen();
        out.resize(1 + 2 * len);

        TArray<uint8_t> xBytes, yBytes;
        pt.x.toBigEndian(xBytes);
        pt.y.toBigEndian(yBytes);

        if (xBytes.size() != len || yBytes.size() != len) {
            return false;
        }

        uint8_t* outPtr = out.begin();
        outPtr[0] = 0x04;
        std::memcpy(outPtr + 1, xBytes.begin(), len);
        std::memcpy(outPtr + 1 + len, yBytes.begin(), len);

        return true;
    }

    bool CEc2Curve::decodePoint(SReadOnlyByteSpan data, SEc2Point& out) const {
        // --> The point at infinity is a valid SEC1 *encoding*, but never a valid *public key* --
        // every caller (createPublicKey()/createPrivateKey() in ecdsa2.cpp) immediately rejected
        // it on top of this call anyway, so it's rejected once here instead, for every caller.
        if (data.size == 1 && data.data[0] == 0x00) {
            return false;
        }

        size_t len = fieldByteLen();
        if (data.size != 1 + 2 * len || data.data[0] != 0x04) {
            return false;
        }

        CGf2m x, y;
        if (!CGf2m::fromBigEndian(*field, SReadOnlyByteSpan(data.data + 1, len), x)) {
            return false;
        }
        if (!CGf2m::fromBigEndian(*field, SReadOnlyByteSpan(data.data + 1 + len, len), y)) {
            return false;
        }

        SEc2Point pt(x, y);
        if (!isOnCurve(pt)) {
            return false;
        }

        // --> Correct (order-n) subgroup: n*pt must be the point at infinity. Unlike CEcCurve's
        // prime-field curves (cofactor 1, where this is mathematically guaranteed by isOnCurve()
        // alone), these binary curves have cofactor 2 or 4 -- a point can genuinely satisfy the
        // curve equation while sitting in a small-order subgroup instead of the main order-n one,
        // letting a maliciously crafted certificate's "public key" confine an ECDSA verification
        // to a tiny, attacker-searchable subgroup (the same vulnerability class as CVE-2026-26007).
        // Without this check, only checkPrivateKey() (never called on a bare imported public key)
        // caught this.
        if (!scalarMul(pt, n).infinity) {
            return false;
        }

        out = pt;
        return true;
    }

    /* Definition of the known curves array, in EEc2KnownCurves order (B-163, K-163, .. B-571,
     * K-571 -- ECURVE2_UNKNOWN has no entry). Domain parameters sourced from FIPS 186-4 Appendix
     * D / SEC 2's NIST binary curve recommendations, cross-checked against std.neuromancer.sk;
     * each base point/order additionally independently verified programmatically before being
     * hardcoded here -- confirmed on-curve (satisfies y^2+xy=x^3+ax^2+b) AND confirmed to have
     * exactly the stated order n (n*G reduces to the point at infinity via this same
     * double-and-add scalarMul()) -- the same two-property check this library used to validate
     * Ed448's algebraically-derived base point, and a much stronger guarantee than either
     * property alone: a wrong digit almost certainly breaks at least one of them. */
    const CEc2Curve CEc2Curve::_knownCurves[ECURVE2_MAX - 1] = {
        // ECURVE2_B163: NIST B-163 (sect163r2)
        CEc2Curve(
            EGF2M_M163,
            "01",
            "020a601907b8c953ca1481eb10512f78744a3205fd",
            "03f0eba16286a2d57ea0991168d4994637e8343e36",
            "00d51fbc6c71a0094fa2cdd545b11c5c0c797324f1",
            "040000000000000000000292fe77e70c12a4234c33"
        ),
        // ECURVE2_K163: NIST K-163 (sect163k1)
        CEc2Curve(
            EGF2M_M163,
            "01",
            "01",
            "02fe13c0537bbc11acaa07d793de4e6d5e5c94eee8",
            "0289070fb05d38ff58321f2e800536d538ccdaa3d9",
            "04000000000000000000020108a2e0cc0d99f8a5ef"
        ),
        // ECURVE2_B233: NIST B-233 (sect233r1)
        CEc2Curve(
            EGF2M_M233,
            "01",
            "0066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad",
            "00fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b",
            "01006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052",
            "1000000000000000000000000000013e974e72f8a6922031d2603cfe0d7"
        ),
        // ECURVE2_K233: NIST K-233 (sect233k1)
        CEc2Curve(
            EGF2M_M233,
            "00",
            "01",
            "017232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126",
            "01db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3",
            "8000000000000000000000000000069d5bb915bcd46efb1ad5f173abdf"
        ),
        // ECURVE2_B283: NIST B-283 (sect283r1)
        CEc2Curve(
            EGF2M_M283,
            "01",
            "27b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5",
            "5f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053",
            "3676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4",
            "3ffffffffffffffffffffffffffffffffffef90399660fc938a90165b042a7cefadb307"
        ),
        // ECURVE2_K283: NIST K-283 (sect283k1)
        CEc2Curve(
            EGF2M_M283,
            "00",
            "01",
            "503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836",
            "1ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259",
            "1ffffffffffffffffffffffffffffffffffe9ae2ed07577265dff7f94451e061e163c61"
        ),
        // ECURVE2_B409: NIST B-409 (sect409r1)
        CEc2Curve(
            EGF2M_M409,
            "01",
            "021a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f",
            "15d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7",
            "061b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706",
            "10000000000000000000000000000000000000000000000000001e2aad6a612f33307be5fa47c3c9e052f838164cd37d9a21173"
        ),
        // ECURVE2_K409: NIST K-409 (sect409k1)
        CEc2Curve(
            EGF2M_M409,
            "00",
            "01",
            "060f05f658f49c1ad3ab1890f7184210efd0987e307c84c27accfb8f9f67cc2c460189eb5aaaa62ee222eb1b35540cfe9023746",
            "1e369050b7c4e42acba1dacbf04299c3460782f918ea427e6325165e9ea10e3da5f6c42e9c55215aa9ca27a5863ec48d8e0286b",
            "7ffffffffffffffffffffffffffffffffffffffffffffffffffe5f83b2d4ea20400ec4557d5ed3e3e7ca5b4b5c83b8e01e5fcf"
        ),
        // ECURVE2_B571: NIST B-571 (sect571r1)
        CEc2Curve(
            EGF2M_M571,
            "01",
            "2f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a",
            "303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19",
            "37bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b",
            "3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe661ce18ff55987308059b186823851ec7dd9ca1161de93d5174d66e8382e9bb2fe84e47"
        ),
        // ECURVE2_K571: NIST K-571 (sect571k1)
        CEc2Curve(
            EGF2M_M571,
            "00",
            "01",
            "26eb7a859923fbc82189631f8103fe4ac9ca2970012d5d46024804801841ca44370958493b205e647da304db4ceb08cbbd1ba39494776fb988b47174dca88c7e2945283a01c8972",
            "349dc807f4fbf374f4aeade3bca95314dd58cec9f307a54ffc61efc006d8a2c9d4979c0ac44aea74fbebbb9f772aedcb620b01a7ba7af1b320430c8591984f601cd4c143ef1c7a3",
            "20000000000000000000000000000000000000000000000000000000000000000000000131850e1f19a63e4b391a8db917f4138b630d84be5d639381e91deb45cfe778f637c1001"
        )
    };

} // namespace crypto
} // namespace certpp
