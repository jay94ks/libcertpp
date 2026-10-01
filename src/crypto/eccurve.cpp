#include <certpp/crypto/eccurve.hpp>
#include <utility>

namespace certpp {
namespace crypto {

        /* Parses a curve's hardcoded hex constant into a CBigNum at static-init time. The
         * strings are trusted literals (see _knownCurves below), so a parse failure (which
         * fromHex only reports via its bool return) can't actually happen here. */
        CBigNum CEcCurve::parseHex(const char* hex) {
            CBigNum result;
            CBigNum::fromHex(hex, result);
            return result;
        }

        CEcCurve::ECPointJac CEcCurve::infinityJac() {
            return ECPointJac{ CBigNum(uint64_t(1)), CBigNum(uint64_t(1)), CBigNum() };
        }

        CEcCurve::ECPointJac CEcCurve::toJacobian(const SEcPoint& pt) {
            if (pt.infinity) {
                return infinityJac();
            }
            return ECPointJac{ pt.x, pt.y, CBigNum(uint64_t(1)) };
        }

        SEcPoint CEcCurve::toAffineFromJac(const ECPointJac& pt, const CBigNum& p) {
            if (pt.z.isZero()) {
                return SEcPoint();
            }

            CBigNum zInv;
            CBigNum::modInverse(pt.z, p, zInv);

            CBigNum zInv2(zInv);
            zInv2.mulMod(zInv, p);

            CBigNum zInv3(zInv2);
            zInv3.mulMod(zInv, p);

            CBigNum x(pt.x);
            x.mulMod(zInv2, p);

            CBigNum y(pt.y);
            y.mulMod(zInv3, p);

            return SEcPoint(std::move(x), std::move(y));
        }

        /* Jacobian doubling (dbl-2007-bl, Bernstein/Lange, general a -- this library's curves
         * span both a == -3, the NIST/Brainpool r1 default, and arbitrary a for secp256k1/the
         * Brainpool t1 curves, so the a == -3 shortcut isn't used). A point of order 2 (y == 0)
         * has an undefined tangent slope -- doubling it is the point at infinity, same
         * special case doublePoint() above already handles in affine form. */
        CEcCurve::ECPointJac CEcCurve::doublePointJac(const ECPointJac& pt, const CBigNum& p, const CBigNum& a) {
            if (pt.z.isZero() || pt.y.isZero()) {
                return infinityJac();
            }

            CBigNum A(pt.x);
            A.mulMod(pt.x, p);

            CBigNum B(pt.y);
            B.mulMod(pt.y, p);

            // C = B^2; B's original value (y^2) is still needed below (xPlusB), so this can't
            // mutate B in place -- a genuine copy.
            CBigNum C(B);
            C.mulMod(B, p);

            CBigNum xPlusB(pt.x);
            xPlusB.add(B);
            xPlusB.mod(p);

            // D = 2*(xPlusB^2 - A - C), built by mutating xPlusB in place (self-squaring, then
            // the rest of the formula) -- xPlusB's pre-square value has no other reader.
            xPlusB.mulMod(xPlusB, p);
            xPlusB.modSub(A, p);
            xPlusB.modSub(C, p);
            xPlusB.add(xPlusB);
            xPlusB.mod(p);
            CBigNum& d = xPlusB;

            CBigNum z2(pt.z);
            z2.mulMod(pt.z, p);

            // z4 = z2^2, by mutating z2 in place -- z2's pre-square value has no other reader.
            z2.mulMod(z2, p);
            CBigNum& z4 = z2;

            // threeA = 3*A: A's own value is read three times below (it stays fixed while
            // threeA accumulates), so this can't be fused into A itself.
            CBigNum threeA(A);
            threeA.add(A);
            threeA.add(A);
            threeA.mod(p);

            CBigNum aZ4(a);
            aZ4.mulMod(z4, p);

            // E = threeA + aZ4, by mutating threeA in place -- its pre-sum value has no other
            // reader.
            threeA.add(aZ4);
            threeA.mod(p);
            CBigNum& e = threeA;

            // F = E^2; E's own value is still needed below (y3), so this can't mutate e in
            // place -- a genuine copy.
            CBigNum F(e);
            F.mulMod(e, p);

            // twoD = 2*D; d's own value is still needed below (dMinusX3), so this can't mutate
            // d in place -- a genuine copy.
            CBigNum twoD(d);
            twoD.add(d);
            twoD.mod(p);

            // x3 = F - twoD, by mutating F in place -- its pre-subtraction value has no other
            // reader.
            F.modSub(twoD, p);
            CBigNum& x3 = F;

            // dMinusX3 = D - x3, by mutating d in place -- this is d's last read.
            d.modSub(x3, p);
            CBigNum& dMinusX3 = d;

            CBigNum y3(e);
            y3.mulMod(dMinusX3, p);

            // eightC = C*8, by mutating C in place -- this is C's last read.
            C.mulMod(CBigNum(uint64_t(8)), p);
            y3.modSub(C, p);

            CBigNum z3(pt.y);
            z3.mulMod(pt.z, p);
            z3.add(z3);
            z3.mod(p);

            return ECPointJac{ std::move(x3), std::move(y3), std::move(z3) };
        }

        /* Jacobian addition (add-2007-bl, Bernstein/Lange, general Z1/Z2). Falls back to
         * doublePointJac() when both points share the same x-coordinate and the same y (P1 ==
         * P2), and to the point at infinity when they share x but differ in y (P1 == -P2) --
         * same two exceptional cases affine add() above already special-cases. */
        CEcCurve::ECPointJac CEcCurve::addJac(const ECPointJac& p1, const ECPointJac& p2, const CBigNum& p, const CBigNum& a) {
            if (p1.z.isZero()) {
                return p2;
            }
            if (p2.z.isZero()) {
                return p1;
            }

            // z1z1/z2z2 are each read again all the way at the very end (z3's formula), so they
            // stay alive as their own variables throughout -- no fusion opportunity for them.
            CBigNum z1z1(p1.z);
            z1z1.mulMod(p1.z, p);

            CBigNum z2z2(p2.z);
            z2z2.mulMod(p2.z, p);

            // u1 is read twice below (h's construction, then v's construction) -- it survives
            // until the second read, where it's fused away (see "u1 becomes v" below).
            CBigNum u1(p1.x);
            u1.mulMod(z2z2, p);

            // u2 is read exactly once below (h's construction) -- that's its last read, so h is
            // built by mutating u2 directly rather than copying it.
            CBigNum u2(p2.x);
            u2.mulMod(z1z1, p);

            CBigNum z2z2z2(z2z2);
            z2z2z2.mulMod(p2.z, p);

            CBigNum z1z1z1(z1z1);
            z1z1z1.mulMod(p1.z, p);

            // s1 is read twice below (this file's "r"'s construction, then twoS1J's) -- it
            // survives until the second read, where it's fused away (see "s1 becomes twoS1J"
            // below).
            CBigNum s1(p1.y);
            s1.mulMod(z2z2z2, p);

            // s2 is read exactly once below (this file's "r"'s construction) -- that's its last
            // read, so "r" is built by mutating s2 directly rather than copying it.
            CBigNum s2(p2.y);
            s2.mulMod(z1z1z1, p);

            // h = u2 - u1 (this is u2's last read -- mutate in place).
            u2.modSub(u1, p);
            CBigNum& h = u2;

            // r = s2 - s1 (this is s2's last read -- mutate in place).
            s2.modSub(s1, p);
            CBigNum& r = s2;

            if (h.isZero()) {
                if (r.isZero()) {
                    return doublePointJac(p1, p, a);
                }
                return infinityJac();
            }

            // i and j are each read twice below (v's/x3's construction, then x3's/twoS1J's) --
            // both stay genuine copies (h/i must still be intact after producing them: h is
            // read again at the very end, i is read again below).
            CBigNum i(h);
            i.add(h);
            i.mod(p);
            i.mulMod(i, p); // (2h)^2

            CBigNum j(h);
            j.mulMod(i, p);

            r.add(r);
            r.mod(p); // r = 2*(s2-s1)

            // v = u1*i (this is u1's first of two remaining reads -- fused into u1 below, at its
            // second/last read).
            u1.mulMod(i, p);
            CBigNum& v = u1;

            CBigNum x3(r);
            x3.mulMod(r, p);
            x3.modSub(j, p);

            CBigNum twoV(v);
            twoV.add(v);
            twoV.mod(p);
            x3.modSub(twoV, p);

            // vMinusX3 = v - x3 (this is v's/u1's last read -- mutate in place).
            v.modSub(x3, p);
            CBigNum& vMinusX3 = v;

            // y3 = r*vMinusX3 (this is r's/s2's last read -- mutate in place).
            r.mulMod(vMinusX3, p);
            CBigNum& y3Accum = r;

            // twoS1J = 2*s1*j (this is s1's last read -- mutate in place).
            s1.mulMod(j, p);
            s1.add(s1);
            s1.mod(p);
            y3Accum.modSub(s1, p);

            CBigNum z1PlusZ2(p1.z);
            z1PlusZ2.add(p2.z);
            z1PlusZ2.mod(p);

            CBigNum z3(z1PlusZ2);
            z3.mulMod(z1PlusZ2, p);
            z3.modSub(z1z1, p);
            z3.modSub(z2z2, p);
            z3.mulMod(h, p);

            return ECPointJac{ std::move(x3), std::move(y3Accum), std::move(z3) };
        }

        void CEcCurve::condSwapJac(bool doSwap, ECPointJac& a, ECPointJac& b) {
            CBigNum::condSwap(doSwap, a.x, b.x);
            CBigNum::condSwap(doSwap, a.y, b.y);
            CBigNum::condSwap(doSwap, a.z, b.z);
        }

    /* Definition of the known curves array, in EEcKnownCurves order (ECURVE_P192, ECURVE_P224,
     * ECURVE_P256, ECURVE_P384, ECURVE_P521, ECURVE_SECP256K1, then the 14 Brainpool curves
     * (RFC 5639) in R1-then-T1 order -- ECURVE_UNKNOWN has no entry). Constants verified against
     * an independent source (FIPS 186-4 / SEC 2 recommended parameters for the NIST/secp256k1
     * curves; RFC 5639 itself, cross-checked against std.neuromancer.sk, for the Brainpool
     * curves) before hardcoding. */
    const CEcCurve CEcCurve::_knownCurves[ECURVE_MAX - 1] = {
        // ECURVE_P192: NIST P-192 / secp192r1
        CEcCurve(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
            "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
            "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"
        ),
        // ECURVE_P224: NIST P-224 / secp224r1
        CEcCurve(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
            "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
            "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
            "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"
        ),
        // ECURVE_P256: NIST P-256 / secp256r1
        CEcCurve(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
        ),
        // ECURVE_P384: NIST P-384 / secp384r1
        CEcCurve(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"
        ),
        // ECURVE_P521: NIST P-521 / secp521r1
        CEcCurve(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"
        ),
        // ECURVE_SECP256K1: secp256k1 (SEC 2)
        CEcCurve(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            "00",
            "07",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
        ),
        // ECURVE_BPOOL160R1: brainpoolP160r1 (RFC 5639)
        CEcCurve(
            "E95E4A5F737059DC60DFC7AD95B3D8139515620F",
            "340E7BE2A280EB74E2BE61BADA745D97E8F7C300",
            "1E589A8595423412134FAA2DBDEC95C8D8675E58",
            "BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3",
            "1667CB477A1A8EC338F94741669C976316DA6321",
            "E95E4A5F737059DC60DF5991D45029409E60FC09"
        ),
        // ECURVE_BPOOL192R1: brainpoolP192r1 (RFC 5639)
        CEcCurve(
            "C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
            "6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF",
            "469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9",
            "C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6",
            "14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F",
            "C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1"
        ),
        // ECURVE_BPOOL224R1: brainpoolP224r1 (RFC 5639)
        CEcCurve(
            "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
            "68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
            "2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",
            "0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D",
            "58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD",
            "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F"
        ),
        // ECURVE_BPOOL256R1: brainpoolP256r1 (RFC 5639)
        CEcCurve(
            "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
            "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
            "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
            "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
            "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
            "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"
        ),
        // ECURVE_BPOOL320R1: brainpoolP320r1 (RFC 5639)
        CEcCurve(
            "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
            "3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
            "520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
            "43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611",
            "14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
            "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311"
        ),
        // ECURVE_BPOOL384R1: brainpoolP384r1 (RFC 5639)
        CEcCurve(
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
            "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
            "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
            "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
            "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565"
        ),
        // ECURVE_BPOOL512R1: brainpoolP512r1 (RFC 5639)
        CEcCurve(
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
            "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
            "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
            "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
            "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069"
        ),
        // ECURVE_BPOOL160T1: brainpoolP160t1 (RFC 5639)
        CEcCurve(
            "E95E4A5F737059DC60DFC7AD95B3D8139515620F",
            "E95E4A5F737059DC60DFC7AD95B3D8139515620C",
            "7A556B6DAE535B7B51ED2C4D7DAA7A0B5C55F380",
            "B199B13B9B34EFC1397E64BAEB05ACC265FF2378",
            "ADD6718B7C7C1961F0991B842443772152C9E0AD",
            "E95E4A5F737059DC60DF5991D45029409E60FC09"
        ),
        // ECURVE_BPOOL192T1: brainpoolP192t1 (RFC 5639)
        CEcCurve(
            "C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
            "C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86294",
            "13D56FFAEC78681E68F9DEB43B35BEC2FB68542E27897B79",
            "3AE9E58C82F63C30282E1FE7BBF43FA72C446AF6F4618129",
            "097E2C5667C2223A902AB5CA449D0084B7E5B3DE7CCC01C9",
            "C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1"
        ),
        // ECURVE_BPOOL224T1: brainpoolP224t1 (RFC 5639)
        CEcCurve(
            "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
            "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FC",
            "4B337D934104CD7BEF271BF60CED1ED20DA14C08B3BB64F18A60888D",
            "6AB1E344CE25FF3896424E7FFE14762ECB49F8928AC0C76029B4D580",
            "0374E9F5143E568CD23F3F4D7C0D4B1E41C8CC0D1C6ABD5F1A46DB4C",
            "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F"
        ),
        // ECURVE_BPOOL256T1: brainpoolP256t1 (RFC 5639)
        CEcCurve(
            "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
            "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5374",
            "662C61C430D84EA4FE66A7733D0B76B7BF93EBC4AF2F49256AE58101FEE92B04",
            "A3E8EB3CC1CFE7B7732213B23A656149AFA142C47AAFBC2B79A191562E1305F4",
            "2D996C823439C56D7F7B22E14644417E69BCB6DE39D027001DABE8F35B25C9BE",
            "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"
        ),
        // ECURVE_BPOOL320T1: brainpoolP320t1 (RFC 5639)
        CEcCurve(
            "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
            "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E24",
            "A7F561E038EB1ED560B3D147DB782013064C19F27ED27C6780AAF77FB8A547CEB5B4FEF422340353",
            "925BE9FB01AFC6FB4D3E7D4990010F813408AB106C4F09CB7EE07868CC136FFF3357F624A21BED52",
            "63BA3A7A27483EBF6671DBEF7ABB30EBEE084E58A0B077AD42A5A0989D1EE71B1B9BC0455FB0D2C3",
            "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311"
        ),
        // ECURVE_BPOOL384T1: brainpoolP384t1 (RFC 5639)
        CEcCurve(
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC50",
            "7F519EADA7BDA81BD826DBA647910F8C4B9346ED8CCDC64E4B1ABD11756DCE1D2074AA263B88805CED70355A33B471EE",
            "18DE98B02DB9A306F2AFCD7235F72A819B80AB12EBD653172476FECD462AABFFC4FF191B946A5F54D8D0AA2F418808CC",
            "25AB056962D30651A114AFD2755AD336747F93475B7A1FCA3B88F2B6A208CCFE469408584DC2B2912675BF5B9E582928",
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565"
        ),
        // ECURVE_BPOOL512T1: brainpoolP512t1 (RFC 5639)
        CEcCurve(
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F0",
            "7CBBBCF9441CFAB76E1890E46884EAE321F70C0BCB4981527897504BEC3E36A62BCDFA2304976540F6450085F2DAE145C22553B465763689180EA2571867423E",
            "640ECE5C12788717B9C1BA06CBC2A6FEBA85842458C56DDE9DB1758D39C0313D82BA51735CDB3EA499AA77A7D6943A64F7A3F25FE26F06B51BAA2696FA9035DA",
            "5B534BD595F5AF0FA2C892376C84ACE1BB4E3019B71634C01131159CAE03CEE9D9932184BEEF216BD71DF2DADF86A627306ECFF96DBB8BACE198B61E00F8B332",
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069"
        )
    };

    CEcCurve::CEcCurve(
        const char* pHex, const char* aHex, const char* bHex,
        const char* gxHex, const char* gyHex, const char* nHex
    )
        : p(parseHex(pHex)), a(parseHex(aHex)), b(parseHex(bHex)), n(parseHex(nHex)),
          g(parseHex(gxHex), parseHex(gyHex))
    {
    }

    /* Maps a known curve identifier to the EAsymmetrics identifying it -- see this method's own
     * doc comment in eccurve.hpp. */
    EAsymmetrics CEcCurve::identify(EEcKnownCurves which) {
        switch (which) {
            case ECURVE_P192:        return EASYM_P192;
            case ECURVE_P224:        return EASYM_P224;
            case ECURVE_P256:        return EASYM_P256;
            case ECURVE_P384:        return EASYM_P384;
            case ECURVE_P521:        return EASYM_P521;
            case ECURVE_SECP256K1:   return EASYM_SECP256K1;
            case ECURVE_BPOOL160R1:  return EASYM_BPOOL160R1;
            case ECURVE_BPOOL192R1:  return EASYM_BPOOL192R1;
            case ECURVE_BPOOL224R1:  return EASYM_BPOOL224R1;
            case ECURVE_BPOOL256R1:  return EASYM_BPOOL256R1;
            case ECURVE_BPOOL320R1:  return EASYM_BPOOL320R1;
            case ECURVE_BPOOL384R1:  return EASYM_BPOOL384R1;
            case ECURVE_BPOOL512R1:  return EASYM_BPOOL512R1;
            case ECURVE_BPOOL160T1:  return EASYM_BPOOL160T1;
            case ECURVE_BPOOL192T1:  return EASYM_BPOOL192T1;
            case ECURVE_BPOOL224T1:  return EASYM_BPOOL224T1;
            case ECURVE_BPOOL256T1:  return EASYM_BPOOL256T1;
            case ECURVE_BPOOL320T1:  return EASYM_BPOOL320T1;
            case ECURVE_BPOOL384T1:  return EASYM_BPOOL384T1;
            case ECURVE_BPOOL512T1:  return EASYM_BPOOL512T1;
            default:                 return EASYM_P256; // unreachable for a validly-constructed CEcdsa
        }
    }

    size_t CEcCurve::fieldByteLen() const {
        return (p.bitLength() + 7) / 8;
    }

    bool CEcCurve::isOnCurve(const SEcPoint& pt) const {
        if (pt.infinity) {
            return true;
        }

        CBigNum lhs(pt.y);
        lhs.mulMod(pt.y, p);

        CBigNum rhs(pt.x);
        rhs.mulMod(pt.x, p);
        rhs.mulMod(pt.x, p);

        CBigNum ax(a);
        ax.mulMod(pt.x, p);

        rhs.add(ax);
        rhs.add(b);
        rhs.mod(p);

        return lhs == rhs;
    }

    SEcPoint CEcCurve::add(const SEcPoint& p1, const SEcPoint& p2) const {
        if (p1.infinity) {
            return p2;
        }

        if (p2.infinity) {
            return p1;
        }

        if (p1.x == p2.x) {
            CBigNum ySum(p1.y);
            ySum.add(p2.y);
            ySum.mod(p);
            if (ySum.isZero()) {
                return SEcPoint(); // p1 == -p2 -- result is the point at infinity
            }

            return doublePoint(p1);
        }

        CBigNum dx(p2.x);
        dx.modSub(p1.x, p);

        CBigNum dy(p2.y);
        dy.modSub(p1.y, p);

        CBigNum dxInv;
        if (!CBigNum::modInverse(dx, p, dxInv)) {
            return SEcPoint(); // unreachable: dx != 0 was just checked (p1.x != p2.x)
        }

        // dy's last read -- mutate in place instead of copying into a separate lambda.
        dy.mulMod(dxInv, p);
        CBigNum& lambda = dy;

        CBigNum x3(lambda);
        x3.mulMod(lambda, p);
        x3.modSub(p1.x, p);
        x3.modSub(p2.x, p);

        CBigNum y3(p1.x);
        y3.modSub(x3, p);
        y3.mulMod(lambda, p);
        y3.modSub(p1.y, p);

        return SEcPoint(std::move(x3), std::move(y3));
    }

    SEcPoint CEcCurve::doublePoint(const SEcPoint& pt) const {
        if (pt.infinity || pt.y.isZero()) {
            return SEcPoint();
        }

        CBigNum xx(pt.x);
        xx.mulMod(pt.x, p);

        CBigNum threeXX(xx);
        threeXX.add(xx);
        threeXX.add(xx);
        threeXX.mod(p);

        // threeXX's last read -- mutate in place instead of copying into a separate numerator.
        threeXX.add(a);
        threeXX.mod(p);

        CBigNum twoY(pt.y);
        twoY.add(pt.y);
        twoY.mod(p);

        CBigNum twoYInv;
        if (!CBigNum::modInverse(twoY, p, twoYInv)) {
            return SEcPoint(); // unreachable: y != 0 was just checked
        }

        // threeXX's (now "numerator"'s) last read -- mutate in place instead of copying into a
        // separate lambda.
        threeXX.mulMod(twoYInv, p);
        CBigNum& lambda = threeXX;

        CBigNum x3(lambda);
        x3.mulMod(lambda, p);
        x3.modSub(pt.x, p);
        x3.modSub(pt.x, p);

        CBigNum y3(pt.x);
        y3.modSub(x3, p);
        y3.mulMod(lambda, p);
        y3.modSub(pt.y, p);

        return SEcPoint(std::move(x3), std::move(y3));
    }

    /* Branch-free double-and-add, entirely in Jacobian coordinates: R0/R1 always satisfy the
     * invariant R1 == R0 + pt, and every iteration always computes both an addition and a
     * doubling -- only which register ends up holding which value depends on the scalar's bit,
     * via condSwapJac() rather than a branch choosing whether to run an addition at all (contrast
     * the old shape, which only ever added when the bit was set). Still not constant-time
     * overall (condSwapJac()/CBigNum's own arithmetic aren't), but removes the "the expensive
     * step only sometimes runs" pattern that was the most visible timing signal. Jacobian
     * coordinates additionally mean the loop itself never pays for a modular inversion --
     * toAffineFromJac() below pays for exactly one, at the very end, replacing the
     * one-inversion-per-step affine version this used to be (add()/doublePoint() above still
     * exist and still work in affine form, for callers that need a single group operation rather
     * than a full scalar multiplication). */
    SEcPoint CEcCurve::scalarMul(const SEcPoint& pt, const CBigNum& k) const {
        SEcPoint result; // infinity

        if (pt.infinity || k.isZero()) {
            return result;
        }

        ECPointJac r0 = infinityJac();
        ECPointJac r1 = toJacobian(pt);

        for (size_t i = k.bitLength(); i-- > 0; ) {
            bool bit = k.testBit(i);

            condSwapJac(bit, r0, r1);
            ECPointJac sum = addJac(r0, r1, p, a);
            ECPointJac doubled = doublePointJac(r0, p, a);
            r1 = std::move(sum);
            r0 = std::move(doubled);
            condSwapJac(bit, r0, r1);
        }

        return toAffineFromJac(r0, p);
    }

    /* Left-to-right windowed method over _baseTable (see its own doc comment for the lazy-build/
     * copy-propagation reasoning): every window's addition still runs unconditionally --
     * _baseTable[0] is the point at infinity, so an all-zero window costs an addJac() that adds
     * nothing (its z == 0 short-circuit) rather than a branch skipping the addition -- the same
     * "always do the expensive step" shape scalarMul()'s ladder above uses. Entirely in Jacobian
     * coordinates internally, same as scalarMul(). */
    SEcPoint CEcCurve::scalarMulBase(const CBigNum& k) const {
        constexpr size_t BASE_TABLE_WINDOW = 4;
        constexpr size_t BASE_TABLE_SIZE = size_t(1) << BASE_TABLE_WINDOW; // 16

        if (g.infinity || k.isZero()) {
            return SEcPoint();
        }

        if (_baseTable.size() != BASE_TABLE_SIZE) {
            TArray<SEcPoint> table;
            table.resize(BASE_TABLE_SIZE);

            table[0] = SEcPoint(); // infinity
            table[1] = g;
            for (size_t i = 2; i < BASE_TABLE_SIZE; ++i) {
                table[i] = add(table[i - 1], g);
            }

            _baseTable = std::move(table);
        }

        size_t bits = k.bitLength();
        size_t numWindows = (bits + BASE_TABLE_WINDOW - 1) / BASE_TABLE_WINDOW;

        ECPointJac result = infinityJac();

        for (size_t w = numWindows; w-- > 0; ) {
            for (size_t i = 0; i < BASE_TABLE_WINDOW; ++i) {
                result = doublePointJac(result, p, a);
            }

            size_t base = w * BASE_TABLE_WINDOW;
            size_t windowValue = 0;
            for (size_t b = 0; b < BASE_TABLE_WINDOW; ++b) {
                if (k.testBit(base + b)) {
                    windowValue |= (size_t(1) << b);
                }
            }

            result = addJac(result, toJacobian(_baseTable[windowValue]), p, a);
        }

        return toAffineFromJac(result, p);
    }

    bool CEcCurve::encodePoint(const SEcPoint& pt, TArray<uint8_t>& out) const {
        if (pt.infinity) {
            out.resize(1);
            out[0] = 0x00;
            return true;
        }

        size_t flen = fieldByteLen();
        out.resize(1 + 2 * flen);
        out[0] = 0x04;

        if (!pt.x.toBigEndian(SByteSpan(out.begin() + 1, flen))) {
            return false;
        }

        if (!pt.y.toBigEndian(SByteSpan(out.begin() + 1 + flen, flen))) {
            return false;
        }

        return true;
    }

    bool CEcCurve::decodePoint(SReadOnlyByteSpan data, SEcPoint& out) const {
        // --> The point at infinity is a valid SEC1 *encoding*, but never a valid *public key* --
        // every caller (createPublicKey()/createPrivateKey() in ecdsa.cpp) immediately rejected it
        // on top of this call anyway, so it's rejected once here instead, for every caller.
        if (data.size == 1 && data.data[0] == 0x00) {
            return false;
        }

        size_t flen = fieldByteLen();
        if (data.size != 1 + 2 * flen || data.data[0] != 0x04) {
            return false;
        }

        CBigNum x = CBigNum::fromBigEndian(data.slice(1, flen));
        CBigNum y = CBigNum::fromBigEndian(data.slice(1 + flen, flen));

        // --> Field range: a flen-byte big-endian value can represent anything up to 2^(8*flen)-1,
        // which is larger than p for every curve this library ships (p is never of the form
        // 2^n-1) -- without this, isOnCurve()'s mod-p arithmetic would accept a non-canonical
        // x/y >= p as "on curve" (it's equal mod p to some legitimate point), letting the same
        // point be smuggled in under more than one byte encoding.
        if (x >= p || y >= p) {
            return false;
        }

        SEcPoint candidate(x, y);
        if (!isOnCurve(candidate)) {
            return false;
        }

        // --> Correct (order-n) subgroup: n*candidate must be the point at infinity. This is
        // mathematically guaranteed already for this library's cofactor-1 curves (the only
        // possible point orders are 1 and n, and order 1 is the already-rejected infinity), but
        // checking it unconditionally here keeps every decodePoint() caller uniformly protected
        // without relying on each one separately re-deriving why it's safe to skip -- see
        // CEc2Curve::decodePoint(), where the equivalent check is NOT redundant.
        if (!scalarMul(candidate, n).infinity) {
            return false;
        }

        out = candidate;
        return true;
    }

} // namespace crypto
} // namespace certpp
