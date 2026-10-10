#include "ariacore.hpp"

#include <cstring>

namespace certpp {
namespace crypto {

    // The four ARIA S-boxes, from RFC 5794 2.4.2's tables. SB3 is SB1's inverse and SB4 is
    // SB2's, which selfCheckTables() asserts on every key expansion so a mistranscribed table
    // cannot reach a caller.
    const uint8_t AriaCore::SB1[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    };

    const uint8_t AriaCore::SB2[256] = {
        0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
        0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
        0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
        0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
        0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
        0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
        0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
        0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
        0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
        0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
        0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
        0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
        0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
        0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
        0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
        0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81,
    };

    const uint8_t AriaCore::SB3[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    };

    const uint8_t AriaCore::SB4[256] = {
        0x30, 0x68, 0x99, 0x1b, 0x87, 0xb9, 0x21, 0x78, 0x50, 0x39, 0xdb, 0xe1, 0x72, 0x09, 0x62, 0x3c,
        0x3e, 0x7e, 0x5e, 0x8e, 0xf1, 0xa0, 0xcc, 0xa3, 0x2a, 0x1d, 0xfb, 0xb6, 0xd6, 0x20, 0xc4, 0x8d,
        0x81, 0x65, 0xf5, 0x89, 0xcb, 0x9d, 0x77, 0xc6, 0x57, 0x43, 0x56, 0x17, 0xd4, 0x40, 0x1a, 0x4d,
        0xc0, 0x63, 0x6c, 0xe3, 0xb7, 0xc8, 0x64, 0x6a, 0x53, 0xaa, 0x38, 0x98, 0x0c, 0xf4, 0x9b, 0xed,
        0x7f, 0x22, 0x76, 0xaf, 0xdd, 0x3a, 0x0b, 0x58, 0x67, 0x88, 0x06, 0xc3, 0x35, 0x0d, 0x01, 0x8b,
        0x8c, 0xc2, 0xe6, 0x5f, 0x02, 0x24, 0x75, 0x93, 0x66, 0x1e, 0xe5, 0xe2, 0x54, 0xd8, 0x10, 0xce,
        0x7a, 0xe8, 0x08, 0x2c, 0x12, 0x97, 0x32, 0xab, 0xb4, 0x27, 0x0a, 0x23, 0xdf, 0xef, 0xca, 0xd9,
        0xb8, 0xfa, 0xdc, 0x31, 0x6b, 0xd1, 0xad, 0x19, 0x49, 0xbd, 0x51, 0x96, 0xee, 0xe4, 0xa8, 0x41,
        0xda, 0xff, 0xcd, 0x55, 0x86, 0x36, 0xbe, 0x61, 0x52, 0xf8, 0xbb, 0x0e, 0x82, 0x48, 0x69, 0x9a,
        0xe0, 0x47, 0x9e, 0x5c, 0x04, 0x4b, 0x34, 0x15, 0x79, 0x26, 0xa7, 0xde, 0x29, 0xae, 0x92, 0xd7,
        0x84, 0xe9, 0xd2, 0xba, 0x5d, 0xf3, 0xc5, 0xb0, 0xbf, 0xa4, 0x3b, 0x71, 0x44, 0x46, 0x2b, 0xfc,
        0xeb, 0x6f, 0xd5, 0xf6, 0x14, 0xfe, 0x7c, 0x70, 0x5a, 0x7d, 0xfd, 0x2f, 0x18, 0x83, 0x16, 0xa5,
        0x91, 0x1f, 0x05, 0x95, 0x74, 0xa9, 0xc1, 0x5b, 0x4a, 0x85, 0x6d, 0x13, 0x07, 0x4f, 0x4e, 0x45,
        0xb2, 0x0f, 0xc9, 0x1c, 0xa6, 0xbc, 0xec, 0x73, 0x90, 0x7b, 0xcf, 0x59, 0x8f, 0xa1, 0xf9, 0x2d,
        0xf2, 0xb1, 0x00, 0x94, 0x37, 0x9f, 0xd0, 0x2e, 0x9c, 0x6e, 0x28, 0x3f, 0x80, 0xf0, 0x3d, 0xd3,
        0x25, 0x8a, 0xb5, 0xe7, 0x42, 0xb3, 0xc7, 0xea, 0xf7, 0x4c, 0x11, 0x33, 0x03, 0xa2, 0xac, 0x60,
    };

    // The 128-bit key-schedule constants, RFC 5794 2.2: the first 384 bits of the fractional
    // part of 1/PI, laid out as four big-endian 32-bit words per constant.
    const uint32_t AriaCore::C1[4] = { 0x517cc1b7u, 0x27220a94u, 0xfe13abe8u, 0xfa9a6ee0u };
    const uint32_t AriaCore::C2[4] = { 0x6db14accu, 0x9e21c820u, 0xff28b1d5u, 0xef5de2b0u };
    const uint32_t AriaCore::C3[4] = { 0xdb92371du, 0x2126e970u, 0x03249775u, 0x04e8c90eu };

    bool AriaCore::selfCheckTables() {
        // SB3 is SB1's inverse and SB4 is SB2's -- so composing either pair must give the
        // identity on every input. This is the property the whole cipher rests on, since SL2
        // is defined in terms of SB3/SB4 and is what makes decryption the inverse.
        for (int i = 0; i < 256; ++i) {
            if (SB3[SB1[i]] != uint8_t(i)) {
                return false;
            }
            if (SB4[SB2[i]] != uint8_t(i)) {
                return false;
            }
        }

        // And the RFC's own worked examples, in case both tables were mistyped in a way that
        // is still mutually consistent.
        return SB1[0x23] == 0x26 && SB4[0xef] == 0xd3;
    }

    /* Type 1 substitution layer, used in odd rounds. SL1 applies SB1/SB2/SB3/SB4 in rotation
     * across the sixteen bytes -- position i uses box (i mod 4) + 1. */
    void AriaCore::substitutionLayer1(uint8_t s[16]) {
        static const uint8_t* const BOX[4] = { SB1, SB2, SB3, SB4 };

        for (size_t i = 0; i < 16; ++i) {
            s[i] = BOX[i & 3][s[i]];
        }
    }

    /* Type 2 substitution layer, used in even rounds. SL2 rotates the boxes by two places, so
     * position i uses box ((i + 2) mod 4) + 1 -- which is why SL2 is SL1's inverse given
     * SB3 = SB1^-1 and SB4 = SB2^-1. */
    void AriaCore::substitutionLayer2(uint8_t s[16]) {
        static const uint8_t* const BOX[4] = { SB3, SB4, SB1, SB2 };

        for (size_t i = 0; i < 16; ++i) {
            s[i] = BOX[i & 3][s[i]];
        }
    }

    /* ARIA's diffusion layer, RFC 5794 2.4.3. Seven-input XOR per output byte, taken straight
     * from the specification's equations. This is an involution, which is what lets the
     * decryption round keys reuse it: A(dk) for each interior ek. */
    void AriaCore::diffusionLayer(uint8_t s[16]) {
        uint8_t t[16];

        t[0]  = uint8_t(s[3] ^ s[4] ^ s[6] ^ s[8]  ^ s[9]  ^ s[13] ^ s[14]);
        t[1]  = uint8_t(s[2] ^ s[5] ^ s[7] ^ s[8]  ^ s[9]  ^ s[12] ^ s[15]);
        t[2]  = uint8_t(s[1] ^ s[4] ^ s[6] ^ s[10] ^ s[11] ^ s[12] ^ s[15]);
        t[3]  = uint8_t(s[0] ^ s[5] ^ s[7] ^ s[10] ^ s[11] ^ s[13] ^ s[14]);
        t[4]  = uint8_t(s[0] ^ s[2] ^ s[5] ^ s[8]  ^ s[11] ^ s[14] ^ s[15]);
        t[5]  = uint8_t(s[1] ^ s[3] ^ s[4] ^ s[9]  ^ s[10] ^ s[14] ^ s[15]);
        t[6]  = uint8_t(s[0] ^ s[2] ^ s[7] ^ s[9]  ^ s[10] ^ s[12] ^ s[13]);
        t[7]  = uint8_t(s[1] ^ s[3] ^ s[6] ^ s[8]  ^ s[11] ^ s[12] ^ s[13]);
        t[8]  = uint8_t(s[0] ^ s[1] ^ s[4] ^ s[7]  ^ s[10] ^ s[13] ^ s[15]);
        t[9]  = uint8_t(s[0] ^ s[1] ^ s[5] ^ s[6]  ^ s[11] ^ s[12] ^ s[14]);
        t[10] = uint8_t(s[2] ^ s[3] ^ s[5] ^ s[6]  ^ s[8]  ^ s[13] ^ s[15]);
        t[11] = uint8_t(s[2] ^ s[3] ^ s[4] ^ s[7]  ^ s[9]  ^ s[12] ^ s[14]);
        t[12] = uint8_t(s[1] ^ s[2] ^ s[6] ^ s[7]  ^ s[9]  ^ s[11] ^ s[12]);
        t[13] = uint8_t(s[0] ^ s[3] ^ s[6] ^ s[7]  ^ s[8]  ^ s[10] ^ s[13]);
        t[14] = uint8_t(s[0] ^ s[3] ^ s[4] ^ s[5]  ^ s[9]  ^ s[11] ^ s[14]);
        t[15] = uint8_t(s[1] ^ s[2] ^ s[4] ^ s[5]  ^ s[8]  ^ s[10] ^ s[15]);

        std::memcpy(s, t, sizeof(t));
    }

    /* FO(D, RK) = A(SL1(D ^ RK)) -- the odd round function. */
    void AriaCore::roundOdd(uint8_t d[16], const uint8_t rk[16]) {
        for (size_t i = 0; i < 16; ++i) {
            d[i] ^= rk[i];
        }
        substitutionLayer1(d);
        diffusionLayer(d);
    }

    /* FE(D, RK) = A(SL2(D ^ RK)) -- the even round function. */
    void AriaCore::roundEven(uint8_t d[16], const uint8_t rk[16]) {
        for (size_t i = 0; i < 16; ++i) {
            d[i] ^= rk[i];
        }
        substitutionLayer2(d);
        diffusionLayer(d);
    }

    void AriaCore::xorRoundKey(uint8_t s[16], const uint8_t rk[16]) {
        for (size_t i = 0; i < 16; ++i) {
            s[i] ^= rk[i];
        }
    }

    /* The three-round Feistel that turns KL and KR into W0..W3, RFC 5794 2.2. CK1/CK2/CK3 are
     * chosen by key size, so the caller passes the three 128-bit constants already permuted
     * into the order this key size uses. */
    void AriaCore::scheduleWords(uint8_t w[4][16], const uint8_t ck[3][16]) {
        uint8_t d[16];

        // W0 = KL, already loaded by the caller into w[0].

        // W1 = FO(W0, CK1) ^ KR. The caller places KR in w[1] before calling, so the
        // zero-padded KR of a 128-bit key and the real KR of a 192- or 256-bit key are the
        // same code path -- no special case for the shortest key.
        {
            uint8_t kr[16];
            std::memcpy(kr, w[1], sizeof(kr));

            std::memcpy(d, w[0], 16);
            roundOdd(d, ck[0]);

            for (size_t i = 0; i < 16; ++i) {
                w[1][i] = uint8_t(d[i] ^ kr[i]);
            }
        }

        // W2 = FE(W1, CK2) ^ W0
        {
            std::memcpy(d, w[1], 16);
            roundEven(d, ck[1]);
            for (size_t i = 0; i < 16; ++i) {
                w[2][i] = uint8_t(d[i] ^ w[0][i]);
            }
        }

        // W3 = FO(W2, CK3) ^ W1
        {
            std::memcpy(d, w[2], 16);
            roundOdd(d, ck[2]);
            for (size_t i = 0; i < 16; ++i) {
                w[3][i] = uint8_t(d[i] ^ w[1][i]);
            }
        }
    }

    /* Loads sixteen bytes into four 32-bit words, big-endian, which is the layout the RFC's
     * round-key rotations operate on. `>>> 19` in the RFC rotates the whole 128-bit value
     * right by 19, which across the four words means a 109-bit left rotation -- computed
     * here as a rotate of a 128-bit value held in four words, rather than four independent
     * 32-bit rotates, which would be a different (and wrong) operation. */

    /* 128-bit rotate left, applied to four words at once. The RFC's rotations are on the
     * whole 128-bit round key, not per-word: `W1 >>> 19` shifts every bit of the 128-bit
     * value right by 19, wrapping the low bits around to the top. */
    static inline void rot128Left(const uint32_t in[4], unsigned bits, uint32_t out[4]) {
        const unsigned shift = bits % 128;
        const unsigned wordShift = shift / 32;
        const unsigned bitShift = shift % 32;

        for (unsigned j = 0; j < 4; ++j) {
            const uint32_t lo = in[(j + wordShift) % 4];
            // The spill bits come from the word ABOVE the one supplying the low half --
            // (j + wordShift + 1), not + 3. Using + 3 produces a rotation whose words are
            // individually right but collectively permuted, which yields round keys that
            // are wrong in every position and match nothing.
            const uint32_t hi = in[(j + wordShift + 1) % 4];
            out[j] = (bitShift == 0)
                ? lo
                : uint32_t((lo << bitShift) | (hi >> (32 - bitShift)));
        }
    }

    /* 128-bit rotate right, four words at once. */
    static inline void rot128Right(const uint32_t in[4], unsigned bits, uint32_t out[4]) {
        rot128Left(in, 128 - (bits % 128), out);
    }

    bool AriaCore::expandKey(const uint8_t* key, size_t keyBytes, uint8_t* roundKeys, uint32_t& nr) {
        if (!key || !roundKeys || (keyBytes != 16 && keyBytes != 24 && keyBytes != 32)) {
            nr = 0;
            return false;
        }

        // A mistranscribed S-box table would produce an ARIA that is self-consistent and
        // wrong -- the one failure mode this class cannot detect from its own output. Cheap
        // to check and paid once per key expansion, so it can never ship.
        if (!selfCheckTables()) {
            nr = 0;
            return false;
        }

        // KL || KR = K || 0...0, with the pad making KR 128 bits for every key size: 128
        // zero bits for a 128-bit key (so KR is entirely zero), 64 for 192, none for 256.
        // Kept as byte strings, in the RFC's order, for the whole schedule.
        uint8_t w[4][16];
        std::memset(w, 0, sizeof(w));
        std::memcpy(w[0], key, 16);
        if (keyBytes > 16) {
            std::memcpy(w[1], key + 16, keyBytes - 16);
        }

        // CK1/CK2/CK3 are C1,C2,C3 for a 128-bit key; C2,C3,C1 for 192; C3,C1,C2 for 256.
        // Stored as sixteen big-endian bytes each, which is the order the round functions
        // consume -- reinterpreting the word arrays as bytes would reverse every constant on
        // a little-endian machine and still produce a self-consistent ARIA that matched
        // nothing.
        uint8_t ck[3][16];
        {
            const uint32_t* src[3] = { C1, C2, C3 };
            if (keyBytes == 24) {
                src[0] = C2; src[1] = C3; src[2] = C1;
            } else if (keyBytes == 32) {
                src[0] = C3; src[1] = C1; src[2] = C2;
            }

            for (size_t k = 0; k < 3; ++k) {
                for (size_t i = 0; i < 4; ++i) {
                    const uint32_t word = src[k][i];
                    ck[k][4 * i + 0] = uint8_t(word >> 24);
                    ck[k][4 * i + 1] = uint8_t(word >> 16);
                    ck[k][4 * i + 2] = uint8_t(word >> 8);
                    ck[k][4 * i + 3] = uint8_t(word);
                }
            }
        }

        scheduleWords(w, ck);

        // The words exist only for the rotations. Loaded once here from the byte values,
        // so every round key below reads the same big-endian interpretation.
        uint32_t ww[4][4];
        for (size_t k = 0; k < 4; ++k) {
            for (size_t i = 0; i < 4; ++i) {
                const uint8_t* p = w[k] + 4 * i;
                ww[k][i] = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
                         | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
            }
        }

        // The seventeen round keys, in the RFC's order. Each is W_a ^ (W_b >>> shift), with
        // the shift from { 19, 31, 61 } and the pair rotating (0,1), (1,2), (2,3), (3,0).
        // The RFC lists all seventeen explicitly, so they are stated explicitly here too --
        // a mis-transcribed table would be undetectable from the output.
        struct Spec {
            uint32_t a;
            uint32_t b;
            unsigned shift;
            bool rotateRight;
        };

        static const Spec SCHEDULE[17] = {
            { 0, 1, 19, true },   // ek1  = W0 ^ (W1 >>> 19)
            { 1, 2, 19, true },   // ek2  = W1 ^ (W2 >>> 19)
            { 2, 3, 19, true },   // ek3  = W2 ^ (W3 >>> 19)
            { 3, 0, 19, true },   // ek4  = W3 ^ (W0 >>> 19)
            { 0, 1, 31, true },   // ek5  = W0 ^ (W1 >>> 31)
            { 1, 2, 31, true },   // ek6
            { 2, 3, 31, true },   // ek7
            { 3, 0, 31, true },   // ek8
            { 0, 1, 61, false },  // ek9  = W0 ^ (W1 <<< 61)
            { 1, 2, 61, false },  // ek10
            { 2, 3, 61, false },  // ek11
            { 3, 0, 61, false },  // ek12
            { 0, 1, 31, false },  // ek13 = W0 ^ (W1 <<< 31)
            { 1, 2, 31, false },  // ek14
            { 2, 3, 31, false },  // ek15
            { 3, 0, 31, false },  // ek16 = (W0 <<< 31) ^ W3
            { 0, 1, 19, false },  // ek17 = W0 ^ (W1 <<< 19) -- note <<< , not >>>
        };

        nr = (keyBytes == 16) ? 12 : (keyBytes == 24) ? 14 : 16;

        for (uint32_t k = 0; k <= nr; ++k) {
            const Spec& s = SCHEDULE[k];

            uint32_t rotated[4];
            if (s.rotateRight) {
                rot128Right(ww[s.b], s.shift, rotated);
            } else {
                rot128Left(ww[s.b], s.shift, rotated);
            }

            for (size_t i = 0; i < 4; ++i) {
                const uint32_t word = ww[s.a][i] ^ rotated[i];
                roundKeys[k * 16 + 4 * i + 0] = uint8_t(word >> 24);
                roundKeys[k * 16 + 4 * i + 1] = uint8_t(word >> 16);
                roundKeys[k * 16 + 4 * i + 2] = uint8_t(word >> 8);
                roundKeys[k * 16 + 4 * i + 3] = uint8_t(word);
            }
        }

        return true;
    }

    bool AriaCore::expandKey(const uint8_t* key, size_t keyBytes, TArray<uint8_t>& roundKeys, uint32_t& nr) {
        const uint32_t rounds = (keyBytes == 16) ? 12 : (keyBytes == 24) ? 14 : (keyBytes == 32) ? 16 : 0;
        if (rounds == 0) {
            nr = 0;
            return false;
        }

        roundKeys.resize(16 * (rounds + 1));
        if (!expandKey(key, keyBytes, roundKeys.begin(), nr)) {
            roundKeys.clear();
            return false;
        }
        return true;
    }

    void AriaCore::encryptBlock(const uint8_t in[16], uint8_t out[16], const uint8_t* roundKeys, uint32_t nr) {
        uint8_t d[16];
        std::memcpy(d, in, 16);

        // Rounds 1..n-1 alternate FO (SL1) and FE (SL2). Round 1 is FO, so the loop index
        // being even means FO. The RFC's round numbering is 1-based, the array is 0-based.
        for (uint32_t r = 0; r + 1 < nr; ++r) {
            if ((r % 2) == 0) {
                roundOdd(d, roundKeys + r * 16);
            } else {
                roundEven(d, roundKeys + r * 16);
            }
        }

        // The final round is different from the others -- it has an extra key addition
        // layer and no diffusion:
        //     C = SL2(P{n-1} ^ ek{n}) ^ ek{n+1}
        // where P{n-1} is the output of round n-1. So the last FO/FE pair is replaced by
        // just the substitution layer with key material on both sides of it.
        for (size_t i = 0; i < 16; ++i) {
            d[i] ^= roundKeys[(nr - 1) * 16 + i];
        }
        substitutionLayer2(d);
        for (size_t i = 0; i < 16; ++i) {
            d[i] ^= roundKeys[nr * 16 + i];
        }

        std::memcpy(out, d, 16);
    }

    void AriaCore::decryptBlock(const uint8_t in[16], uint8_t out[16], const uint8_t* roundKeys, uint32_t nr) {
        uint8_t d[16];
        std::memcpy(d, in, 16);

        // Decryption is encryption with the round keys replaced by dk1..dk{n+1}, where
        // dk1 = ek{n+1}, dk{n+1} = ek1, and every interior dk{i} is A(ek{n+2-i}). A is an
        // involution, so no inverse of it is needed -- which is what makes this cheap.
        //
        // Indexed from 0: dk[0] = ek[n], dk[n] = ek[0], and dk[i] = A(ek[n-i]) for
        // 1 <= i <= n-1.
        uint8_t dk[AriaCore::MAX_ROUND_KEY_BYTES];
        std::memcpy(dk, roundKeys + nr * 16, 16);
        std::memcpy(dk + nr * 16, roundKeys, 16);

        for (uint32_t i = 1; i < nr; ++i) {
            uint8_t t[16];
            std::memcpy(t, roundKeys + (nr - i) * 16, 16);
            diffusionLayer(t);
            std::memcpy(dk + i * 16, t, 16);
        }

        // Rounds 1..n-1, then the final round's extra key addition layer.
        for (uint32_t r = 0; r + 1 < nr; ++r) {
            if ((r % 2) == 0) {
                roundOdd(d, dk + r * 16);
            } else {
                roundEven(d, dk + r * 16);
            }
        }

        for (size_t i = 0; i < 16; ++i) {
            d[i] ^= dk[(nr - 1) * 16 + i];
        }
        substitutionLayer2(d);
        for (size_t i = 0; i < 16; ++i) {
            d[i] ^= dk[nr * 16 + i];
        }

        std::memcpy(out, d, 16);
    }

} // namespace crypto
} // namespace certpp

