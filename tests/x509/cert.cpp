#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <certpp/asn1/decoder.hpp>

using namespace certpp;
using namespace certpp::x509;
using namespace certpp::crypto;
using namespace certpp::asn1;

namespace {
    // A self-signed RSA-1024/SHA-256 leaf certificate (openssl req -x509 -newkey rsa:1024 ...),
    // Subject/Issuer "C=US, ST=California, L=San Francisco, O=libcertpp, OU=Test,
    // CN=test.libcertpp.local", validity 2026-09-27..2036-09-24.
    constexpr uint8_t RSA_CERT_DER[] = {
        0x30, 0x82, 0x02, 0xd4, 0x30, 0x82, 0x02, 0x3d, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x6f, 0x61, 0x23, 0x1a, 0x98, 0xf0, 0xa7, 0xe1, 0xf4,
        0x2b, 0x53, 0x47, 0xca, 0x4c, 0xa7, 0x98, 0x22, 0x7c, 0xa8, 0xae, 0x30,
        0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00, 0x30, 0x7c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
        0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
        0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e,
        0x69, 0x61, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c,
        0x0d, 0x53, 0x61, 0x6e, 0x20, 0x46, 0x72, 0x61, 0x6e, 0x63, 0x69, 0x73,
        0x63, 0x6f, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
        0x09, 0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70, 0x70, 0x31, 0x0d,
        0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x04, 0x54, 0x65, 0x73,
        0x74, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14,
        0x74, 0x65, 0x73, 0x74, 0x2e, 0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74,
        0x70, 0x70, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x30, 0x1e, 0x17, 0x0d,
        0x32, 0x36, 0x30, 0x39, 0x32, 0x37, 0x31, 0x35, 0x32, 0x32, 0x35, 0x36,
        0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x39, 0x32, 0x34, 0x31, 0x35, 0x32,
        0x32, 0x35, 0x36, 0x5a, 0x30, 0x7c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06,
        0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f,
        0x72, 0x6e, 0x69, 0x61, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04,
        0x07, 0x0c, 0x0d, 0x53, 0x61, 0x6e, 0x20, 0x46, 0x72, 0x61, 0x6e, 0x63,
        0x69, 0x73, 0x63, 0x6f, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04,
        0x0a, 0x0c, 0x09, 0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70, 0x70,
        0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x04, 0x54,
        0x65, 0x73, 0x74, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x14, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x6c, 0x69, 0x62, 0x63, 0x65,
        0x72, 0x74, 0x70, 0x70, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x30, 0x81,
        0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02,
        0x81, 0x81, 0x00, 0xa6, 0xfc, 0xe7, 0x35, 0x6b, 0x3a, 0xb9, 0xa2, 0xd2,
        0x86, 0x0c, 0x23, 0xa8, 0x20, 0x82, 0xa8, 0x48, 0xde, 0xa2, 0x88, 0x9e,
        0xb2, 0x4a, 0xdd, 0xd8, 0x74, 0x07, 0xa2, 0xd9, 0x59, 0x6b, 0x80, 0x06,
        0x1c, 0x01, 0xad, 0x1f, 0x20, 0xb7, 0xcc, 0x39, 0xb1, 0x7a, 0xcb, 0x61,
        0x08, 0xac, 0xbd, 0x8d, 0xe3, 0x67, 0x70, 0x40, 0x3b, 0x72, 0x36, 0x2c,
        0xdc, 0xb3, 0x80, 0xcb, 0x49, 0x79, 0x5a, 0x41, 0x0b, 0x37, 0x7f, 0x04,
        0x89, 0x63, 0xf6, 0xcb, 0x3c, 0x47, 0x1f, 0x1b, 0x71, 0x73, 0x50, 0x92,
        0x53, 0xb1, 0xd5, 0x2f, 0xcf, 0xfe, 0x0d, 0x54, 0x2d, 0x5b, 0xe4, 0x10,
        0x1b, 0xd0, 0x38, 0xef, 0xf1, 0x85, 0xdf, 0x3f, 0x30, 0x8d, 0xf4, 0x81,
        0xcb, 0x64, 0x83, 0xcd, 0x37, 0x53, 0xb9, 0xb4, 0x38, 0x9a, 0x2c, 0xb6,
        0xbe, 0x2a, 0xd1, 0xc4, 0x79, 0x83, 0x99, 0x5c, 0xd8, 0xbb, 0x8b, 0x02,
        0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03,
        0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x72, 0x92, 0xc7, 0x0c, 0xff,
        0xef, 0xb8, 0x2a, 0xb3, 0x8c, 0x28, 0xba, 0x7e, 0x81, 0xa1, 0xf0, 0x75,
        0x7c, 0x72, 0xfa, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
        0x30, 0x16, 0x80, 0x14, 0x72, 0x92, 0xc7, 0x0c, 0xff, 0xef, 0xb8, 0x2a,
        0xb3, 0x8c, 0x28, 0xba, 0x7e, 0x81, 0xa1, 0xf0, 0x75, 0x7c, 0x72, 0xfa,
        0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05,
        0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00,
        0x4a, 0x49, 0x12, 0xfb, 0x00, 0x29, 0x34, 0x1e, 0x1f, 0x4f, 0x8a, 0x2a,
        0x11, 0x6f, 0x51, 0xc3, 0x60, 0x3e, 0x73, 0xf0, 0xf0, 0xf9, 0xd4, 0xb9,
        0x31, 0xb3, 0xb6, 0x7d, 0x02, 0xc7, 0xa1, 0x49, 0x8b, 0xbe, 0x5c, 0x6d,
        0x2d, 0x31, 0x71, 0x51, 0x4b, 0xc3, 0x66, 0x7d, 0x82, 0x0f, 0xa1, 0x8e,
        0x17, 0xa1, 0x49, 0xf2, 0x4b, 0x0b, 0xea, 0xb5, 0xb3, 0x05, 0x60, 0x67,
        0xcc, 0x26, 0x3b, 0xfb, 0x70, 0xbd, 0xbe, 0x76, 0xb2, 0x1a, 0x74, 0x29,
        0x50, 0x79, 0xf6, 0xd3, 0xc5, 0x81, 0x70, 0x16, 0xc8, 0xa0, 0x7e, 0x56,
        0x4a, 0x58, 0x34, 0xb0, 0x5f, 0x0b, 0x6c, 0x5e, 0x3c, 0x9b, 0xf0, 0x91,
        0x65, 0x8e, 0x2b, 0xba, 0x9a, 0x2b, 0x8e, 0xc5, 0x14, 0x7e, 0xb7, 0x0c,
        0x65, 0x8a, 0x76, 0xad, 0x8f, 0x82, 0x38, 0x4d, 0x23, 0x18, 0xa1, 0x64,
        0xb8, 0x73, 0x1c, 0x7e, 0x23, 0x4e, 0x5b, 0xe6,
    };

    constexpr uint8_t RSA_CERT_SERIAL[] = {
        0x6f, 0x61, 0x23, 0x1a, 0x98, 0xf0, 0xa7, 0xe1, 0xf4, 0x2b, 0x53, 0x47,
        0xca, 0x4c, 0xa7, 0x98, 0x22, 0x7c, 0xa8, 0xae,
    };

    constexpr uint8_t RSA_CERT_SHA1_THUMBPRINT[] = {
        0x91, 0xd2, 0x43, 0x07, 0x66, 0x8f, 0xcd, 0x26, 0x3a, 0x50,
        0x6a, 0x1d, 0x35, 0xab, 0x65, 0x7e, 0x14, 0xd3, 0xb2, 0xb7,
    };

    // A self-signed EC (P-256)/SHA-256 leaf certificate, Subject/Issuer
    // "C=KR, O=libcertpp, CN=ec.libcertpp.local", same validity window as above.
    constexpr uint8_t EC_CERT_DER[] = {
        0x30, 0x82, 0x01, 0xd2, 0x30, 0x82, 0x01, 0x77, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x59, 0xb1, 0x69, 0x9c, 0xca, 0xcc, 0x87, 0x82, 0xaf,
        0x74, 0x49, 0x11, 0x5e, 0xc8, 0x99, 0xf5, 0xad, 0x09, 0xda, 0x78, 0x30,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
        0x3e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x4b, 0x52, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
        0x09, 0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70, 0x70, 0x31, 0x1b,
        0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x65, 0x63, 0x2e,
        0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70, 0x70, 0x2e, 0x6c, 0x6f,
        0x63, 0x61, 0x6c, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32,
        0x37, 0x31, 0x35, 0x32, 0x33, 0x30, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36,
        0x30, 0x39, 0x32, 0x34, 0x31, 0x35, 0x32, 0x33, 0x30, 0x32, 0x5a, 0x30,
        0x3e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x4b, 0x52, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
        0x09, 0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70, 0x70, 0x31, 0x1b,
        0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x65, 0x63, 0x2e,
        0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70, 0x70, 0x2e, 0x6c, 0x6f,
        0x63, 0x61, 0x6c, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
        0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xe8, 0x6a, 0x84, 0xe6, 0xa2, 0xd7,
        0x92, 0xff, 0x27, 0xef, 0x6f, 0x29, 0xa9, 0xfd, 0x34, 0xae, 0xa1, 0x4f,
        0x99, 0xb9, 0x60, 0xec, 0xff, 0x63, 0x2b, 0xf7, 0x72, 0x39, 0xc7, 0x72,
        0x5b, 0xc9, 0xa3, 0x19, 0xaf, 0x75, 0xb4, 0x25, 0xea, 0x72, 0x6f, 0x73,
        0x2a, 0x83, 0x6a, 0x41, 0x91, 0x3f, 0x8d, 0x5c, 0x9a, 0xf0, 0x5b, 0x6e,
        0x5f, 0x21, 0x74, 0x39, 0x01, 0x12, 0x36, 0xbf, 0x1c, 0x00, 0xa3, 0x53,
        0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
        0x14, 0x34, 0x64, 0x79, 0x05, 0x64, 0x40, 0x8b, 0xe6, 0x8b, 0xee, 0x07,
        0x0b, 0x0a, 0xa5, 0x60, 0xf8, 0xa3, 0x6b, 0x5a, 0xd0, 0x30, 0x1f, 0x06,
        0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x34, 0x64,
        0x79, 0x05, 0x64, 0x40, 0x8b, 0xe6, 0x8b, 0xee, 0x07, 0x0b, 0x0a, 0xa5,
        0x60, 0xf8, 0xa3, 0x6b, 0x5a, 0xd0, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
        0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03,
        0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0x88, 0x7e, 0x98, 0xfe, 0xea,
        0xb5, 0x1d, 0xff, 0x9f, 0xdb, 0x68, 0x3f, 0x86, 0x8f, 0x50, 0x41, 0x79,
        0x74, 0xb9, 0xa0, 0xb7, 0x8c, 0x4c, 0xb8, 0xec, 0x6a, 0x99, 0x6f, 0x5c,
        0x5c, 0xf2, 0xfa, 0x02, 0x21, 0x00, 0x8d, 0x13, 0x11, 0xa6, 0x64, 0x39,
        0x42, 0x46, 0x2a, 0x72, 0x95, 0x65, 0xd5, 0xbc, 0x70, 0xef, 0xd0, 0x43,
        0x07, 0xf3, 0x55, 0xcd, 0x3f, 0x6f, 0xcf, 0xeb, 0xf8, 0x06, 0x99, 0x6a,
        0x92, 0x22,
    };

    constexpr uint8_t EC_CERT_SERIAL[] = {
        0x59, 0xb1, 0x69, 0x9c, 0xca, 0xcc, 0x87, 0x82, 0xaf, 0x74, 0x49, 0x11,
        0x5e, 0xc8, 0x99, 0xf5, 0xad, 0x09, 0xda, 0x78,
    };

    // A self-signed RSA-1024/SHA-256 leaf certificate with an explicit, critical KeyUsage
    // extension (openssl req -x509 ... -addext "keyUsage=critical,digitalSignature,
    // keyCertSign,cRLSign"): Subject/Issuer "C=US, O=libcertpp, CN=keyusage.libcertpp.local".
    constexpr uint8_t KU_CERT_DER[] = {
        0x30, 0x82, 0x02, 0x74, 0x30, 0x82, 0x01, 0xdd, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x56, 0x76, 0xd1, 0x47, 0x92, 0xc2, 0x74, 0x8b, 0x12,
        0x8f, 0x4e, 0x94, 0xb7, 0x8a, 0x44, 0x0c, 0x27, 0x43, 0x39, 0x88, 0x30,
        0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00, 0x30, 0x44, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
        0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
        0x04, 0x0a, 0x0c, 0x09, 0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70,
        0x70, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x18,
        0x6b, 0x65, 0x79, 0x75, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x6c, 0x69, 0x62,
        0x63, 0x65, 0x72, 0x74, 0x70, 0x70, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
        0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32, 0x37, 0x31, 0x36,
        0x30, 0x35, 0x35, 0x35, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x39, 0x32,
        0x34, 0x31, 0x36, 0x30, 0x35, 0x35, 0x35, 0x5a, 0x30, 0x44, 0x31, 0x0b,
        0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
        0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x6c, 0x69,
        0x62, 0x63, 0x65, 0x72, 0x74, 0x70, 0x70, 0x31, 0x21, 0x30, 0x1f, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0c, 0x18, 0x6b, 0x65, 0x79, 0x75, 0x73, 0x61,
        0x67, 0x65, 0x2e, 0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70, 0x70,
        0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06,
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
        0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xad,
        0x4f, 0x1c, 0xea, 0x34, 0xfa, 0x25, 0x0c, 0x56, 0xa1, 0x20, 0x34, 0x0e,
        0xa7, 0x2d, 0xa4, 0xea, 0xc1, 0x32, 0x9d, 0x67, 0xa4, 0x37, 0x58, 0x51,
        0xd4, 0x0a, 0x7d, 0xe6, 0x25, 0xd6, 0xce, 0x93, 0xd1, 0x64, 0xc4, 0xe3,
        0x2f, 0x8b, 0x4f, 0xfe, 0x7f, 0xbf, 0x28, 0x1c, 0x23, 0x28, 0x84, 0x5b,
        0x47, 0x19, 0xc8, 0x99, 0xd1, 0x28, 0x52, 0x8f, 0xaf, 0xe8, 0xed, 0xe2,
        0x5a, 0x2a, 0x84, 0x1a, 0xed, 0x07, 0x50, 0xa2, 0xb8, 0x2f, 0xa3, 0xfb,
        0xfb, 0xa4, 0xdc, 0xdc, 0x53, 0x5e, 0xf1, 0xc3, 0x53, 0xdc, 0x15, 0x8e,
        0xe8, 0x00, 0xef, 0x5e, 0x61, 0x5c, 0xa0, 0x57, 0xde, 0x7a, 0x8f, 0x60,
        0xd9, 0x2c, 0x4c, 0xc6, 0x73, 0x6a, 0x7d, 0x38, 0xd3, 0x28, 0x4b, 0xd9,
        0x96, 0x09, 0x8d, 0xe1, 0x78, 0x77, 0x25, 0x32, 0x8c, 0x23, 0x3a, 0xa4,
        0x7e, 0xc4, 0x2b, 0x22, 0xbc, 0x49, 0x1d, 0x02, 0x03, 0x01, 0x00, 0x01,
        0xa3, 0x63, 0x30, 0x61, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
        0x16, 0x04, 0x14, 0xed, 0xa8, 0x45, 0xe0, 0x14, 0x59, 0x31, 0xbf, 0x17,
        0x5e, 0xd8, 0x87, 0xd8, 0x1e, 0xee, 0xd4, 0xab, 0x2d, 0x7c, 0xa4, 0x30,
        0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
        0xed, 0xa8, 0x45, 0xe0, 0x14, 0x59, 0x31, 0xbf, 0x17, 0x5e, 0xd8, 0x87,
        0xd8, 0x1e, 0xee, 0xd4, 0xab, 0x2d, 0x7c, 0xa4, 0x30, 0x0f, 0x06, 0x03,
        0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
        0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04,
        0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00,
        0x43, 0x42, 0x02, 0x5a, 0xb4, 0xad, 0xfa, 0x7e, 0x2e, 0x7c, 0x36, 0x55,
        0xc0, 0xc2, 0x2f, 0x94, 0x3d, 0x43, 0xb5, 0x3c, 0x32, 0x4b, 0xb0, 0xe1,
        0xc2, 0xe6, 0x81, 0x8d, 0x6a, 0x2d, 0x08, 0x39, 0x49, 0x00, 0x22, 0x6b,
        0x44, 0xb9, 0x7e, 0xae, 0xa5, 0xbb, 0x27, 0x40, 0xa4, 0x2c, 0x75, 0xa0,
        0xc3, 0xe7, 0x31, 0x05, 0xc1, 0x7d, 0x31, 0xc2, 0xee, 0x6d, 0x4f, 0x26,
        0x98, 0xac, 0x39, 0xc2, 0xd3, 0xdc, 0x4e, 0xb8, 0x59, 0x08, 0x4b, 0xf7,
        0x77, 0x51, 0x3a, 0x2f, 0x59, 0x8f, 0x09, 0x58, 0x9c, 0xb8, 0x89, 0x38,
        0xb1, 0x5e, 0x4f, 0xdc, 0x6f, 0xb8, 0x1d, 0x7d, 0x7b, 0xcc, 0x97, 0x7d,
        0xff, 0xb6, 0xd8, 0xbc, 0x03, 0xe5, 0xb9, 0xf4, 0xfd, 0x9f, 0xce, 0x38,
        0x5c, 0x59, 0xdc, 0x58, 0x67, 0xce, 0xf6, 0x2d, 0x78, 0x9c, 0x7a, 0x69,
        0xce, 0xf0, 0x15, 0xec, 0xc1, 0x07, 0x5b, 0xae,
    };

    // A self-signed RSA-1024/SHA-256 leaf certificate whose matching private key is embedded
    // below (openssl genrsa -out pk.key 1024; openssl req -x509 -key pk.key ...): Subject/Issuer
    // "C=US, O=libcertpp, CN=privkey.libcertpp.local".
    constexpr uint8_t PK_CERT_DER[] = {
        0x30, 0x82, 0x02, 0x62, 0x30, 0x82, 0x01, 0xcb, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x54, 0xa1, 0xcb, 0x71, 0x4e, 0x9c, 0xcb, 0xa9, 0xfa,
        0x8f, 0x40, 0x10, 0x22, 0x9d, 0xb8, 0x09, 0x6d, 0xdb, 0xf1, 0x28, 0x30,
        0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00, 0x30, 0x43, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
        0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
        0x04, 0x0a, 0x0c, 0x09, 0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70,
        0x70, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17,
        0x70, 0x72, 0x69, 0x76, 0x6b, 0x65, 0x79, 0x2e, 0x6c, 0x69, 0x62, 0x63,
        0x65, 0x72, 0x74, 0x70, 0x70, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x30,
        0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32, 0x37, 0x31, 0x36, 0x34,
        0x31, 0x34, 0x39, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x39, 0x32, 0x34,
        0x31, 0x36, 0x34, 0x31, 0x34, 0x39, 0x5a, 0x30, 0x43, 0x31, 0x0b, 0x30,
        0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x12,
        0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x6c, 0x69, 0x62,
        0x63, 0x65, 0x72, 0x74, 0x70, 0x70, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x17, 0x70, 0x72, 0x69, 0x76, 0x6b, 0x65, 0x79,
        0x2e, 0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70, 0x70, 0x2e, 0x6c,
        0x6f, 0x63, 0x61, 0x6c, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81,
        0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xc4, 0x5b, 0xcf,
        0x59, 0xa5, 0x83, 0xc6, 0xaa, 0x53, 0xee, 0xbd, 0xa9, 0xe8, 0x24, 0xe6,
        0xd7, 0x8c, 0xfd, 0x9c, 0xe7, 0x54, 0x91, 0x37, 0xaf, 0x3c, 0x60, 0x80,
        0x77, 0x37, 0x68, 0x72, 0x75, 0xc9, 0xa2, 0x6b, 0x4d, 0x9b, 0xe8, 0x9b,
        0xc7, 0xaf, 0x0a, 0x40, 0xf6, 0xde, 0xbe, 0x75, 0x6e, 0x82, 0xfc, 0x79,
        0x81, 0x77, 0x00, 0xd4, 0x17, 0x5a, 0x58, 0xdd, 0xfc, 0x43, 0xb8, 0xb8,
        0xab, 0x97, 0xe1, 0x8c, 0x9c, 0xf6, 0x31, 0xbd, 0xda, 0x68, 0x66, 0x95,
        0xff, 0x5e, 0x4c, 0x8a, 0x82, 0x42, 0x18, 0x98, 0xf7, 0x7d, 0x0e, 0xe4,
        0x78, 0x1c, 0xd4, 0xc3, 0xd3, 0xd0, 0x1d, 0xf3, 0x45, 0xa0, 0x3a, 0xf4,
        0x25, 0x09, 0xe3, 0x20, 0x35, 0x6e, 0xee, 0xf4, 0xa1, 0xf6, 0x30, 0x56,
        0x9e, 0x46, 0x34, 0x90, 0x47, 0x4b, 0x91, 0x28, 0xd5, 0x11, 0x42, 0x2f,
        0x17, 0xd0, 0x6c, 0x39, 0x41, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x53,
        0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
        0x14, 0xa0, 0x27, 0x9d, 0x94, 0x41, 0x9e, 0x2f, 0xfc, 0xfd, 0xbb, 0x61,
        0xcd, 0xc4, 0xa3, 0x36, 0xe8, 0xc1, 0x98, 0x74, 0x2b, 0x30, 0x1f, 0x06,
        0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xa0, 0x27,
        0x9d, 0x94, 0x41, 0x9e, 0x2f, 0xfc, 0xfd, 0xbb, 0x61, 0xcd, 0xc4, 0xa3,
        0x36, 0xe8, 0xc1, 0x98, 0x74, 0x2b, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
        0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30,
        0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0xa8, 0xf9, 0xc8, 0x11, 0x26, 0x37,
        0xee, 0x24, 0x78, 0x62, 0xc7, 0x7a, 0x62, 0x8e, 0x6c, 0xc7, 0x9e, 0x91,
        0x19, 0x42, 0xeb, 0x34, 0xdf, 0xd6, 0xaf, 0x3c, 0xec, 0x3d, 0x4b, 0xb1,
        0xf4, 0x8f, 0x16, 0x78, 0x39, 0x43, 0x2f, 0x18, 0xd5, 0x95, 0x45, 0x97,
        0xf5, 0x0a, 0x34, 0x48, 0x83, 0x7b, 0x5a, 0x6d, 0x2b, 0x9f, 0xd7, 0xe7,
        0xdc, 0x42, 0x6f, 0x19, 0x66, 0x36, 0xc9, 0x7c, 0xe3, 0xce, 0x20, 0x2a,
        0x27, 0x9e, 0x2b, 0x5d, 0xa2, 0x12, 0xc1, 0x99, 0xda, 0xd7, 0x01, 0xd8,
        0x36, 0x49, 0x6d, 0xfa, 0xd6, 0xf8, 0xee, 0x6b, 0xa7, 0xc0, 0x0b, 0x30,
        0x3f, 0xe5, 0xea, 0x33, 0x78, 0x83, 0xf3, 0x5f, 0xc7, 0x6a, 0xcd, 0x3a,
        0xd2, 0x5b, 0xc2, 0xb0, 0x4c, 0x3a, 0x44, 0x57, 0xf1, 0x1e, 0xea, 0x3a,
        0xcf, 0x69, 0xfa, 0x43, 0x12, 0x7c, 0xb2, 0xe9, 0x3f, 0x9d, 0x8e, 0x4c,
        0x9f, 0xea,
    };

    // PK_CERT_DER's own private key, PKCS#1 RSAPrivateKey DER (openssl rsa -traditional).
    constexpr uint8_t PK_PRIVATE_KEY_DER[] = {
        0x30, 0x82, 0x02, 0x5e, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xc4,
        0x5b, 0xcf, 0x59, 0xa5, 0x83, 0xc6, 0xaa, 0x53, 0xee, 0xbd, 0xa9, 0xe8,
        0x24, 0xe6, 0xd7, 0x8c, 0xfd, 0x9c, 0xe7, 0x54, 0x91, 0x37, 0xaf, 0x3c,
        0x60, 0x80, 0x77, 0x37, 0x68, 0x72, 0x75, 0xc9, 0xa2, 0x6b, 0x4d, 0x9b,
        0xe8, 0x9b, 0xc7, 0xaf, 0x0a, 0x40, 0xf6, 0xde, 0xbe, 0x75, 0x6e, 0x82,
        0xfc, 0x79, 0x81, 0x77, 0x00, 0xd4, 0x17, 0x5a, 0x58, 0xdd, 0xfc, 0x43,
        0xb8, 0xb8, 0xab, 0x97, 0xe1, 0x8c, 0x9c, 0xf6, 0x31, 0xbd, 0xda, 0x68,
        0x66, 0x95, 0xff, 0x5e, 0x4c, 0x8a, 0x82, 0x42, 0x18, 0x98, 0xf7, 0x7d,
        0x0e, 0xe4, 0x78, 0x1c, 0xd4, 0xc3, 0xd3, 0xd0, 0x1d, 0xf3, 0x45, 0xa0,
        0x3a, 0xf4, 0x25, 0x09, 0xe3, 0x20, 0x35, 0x6e, 0xee, 0xf4, 0xa1, 0xf6,
        0x30, 0x56, 0x9e, 0x46, 0x34, 0x90, 0x47, 0x4b, 0x91, 0x28, 0xd5, 0x11,
        0x42, 0x2f, 0x17, 0xd0, 0x6c, 0x39, 0x41, 0x02, 0x03, 0x01, 0x00, 0x01,
        0x02, 0x81, 0x81, 0x00, 0xbe, 0x1c, 0x95, 0xd9, 0x19, 0xe3, 0x48, 0x09,
        0xc9, 0x51, 0xb0, 0xd8, 0x3c, 0x26, 0xde, 0x49, 0x7b, 0xfc, 0x60, 0x59,
        0xa9, 0x0b, 0x20, 0x7a, 0xcd, 0x5e, 0x31, 0x83, 0x3b, 0x66, 0x28, 0xcb,
        0xd9, 0xf9, 0x23, 0x22, 0xf4, 0xfc, 0x75, 0x37, 0x14, 0x46, 0x3d, 0x37,
        0xc7, 0xd9, 0x67, 0x21, 0x24, 0x39, 0x05, 0xfb, 0x4f, 0x18, 0xc2, 0x40,
        0x09, 0xfd, 0x58, 0x8f, 0xd1, 0x91, 0x9b, 0x58, 0xf2, 0x8e, 0x90, 0x38,
        0xa8, 0x4f, 0xca, 0xab, 0x52, 0xf8, 0x81, 0xb5, 0xcc, 0xf7, 0xba, 0x6a,
        0xb4, 0xba, 0xa6, 0x45, 0xe4, 0xfd, 0xec, 0x7a, 0xaf, 0xc0, 0xe5, 0x82,
        0xd9, 0xc4, 0xde, 0x64, 0x57, 0xa7, 0x44, 0x02, 0x69, 0x00, 0x9a, 0x7d,
        0x26, 0x55, 0xd6, 0xe0, 0xe9, 0x54, 0x42, 0xe7, 0x7d, 0xd8, 0x03, 0xf7,
        0xe8, 0xf7, 0xa9, 0xd9, 0x14, 0x79, 0x4f, 0x91, 0x7d, 0x5d, 0xd9, 0x01,
        0x02, 0x41, 0x00, 0xfb, 0xe8, 0x3d, 0xea, 0x56, 0x25, 0x0e, 0x8e, 0x86,
        0x94, 0x4a, 0x6d, 0x47, 0x65, 0xf1, 0xcc, 0x95, 0x94, 0xb3, 0x5b, 0xb0,
        0x74, 0x10, 0x76, 0x49, 0xc8, 0x01, 0x84, 0x15, 0x32, 0x69, 0x8d, 0x7d,
        0xc3, 0x04, 0x3c, 0x19, 0x3a, 0x31, 0x5c, 0xad, 0x4c, 0x54, 0xf1, 0xd9,
        0xaa, 0x95, 0x48, 0xb6, 0xda, 0xb3, 0x9e, 0xa7, 0x10, 0x0f, 0x76, 0xfe,
        0xa2, 0x24, 0xd2, 0x84, 0xdf, 0x90, 0x09, 0x02, 0x41, 0x00, 0xc7, 0x8c,
        0x86, 0x5c, 0x8a, 0xbe, 0xce, 0x55, 0x6d, 0xe6, 0xcd, 0xd8, 0x4b, 0xbf,
        0x45, 0x2f, 0x4b, 0x70, 0x46, 0xe3, 0x2a, 0x4d, 0xc7, 0x4d, 0xcd, 0x52,
        0x8d, 0x33, 0xa2, 0xf0, 0x9a, 0xce, 0x02, 0x80, 0x16, 0x9a, 0x3f, 0x07,
        0xe8, 0x83, 0x72, 0x56, 0x17, 0x74, 0x55, 0xb2, 0x01, 0x52, 0xb7, 0x74,
        0xd6, 0x72, 0x23, 0xe2, 0x7b, 0x4e, 0x9e, 0x80, 0x54, 0x13, 0x4f, 0xb7,
        0x3d, 0x79, 0x02, 0x41, 0x00, 0xf4, 0xe3, 0x76, 0x65, 0x7c, 0x2f, 0x74,
        0x32, 0x4c, 0x54, 0x96, 0xf2, 0x1b, 0x69, 0xd8, 0xa1, 0xf9, 0x7c, 0x60,
        0xcc, 0xaf, 0x02, 0x76, 0x0a, 0x78, 0x79, 0x8e, 0x37, 0xb8, 0x5f, 0x94,
        0xcb, 0x6f, 0x4a, 0x09, 0xb0, 0xdf, 0x19, 0x7a, 0x69, 0x4d, 0x33, 0x9a,
        0x94, 0xae, 0xf5, 0x2d, 0x41, 0x4e, 0x39, 0xd8, 0x4a, 0x50, 0xc0, 0xc5,
        0x37, 0xfa, 0x1c, 0xe8, 0xcd, 0x1b, 0x4d, 0x36, 0xf9, 0x02, 0x40, 0x57,
        0x18, 0x22, 0x5c, 0xa9, 0xc1, 0xf5, 0xd4, 0x9b, 0x8f, 0x2d, 0x30, 0xc6,
        0x7e, 0xc8, 0xf7, 0x87, 0x79, 0x8d, 0xb7, 0x00, 0x73, 0xca, 0x15, 0x4f,
        0x14, 0x44, 0xc4, 0xd0, 0xcd, 0x2b, 0x03, 0xd7, 0x5b, 0x88, 0x81, 0xf2,
        0x18, 0xc5, 0x86, 0xf9, 0x94, 0x51, 0xd0, 0x58, 0xc6, 0xc4, 0x85, 0x11,
        0xc5, 0x51, 0x03, 0xa8, 0x5d, 0xe5, 0x6b, 0xbf, 0x0a, 0x4b, 0xa7, 0xd2,
        0x17, 0x2c, 0x21, 0x02, 0x41, 0x00, 0xbb, 0x28, 0x81, 0x34, 0x5c, 0x9b,
        0x76, 0x04, 0xd8, 0x51, 0x12, 0xe2, 0xb2, 0x8a, 0xc2, 0x11, 0xfd, 0xae,
        0xa7, 0xbe, 0x5c, 0x1a, 0x8a, 0x69, 0x4e, 0xbb, 0x1b, 0xf8, 0xa8, 0xd4,
        0xce, 0x32, 0xa0, 0x32, 0x8e, 0xd8, 0x21, 0x60, 0x8d, 0xfc, 0xc7, 0x06,
        0x76, 0x26, 0xff, 0xcf, 0x50, 0xba, 0xbc, 0xb5, 0x93, 0x8c, 0x4a, 0x48,
        0x5a, 0xfe, 0x89, 0x67, 0x8a, 0x39, 0xc4, 0x5c, 0xec, 0x7b,
    };

    // An unrelated RSA private key (not PK_CERT_DER's own), PKCS#1 DER, for the
    // wrong-key-rejected test.
    constexpr uint8_t OTHER_PRIVATE_KEY_DER[] = {
        0x30, 0x82, 0x02, 0x5c, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xc1,
        0xc5, 0xf5, 0xa0, 0x60, 0x14, 0x31, 0x87, 0x26, 0xcb, 0xd9, 0x46, 0xb5,
        0x6f, 0xc1, 0xb7, 0xe1, 0xcb, 0x07, 0x8c, 0xb7, 0x75, 0xf8, 0xa5, 0x09,
        0xac, 0x76, 0xa2, 0x60, 0xd2, 0x2c, 0x67, 0x4d, 0xa5, 0xea, 0xf6, 0x38,
        0x1e, 0x28, 0xe8, 0xbc, 0x13, 0x2d, 0x20, 0x04, 0xa6, 0xb6, 0x5a, 0x45,
        0xc1, 0xa5, 0xff, 0x1b, 0x7e, 0xb8, 0x5f, 0x98, 0x27, 0xef, 0x18, 0x9e,
        0xf5, 0x4f, 0x96, 0x19, 0x00, 0xa6, 0xb0, 0xfa, 0x16, 0x8d, 0xb4, 0x3a,
        0x57, 0x74, 0x05, 0xee, 0x2b, 0x85, 0xc0, 0xb0, 0xc4, 0x4a, 0x90, 0xb3,
        0xb5, 0xe7, 0xea, 0xf2, 0x08, 0x61, 0xd3, 0x5b, 0x70, 0xfa, 0xd8, 0xec,
        0x1b, 0x54, 0xc1, 0x3c, 0xe9, 0xac, 0xa3, 0x1b, 0x9b, 0xca, 0x8d, 0xad,
        0x44, 0x10, 0xb9, 0x42, 0x9f, 0x63, 0x39, 0x49, 0x92, 0x2a, 0x3b, 0x6b,
        0x9b, 0xd2, 0x78, 0x51, 0x8c, 0x19, 0x19, 0x02, 0x03, 0x01, 0x00, 0x01,
        0x02, 0x7f, 0x48, 0xa9, 0xf3, 0x72, 0x30, 0x95, 0x61, 0xfd, 0x4c, 0x8f,
        0x24, 0xeb, 0x5f, 0x1e, 0x89, 0x86, 0x6b, 0x25, 0xb7, 0xaf, 0x0d, 0x1d,
        0x30, 0x20, 0xb3, 0x7f, 0xf8, 0xfc, 0xeb, 0x51, 0xe5, 0x54, 0xd7, 0xc9,
        0x60, 0x52, 0xf4, 0xb8, 0x5a, 0x9e, 0xeb, 0xe8, 0x45, 0x03, 0xbc, 0xba,
        0xc7, 0xa7, 0x12, 0x81, 0x8b, 0xbe, 0x1e, 0x91, 0x66, 0x92, 0x72, 0x7c,
        0x87, 0x2c, 0xb4, 0x6f, 0x49, 0x68, 0x57, 0x4d, 0xcd, 0x7c, 0x35, 0x0b,
        0x6d, 0x27, 0x2b, 0x87, 0x6a, 0x87, 0x00, 0xd2, 0xb3, 0x4b, 0xaa, 0x45,
        0xb0, 0xbd, 0xa6, 0xef, 0x69, 0xa0, 0x2c, 0x56, 0x89, 0x81, 0xd5, 0xad,
        0x44, 0x64, 0x0f, 0xfd, 0x58, 0xdb, 0x8a, 0x1c, 0xf9, 0xa8, 0xd5, 0x56,
        0x3a, 0xbb, 0x2b, 0x34, 0xe9, 0xa1, 0x70, 0xae, 0x3f, 0x3b, 0xe6, 0xcf,
        0xdc, 0xe6, 0x3c, 0xf7, 0xe6, 0xc4, 0xf3, 0x2d, 0x81, 0x02, 0x41, 0x00,
        0xff, 0xfe, 0x86, 0xb2, 0x20, 0xc2, 0xe3, 0x74, 0xb9, 0xcb, 0xb5, 0x2c,
        0xcb, 0x26, 0x86, 0x80, 0x6a, 0xd0, 0xa8, 0x7a, 0xac, 0x91, 0xa3, 0xff,
        0x84, 0xbd, 0xd6, 0x78, 0x24, 0x54, 0x35, 0xa6, 0x1c, 0x78, 0x03, 0x55,
        0xec, 0xbd, 0x26, 0xf1, 0x72, 0x6f, 0x78, 0x80, 0x89, 0x60, 0xab, 0x1f,
        0xb7, 0xa5, 0x7c, 0x70, 0xca, 0x7b, 0x7b, 0xac, 0x39, 0x5e, 0x1d, 0xa9,
        0xba, 0x36, 0x85, 0xeb, 0x02, 0x41, 0x00, 0xc1, 0xc7, 0x13, 0x39, 0x7d,
        0x3f, 0x4f, 0x0d, 0xe9, 0x64, 0xd9, 0x5d, 0x5a, 0x15, 0xc9, 0x99, 0xf7,
        0x1a, 0xaf, 0x62, 0x72, 0xac, 0x17, 0xc1, 0xdd, 0x63, 0x51, 0x1a, 0x39,
        0x49, 0xd5, 0x04, 0x99, 0x4a, 0x39, 0xd3, 0x9d, 0x95, 0xd0, 0xf7, 0x81,
        0x2e, 0xd1, 0xde, 0xbe, 0xb8, 0x83, 0x5d, 0xef, 0x7a, 0xbc, 0x58, 0x19,
        0xa1, 0xf9, 0xfe, 0xed, 0x42, 0xaa, 0xd6, 0xfc, 0xcf, 0x08, 0x0b, 0x02,
        0x41, 0x00, 0x90, 0xe1, 0x99, 0x94, 0x08, 0xcc, 0xa3, 0xf4, 0xb5, 0x0e,
        0xa0, 0x7c, 0x38, 0x81, 0x96, 0x4f, 0xe9, 0xa4, 0x2c, 0x26, 0x39, 0xb2,
        0xb7, 0xb1, 0x6e, 0x8c, 0x0e, 0x6c, 0xb2, 0x8a, 0xe2, 0x4e, 0x20, 0x00,
        0xa0, 0x4a, 0xaa, 0x10, 0xa7, 0x90, 0xb0, 0xe6, 0x7b, 0xb9, 0xab, 0x86,
        0x85, 0x73, 0x0e, 0xf9, 0xde, 0xc2, 0xeb, 0x26, 0x15, 0xe9, 0x74, 0x12,
        0x5b, 0x11, 0x6b, 0x2d, 0x5e, 0x7f, 0x02, 0x41, 0x00, 0x83, 0x09, 0xba,
        0x48, 0x60, 0x18, 0x15, 0xbf, 0x94, 0x9a, 0xec, 0x1a, 0xa2, 0xb6, 0xa5,
        0x14, 0x06, 0xf3, 0xf6, 0xb2, 0x1e, 0x55, 0x9d, 0xe3, 0x2d, 0x70, 0xe2,
        0x01, 0x57, 0xc8, 0x43, 0xd2, 0xce, 0x4e, 0x51, 0x78, 0x76, 0xd2, 0x3e,
        0xf3, 0x80, 0x5a, 0x46, 0xf5, 0xd8, 0x07, 0x32, 0x5e, 0xad, 0x79, 0x54,
        0x30, 0x47, 0x75, 0x2f, 0x77, 0x62, 0xbe, 0x78, 0x84, 0xd5, 0x84, 0xb3,
        0x2d, 0x02, 0x41, 0x00, 0xab, 0x36, 0x17, 0x1a, 0xfe, 0x03, 0xb2, 0x2f,
        0x97, 0x6c, 0x4a, 0x0b, 0x97, 0x56, 0x0f, 0xae, 0xc9, 0xef, 0x99, 0xf6,
        0xc6, 0x9a, 0x5a, 0x41, 0xd1, 0x19, 0x6b, 0xe7, 0x11, 0x5c, 0xad, 0x67,
        0x39, 0x8f, 0xb5, 0xfe, 0xed, 0x72, 0x66, 0x9d, 0x72, 0x3a, 0xbc, 0xfd,
        0x8b, 0x75, 0x17, 0x8b, 0x78, 0x77, 0x0f, 0x57, 0xc3, 0xb7, 0x05, 0xa0,
        0xdd, 0x4b, 0xd3, 0x44, 0x9d, 0xbf, 0xc9, 0x1a,
    };

    // A self-signed RSA-1024/SHA-256 CA certificate with an explicit, critical NameConstraints
    // extension (openssl req -x509 ... -addext "basicConstraints=critical,CA:TRUE" -addext
    // "nameConstraints=critical,permitted;DNS:libcertpp.local,excluded;DNS:evil.libcertpp.local"):
    // Subject/Issuer "C=US, O=libcertpp, CN=nc.libcertpp.local".
    constexpr uint8_t NC_CERT_DER[] = {
        0x30, 0x82, 0x02, 0x97, 0x30, 0x82, 0x02, 0x00, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x49, 0x83, 0x9c, 0xea, 0xd2, 0x3a, 0xa4, 0xb2, 0xa4,
        0x4d, 0xe4, 0xec, 0xcf, 0xdc, 0xd4, 0x10, 0xb5, 0x4d, 0x74, 0x87, 0x30,
        0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00, 0x30, 0x3e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
        0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
        0x04, 0x0a, 0x0c, 0x09, 0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70,
        0x70, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12,
        0x6e, 0x63, 0x2e, 0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70, 0x70,
        0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36,
        0x30, 0x39, 0x32, 0x38, 0x30, 0x32, 0x31, 0x36, 0x31, 0x38, 0x5a, 0x17,
        0x0d, 0x33, 0x36, 0x30, 0x39, 0x32, 0x35, 0x30, 0x32, 0x31, 0x36, 0x31,
        0x38, 0x5a, 0x30, 0x3e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
        0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
        0x04, 0x0a, 0x0c, 0x09, 0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70,
        0x70, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12,
        0x6e, 0x63, 0x2e, 0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70, 0x70,
        0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06,
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
        0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xde,
        0xe4, 0x77, 0x50, 0x50, 0x21, 0xb8, 0x5f, 0x09, 0x8a, 0x37, 0xc4, 0x8f,
        0x42, 0x1b, 0x99, 0x62, 0x19, 0x67, 0x4c, 0xa7, 0x90, 0x19, 0xfe, 0xd4,
        0x55, 0xd2, 0xa3, 0xb2, 0x2c, 0x6b, 0x1b, 0x01, 0x6e, 0x03, 0xe6, 0xbd,
        0x25, 0x47, 0x53, 0x57, 0x49, 0x23, 0x11, 0x9b, 0x77, 0x49, 0x55, 0xa9,
        0x90, 0xdb, 0x65, 0xa8, 0x39, 0xe7, 0x73, 0xc8, 0xf2, 0xfe, 0xeb, 0x88,
        0xe7, 0xb0, 0x18, 0x72, 0x7e, 0x13, 0x42, 0x47, 0xbd, 0xbc, 0xe4, 0xab,
        0x94, 0x94, 0x23, 0xdb, 0xbd, 0x83, 0xea, 0x73, 0xe6, 0x83, 0x0d, 0x33,
        0x34, 0xd1, 0x73, 0xcf, 0x0e, 0x89, 0xc4, 0xc5, 0x26, 0x41, 0xf2, 0xfc,
        0x59, 0xe0, 0xe4, 0x9e, 0x7c, 0xb3, 0x66, 0x04, 0x91, 0x7f, 0x58, 0xe4,
        0x4a, 0x2d, 0x5b, 0xed, 0xfc, 0x51, 0x3b, 0x9d, 0x8b, 0xf7, 0xb6, 0x03,
        0x31, 0xfa, 0xcc, 0x9c, 0xaa, 0x01, 0x35, 0x02, 0x03, 0x01, 0x00, 0x01,
        0xa3, 0x81, 0x91, 0x30, 0x81, 0x8e, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
        0x0e, 0x04, 0x16, 0x04, 0x14, 0x5b, 0xb1, 0xd9, 0x6e, 0x9a, 0x9b, 0x58,
        0x38, 0x10, 0x30, 0x74, 0xcb, 0x77, 0x9e, 0xe5, 0x5d, 0x18, 0xea, 0x03,
        0x99, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
        0x80, 0x14, 0x5b, 0xb1, 0xd9, 0x6e, 0x9a, 0x9b, 0x58, 0x38, 0x10, 0x30,
        0x74, 0xcb, 0x77, 0x9e, 0xe5, 0x5d, 0x18, 0xea, 0x03, 0x99, 0x30, 0x0f,
        0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
        0x01, 0x01, 0xff, 0x30, 0x3b, 0x06, 0x03, 0x55, 0x1d, 0x1e, 0x01, 0x01,
        0xff, 0x04, 0x31, 0x30, 0x2f, 0xa0, 0x13, 0x30, 0x11, 0x82, 0x0f, 0x6c,
        0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70, 0x70, 0x2e, 0x6c, 0x6f, 0x63,
        0x61, 0x6c, 0xa1, 0x18, 0x30, 0x16, 0x82, 0x14, 0x65, 0x76, 0x69, 0x6c,
        0x2e, 0x6c, 0x69, 0x62, 0x63, 0x65, 0x72, 0x74, 0x70, 0x70, 0x2e, 0x6c,
        0x6f, 0x63, 0x61, 0x6c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x09,
        0xcb, 0x4f, 0x62, 0x9a, 0x93, 0x55, 0xbd, 0xa8, 0x6c, 0x54, 0x5a, 0x86,
        0x2b, 0x64, 0x1a, 0xe8, 0x6a, 0x64, 0x0d, 0xab, 0x97, 0x9d, 0xef, 0x95,
        0xd8, 0xcc, 0x47, 0x6c, 0xf0, 0x13, 0xa0, 0xb5, 0x4b, 0xcc, 0xdb, 0xa8,
        0xbf, 0xb7, 0xc6, 0xfe, 0xfd, 0x71, 0xcf, 0xa9, 0x27, 0xd3, 0xb3, 0x24,
        0x83, 0x85, 0xc3, 0xb5, 0x3d, 0x5f, 0x78, 0xb0, 0x83, 0xd7, 0x30, 0xd0,
        0x17, 0x03, 0xe5, 0xd5, 0x56, 0x15, 0x03, 0xe0, 0x18, 0x28, 0xbc, 0xde,
        0x6c, 0x1c, 0x1f, 0x60, 0xec, 0x20, 0x90, 0x80, 0x3f, 0x88, 0xb1, 0xc0,
        0xb4, 0x4b, 0x02, 0x53, 0x10, 0xbe, 0xbc, 0x4d, 0x97, 0x83, 0xa3, 0x7e,
        0xcf, 0xa5, 0xf6, 0x0a, 0x4c, 0x9c, 0x74, 0x72, 0x88, 0x84, 0x22, 0xc1,
        0xa4, 0xd3, 0x55, 0x11, 0xb7, 0xa6, 0x09, 0xd4, 0x3d, 0x28, 0x90, 0x00,
        0x7a, 0xf1, 0x7b, 0x7c, 0xc5, 0x2a, 0xfa,
    };

    // A self-signed RSA-1024/SHA-256 certificate (openssl req -x509 -newkey rsa:1024 ...) and its
    // own matching private key, both in PEM: Subject/Issuer "C=US, O=libcertpp,
    // CN=pem.libcertpp.local". PEM_KEY_PKCS1 is the traditional PKCS#1 "RSA PRIVATE KEY" form
    // (openssl rsa -traditional); PEM_KEY_PKCS8 is the unencrypted PKCS#8 "PRIVATE KEY" form
    // (openssl pkcs8 -topk8 -nocrypt) of the exact same key.
    constexpr const char* PEM_CERT = R"(-----BEGIN CERTIFICATE-----
MIICWjCCAcOgAwIBAgIUCH4jWJNGAak4KOdIuNhAqbd21pMwDQYJKoZIhvcNAQEL
BQAwPzELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCWxpYmNlcnRwcDEcMBoGA1UEAwwT
cGVtLmxpYmNlcnRwcC5sb2NhbDAeFw0yNjA5MjgwNDA5MDFaFw0zNjA5MjUwNDA5
MDFaMD8xCzAJBgNVBAYTAlVTMRIwEAYDVQQKDAlsaWJjZXJ0cHAxHDAaBgNVBAMM
E3BlbS5saWJjZXJ0cHAubG9jYWwwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB
ANWAMbaKLu013IyUYlNBAOCgdh2HbiFL19x0goTkenUuqqgYqU/uiqcjZFndArpe
hloZeVoZa1QwaM8VmrDlaZ71CBxDHDkw9VhD22mXYpZd9wbb0ItQ+qbGG8S1X9Tk
LLZiHd5RtVKhR218HVuTf0kFtoSMQoug1FrqXk3UJxB1AgMBAAGjUzBRMB0GA1Ud
DgQWBBQe2uqZXC0LZhHHfqdm8yER/I9QQTAfBgNVHSMEGDAWgBQe2uqZXC0LZhHH
fqdm8yER/I9QQTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBAIQo
TZPR1UChETcaWJfBahI183Z733qaKoLo/cNxqq0BOn67mSY22h/J4c8UiCh8Lmgv
i70ddnxgt/7kfeiUDIggbH0bHz2sfIIIFrftdPxvOuO4EWwyAVXh+xZJm/peXjjC
sYWQh4Fr5OiLARxCWgiiqUb7ZGfnZp14QUt1tjEk
-----END CERTIFICATE-----
)";

    constexpr const char* PEM_KEY_PKCS1 = R"(-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDVgDG2ii7tNdyMlGJTQQDgoHYdh24hS9fcdIKE5Hp1LqqoGKlP
7oqnI2RZ3QK6XoZaGXlaGWtUMGjPFZqw5Wme9QgcQxw5MPVYQ9tpl2KWXfcG29CL
UPqmxhvEtV/U5Cy2Yh3eUbVSoUdtfB1bk39JBbaEjEKLoNRa6l5N1CcQdQIDAQAB
AoGBAMNYdCQM8zrfmViXPA/o3iCpMOl7zOxyNKPlhraJRvKJLGR5jBEytXKQE3WV
nrVfX5Z40Gv77hQt5vfzUIKipau7hjI5q4GUx/V6subAQhVEE4WzvXkUWj1vTtxy
VpVgSpLG4Q+RcZPcYD44QPgsk/c74nxLIYG7Y3Xj8DcY39XRAkEA8VORXIc7OVnD
Y2uTlxfENcHDxuQNLWwf/XuhW2au35U9Ig+qHg5TAb0LPbk7v4WTz4XoeqqKJqqc
0YzJR0OnZwJBAOJ7f4uN/mSWBZttbAIiDUSjQ5AjIqZrhzz4Iu+97U9wpQvaID7I
Fog2isg9SiNUzAKPHM3+4/bnoeNxr66V68MCQQCV8HU9hywt6u6yQ/G0i+i1+cj5
N1JUqXyK0xijIH6AnkoYcqEhAYdjaiCk3gUYbxcydiHGrVUexxyeOhoI9Cj7AkBD
LHoB/FWNo+l51hSI9WyWBQ6O+7zVO2NbNAW4sc5nF3P8de/GbzYvpG25QmRw4j+4
KpZSit02aDFd8mQ3FgRdAkAgf1Aj1p4qNGP4feEP4t9VTy03MNR/lehX0NL1p/yp
5wgTOj7nTqjWzIIb52xEOysSdSO1NOozMgavGxj1EpKZ
-----END RSA PRIVATE KEY-----
)";

    constexpr const char* PEM_KEY_PKCS8 = R"(-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANWAMbaKLu013IyU
YlNBAOCgdh2HbiFL19x0goTkenUuqqgYqU/uiqcjZFndArpehloZeVoZa1QwaM8V
mrDlaZ71CBxDHDkw9VhD22mXYpZd9wbb0ItQ+qbGG8S1X9TkLLZiHd5RtVKhR218
HVuTf0kFtoSMQoug1FrqXk3UJxB1AgMBAAECgYEAw1h0JAzzOt+ZWJc8D+jeIKkw
6XvM7HI0o+WGtolG8oksZHmMETK1cpATdZWetV9flnjQa/vuFC3m9/NQgqKlq7uG
MjmrgZTH9Xqy5sBCFUQThbO9eRRaPW9O3HJWlWBKksbhD5Fxk9xgPjhA+CyT9zvi
fEshgbtjdePwNxjf1dECQQDxU5Fchzs5WcNja5OXF8Q1wcPG5A0tbB/9e6FbZq7f
lT0iD6oeDlMBvQs9uTu/hZPPheh6qoomqpzRjMlHQ6dnAkEA4nt/i43+ZJYFm21s
AiINRKNDkCMipmuHPPgi773tT3ClC9ogPsgWiDaKyD1KI1TMAo8czf7j9ueh43Gv
rpXrwwJBAJXwdT2HLC3q7rJD8bSL6LX5yPk3UlSpfIrTGKMgfoCeShhyoSEBh2Nq
IKTeBRhvFzJ2IcatVR7HHJ46Ggj0KPsCQEMsegH8VY2j6XnWFIj1bJYFDo77vNU7
Y1s0BbixzmcXc/x178ZvNi+kbblCZHDiP7gqllKK3TZoMV3yZDcWBF0CQCB/UCPW
nio0Y/h94Q/i31VPLTcw1H+V6FfQ0vWn/KnnCBM6PudOqNbMghvnbEQ7KxJ1I7U0
6jMyBq8bGPUSkpk=
-----END PRIVATE KEY-----
)";

    // An unrelated RSA private key (PKCS#8), not PEM_CERT's own -- for the mismatched-key test.
    constexpr const char* PEM_OTHER_KEY_PKCS8 = R"(-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALXPZUF6tXqDbt0g
eKTkRyx14FeLk5vg5uvP/fICLhh+5QKQ5AI6BLTpHg9sgZWrt6ZCr7H0dmCmNikc
DWX9Z5rHeuHnVxhkoh9HGnun0QgGJdDmTaSedXIKgAcRaBmGMg3Fo1rvOowLgUue
BLHF3zG2h8KvIhlOvWVxb2wgiemLAgMBAAECgYEAs5XTv9UUs5pmBNiRMtcmEp2w
5ujA+kUx9BY0EjvjCmE1ls5F2okyovxtq/CTI6NFuV2/rHj8AUXM09iYx3iCP21o
7bsVB6R8aEakxy4meiEosZPg+LjNibBk2fC0UFKq82LvecoTdAPsYhLl3QoaghcR
0aQAEf2jm3tbRsntFgECQQDvf0wQb3kvUu11Q0T3A0++UkMesK/3qXA8c0gqNoj9
AuDBV5avmgY+X9TkTVQinAbJlw0Uo+O3kLmMM59NANEBAkEAwlaBLT4AwweS9r6g
8VP0AQ9PAqQZZwMr6uJtJ9ujqAdpi8zihczYZCunnWfY5PQph//3okbaZR93dTJ9
jUpuiwJAMhkRwzpeQiz5qRbaPUV/D9PLYIcbOBZEeRCwXswrmalZdHgq+C6i8bdA
JEWcvOSgctjbDp89yi9G8PH3d7cdAQJBAIngFYWjl6bGmN22ITkV9udJlSSqh9st
xNrACfFdQp7To24rzgpfaqam0iQ6qQbGszBpyaa33fogeQAM8kZrqEECQQCDc+3/
nw6D8ktVsOZnc1VWltxfB79rkOMmUqZsIW5oLAO3S5F9sdzGlXv3fhDW2x4+6w94
X6y/oiwmpEZ6yD7R
-----END PRIVATE KEY-----
)";

    // A self-signed EC (P-256)/SHA-256 certificate and its own matching private key, both PEM,
    // the key in PKCS#8 form (openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 ...):
    // Subject/Issuer "C=US, O=libcertpp, CN=ec.export.local".
    constexpr const char* PEM_EC_CERT = R"(-----BEGIN CERTIFICATE-----
MIIBzDCCAXGgAwIBAgIUK1Kh2xIGGgeg6VqTFM0QWrVDpUEwCgYIKoZIzj0EAwIw
OzELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCWxpYmNlcnRwcDEYMBYGA1UEAwwPZWMu
ZXhwb3J0LmxvY2FsMB4XDTI2MDkyODA2MDgyOVoXDTM2MDkyNTA2MDgyOVowOzEL
MAkGA1UEBhMCVVMxEjAQBgNVBAoMCWxpYmNlcnRwcDEYMBYGA1UEAwwPZWMuZXhw
b3J0LmxvY2FsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/RBZa8uHCURT/TX9
CDFZIaVvCqRwY59Jbv/j2pHx98TsE5zTW/N58bwc5WXmyS2bZZCi350b1To42UD5
/87EoKNTMFEwHQYDVR0OBBYEFPDa5ojbbkdia7sUFAeX6k3fphLpMB8GA1UdIwQY
MBaAFPDa5ojbbkdia7sUFAeX6k3fphLpMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI
zj0EAwIDSQAwRgIhAPT1o/g5JD3MY98R34mKq+J4tmnYzOVMH/I3Gvtesl13AiEA
4xSBzhjo7cX5Mq+d2yfx34SjJwhXnug/elvCCbgntaE=
-----END CERTIFICATE-----
)";

    constexpr const char* PEM_EC_KEY_PKCS8 = R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOczqBcroJVgFOjfe
WbxWpD8MEPy6VSHDwhudccPemqKhRANCAAT9EFlry4cJRFP9Nf0IMVkhpW8KpHBj
n0lu/+PakfH3xOwTnNNb83nxvBzlZebJLZtlkKLfnRvVOjjZQPn/zsSg
-----END PRIVATE KEY-----
)";

    // A self-signed DSA (1024-bit)/SHA-256 certificate and its own matching private key, both
    // PEM, the key in PKCS#8 form (openssl req -x509 -newkey dsa:<params> ...): Subject/Issuer
    // "C=US, O=libcertpp, CN=dsa.export.local".
    constexpr const char* PEM_DSA_CERT = R"(-----BEGIN CERTIFICATE-----
MIIDLjCCAtygAwIBAgIUJ02P4yOjG4umg6bvvMuLjEQcmd4wCwYJYIZIAWUDBAMC
MDwxCzAJBgNVBAYTAlVTMRIwEAYDVQQKDAlsaWJjZXJ0cHAxGTAXBgNVBAMMEGRz
YS5leHBvcnQubG9jYWwwHhcNMjYwOTI4MDYxMzE1WhcNMzYwOTI1MDYxMzE1WjA8
MQswCQYDVQQGEwJVUzESMBAGA1UECgwJbGliY2VydHBwMRkwFwYDVQQDDBBkc2Eu
ZXhwb3J0LmxvY2FsMIIBvzCCATMGByqGSM44BAEwggEmAoGBAMVisLG3T/iIzDEL
NAZW5OmUOudSbfpcLAdWiY3IrSCdLnbD3GNfkN0ytnhNOD49ancpDBt4tCA5V2wa
M7fD98QNj/E3V0FDGBVuKaX7kCkMkHQprKwbWLrXA5kxEANXpSL2F8QsSN6OD5E7
qiBpUKT452GelurYVVNE+2hDCPHpAh0ApGQekAvRaT1YHcQjSifNOTTizJApfV1L
uom3tQKBgGVDanGCwdE7Ctr/FF8mmXVdhKVbYXwkzgYzJDW4JLn6jk/MjBFNDpAv
tis46tbJReiEOYXeOtIVMhBeguJjDEmG4HK5hnUYzfDKSpw+lBvpvrfD+lpautpF
L7Iorz4Hw2mqlrSk0TqNvGb3SM4TP0PJ/NlVBbGgGL35bj+SXuHKA4GFAAKBgQCz
VhtEg0jo+RYGhUwt6o6EBonYjDThgiL+IJSRV+ZmXvMKxLUv7+/tVsqlVV0yBx3L
poQXFNpmpx0OHQzg1Zh8EM2inb3M+gjIjEhDlvXBw/dgbNsCfFH/7dgfezcfN9qc
Zj/YRmXoz5A5zlYuJFFlnrUpF7okoGrgK14QAt28uaNTMFEwHQYDVR0OBBYEFCIZ
U5x0BYa0i+yfTibUMz+NhWxeMB8GA1UdIwQYMBaAFCIZU5x0BYa0i+yfTibUMz+N
hWxeMA8GA1UdEwEB/wQFMAMBAf8wCwYJYIZIAWUDBAMCAz8AMDwCHDrCO9DreBsB
uH2tO+oj7Tx4BbUgkYO+cuGJGroCHARaTkvtfgc0UEo1znOhrmLuwDHdleUfyZ+G
plc=
-----END CERTIFICATE-----
)";

    constexpr const char* PEM_DSA_KEY_PKCS8 = R"(-----BEGIN PRIVATE KEY-----
MIIBWgIBADCCATMGByqGSM44BAEwggEmAoGBAMVisLG3T/iIzDELNAZW5OmUOudS
bfpcLAdWiY3IrSCdLnbD3GNfkN0ytnhNOD49ancpDBt4tCA5V2waM7fD98QNj/E3
V0FDGBVuKaX7kCkMkHQprKwbWLrXA5kxEANXpSL2F8QsSN6OD5E7qiBpUKT452Ge
lurYVVNE+2hDCPHpAh0ApGQekAvRaT1YHcQjSifNOTTizJApfV1Luom3tQKBgGVD
anGCwdE7Ctr/FF8mmXVdhKVbYXwkzgYzJDW4JLn6jk/MjBFNDpAvtis46tbJReiE
OYXeOtIVMhBeguJjDEmG4HK5hnUYzfDKSpw+lBvpvrfD+lpautpFL7Iorz4Hw2mq
lrSk0TqNvGb3SM4TP0PJ/NlVBbGgGL35bj+SXuHKBB4CHFOzp04xOv3XpiYlyME6
HtgZfUEVNyT4FdAw2b8=
-----END PRIVATE KEY-----
)";

    // A self-signed Ed25519 certificate and its own matching private key, both PEM, the key in
    // PKCS#8 form (openssl req -x509 -newkey ed25519 ...): Subject/Issuer "C=US, O=libcertpp,
    // CN=ed25519.export.local".
    constexpr const char* PEM_ED25519_CERT = R"(-----BEGIN CERTIFICATE-----
MIIBlTCCAUegAwIBAgIUEeS6GJvchefnupRwftfuz6CT+CwwBQYDK2VwMEAxCzAJ
BgNVBAYTAlVTMRIwEAYDVQQKDAlsaWJjZXJ0cHAxHTAbBgNVBAMMFGVkMjU1MTku
ZXhwb3J0LmxvY2FsMB4XDTI2MDkyODA2MDgyOVoXDTM2MDkyNTA2MDgyOVowQDEL
MAkGA1UEBhMCVVMxEjAQBgNVBAoMCWxpYmNlcnRwcDEdMBsGA1UEAwwUZWQyNTUx
OS5leHBvcnQubG9jYWwwKjAFBgMrZXADIQAEMdaPRLSCxlSePe6SYkhPhVGKriH6
QTTPQPqb1nzS46NTMFEwHQYDVR0OBBYEFJQ9GGsU4rsC2+4raeliKl3a7rEsMB8G
A1UdIwQYMBaAFJQ9GGsU4rsC2+4raeliKl3a7rEsMA8GA1UdEwEB/wQFMAMBAf8w
BQYDK2VwA0EAr53eOOsbRxeazwD2DUPbKpU7BRkwYRBWqaWi2IgEoZnvdjAUYRe8
HS9Nr3rYGQEdvw8/5UXxr4e8xkxj9CtIAQ==
-----END CERTIFICATE-----
)";

    constexpr const char* PEM_ED25519_KEY_PKCS8 = R"(-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMiQd9/RfiFzU9VIz9pGjz6Kxjz3RRXwRvD8LQkLloVb
-----END PRIVATE KEY-----
)";

    // A self-signed Ed448 certificate and its own matching private key, both PEM, the key in
    // PKCS#8 form (openssl req -x509 -newkey ed448 ...): Subject/Issuer "C=US, O=libcertpp,
    // CN=ed448.export.local".
    constexpr const char* PEM_ED448_CERT = R"(-----BEGIN CERTIFICATE-----
MIIB3DCCAVygAwIBAgIUVf2M0DafYrhHGdYjdzHo36MxBYAwBQYDK2VxMD4xCzAJ
BgNVBAYTAlVTMRIwEAYDVQQKDAlsaWJjZXJ0cHAxGzAZBgNVBAMMEmVkNDQ4LmV4
cG9ydC5sb2NhbDAeFw0yNjA5MjgwOTAyMzZaFw0zNjA5MjUwOTAyMzZaMD4xCzAJ
BgNVBAYTAlVTMRIwEAYDVQQKDAlsaWJjZXJ0cHAxGzAZBgNVBAMMEmVkNDQ4LmV4
cG9ydC5sb2NhbDBDMAUGAytlcQM6AF7WlSUV4fDDsLwLOeBSreXzdg456rMiO9Dq
mcai6FhVT7GbCMj1ilyW5EdjZZEEaJRzC5tF0iOCAKNTMFEwHQYDVR0OBBYEFNaU
Y87Vm4oKX9ILzj8bT7D8gVlAMB8GA1UdIwQYMBaAFNaUY87Vm4oKX9ILzj8bT7D8
gVlAMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VxA3MAcY3wC6ndRy5Bfk9Jon6lKzFE
uStcwgVSGxHEp6Di7/sctdtuGGmnhGpjSrwdkIbPeUImLe9uWqKAx9xSULv+RUw0
vhwDWgOYdmfE9FfyfRtwLK5BRvDLvVgIf5s9gqFFIZwPyi8gP2x9iN+29SakXTMA
-----END CERTIFICATE-----
)";

    constexpr const char* PEM_ED448_KEY_PKCS8 = R"(-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOfTxgaxw3GbQoFAtRbhK0oBsJAOIy5VNrxf7TtuWRDQp
fQEMlwEimnMQFAoOhfK+My6R9ThzRoLUJw==
-----END PRIVATE KEY-----
)";

    // An X25519 public key certificate (X25519 can't sign, so unlike the other fixtures this one
    // is issued by a separate throwaway RSA CA rather than self-signed: openssl genpkey
    // -algorithm X25519, then openssl x509 -new -force_pubkey ... -CA ... -CAkey ...) and its own
    // matching private key, both PEM, the key in PKCS#8 form: Subject "C=US, O=libcertpp,
    // CN=x25519.export.local", Issuer "C=US, O=libcertpp, CN=Test CA".
    constexpr const char* PEM_X25519_CERT = R"(-----BEGIN CERTIFICATE-----
MIICSDCCATCgAwIBAgIUL7ajM2otVeHsu+by7hGMRn/McYEwDQYJKoZIhvcNAQEL
BQAwMzELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCWxpYmNlcnRwcDEQMA4GA1UEAwwH
VGVzdCBDQTAeFw0yNjA5MjgwOTU0MThaFw0zNjA5MjUwOTU0MThaMD8xCzAJBgNV
BAYTAlVTMRIwEAYDVQQKDAlsaWJjZXJ0cHAxHDAaBgNVBAMME3gyNTUxOS5leHBv
cnQubG9jYWwwKjAFBgMrZW4DIQAWauTHXVm/oM0GfCEEVI2E/q0NRYHqagXIDzRZ
sBtWY6NCMEAwHQYDVR0OBBYEFPx14n2mRwCbkutQWwdDCG04xWyHMB8GA1UdIwQY
MBaAFEBnOmrr8La7/iIngkLnz9D/Qew0MA0GCSqGSIb3DQEBCwUAA4IBAQCJh+jS
Ck+iziJysrGUPn7L3GtE2/dZ0UKy2CMCUbUn0ghutwtt3B4s7cV9OiNd0XWD6T71
w1rsuPNuRVwQ9v6DX0SEKrGkCfZmaALag2Go2TjtzwpP1KaJTapaVfwqONGxJoBV
DaSvcrArWFmj7yOnG4liB3lnIt9Jme9eYGt137cYmvOqApvPIKDsMtukLY+fotk3
RO+Nhuqtzi/QTp9niVw2MfI0UjzOEwDATopmhmnOHjn4ZLWmQ1L2Mj2va0m1K106
h4u/m2bdj9I57QiRQ//oXC6nZsXzTU5mqVUpYda7fDeovO5Xzl8mvBI1ZAdaOiTl
tAx0ART8rmNitKfB
-----END CERTIFICATE-----
)";

    constexpr const char* PEM_X25519_KEY_PKCS8 = R"(-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIAAcwwXynjBFSUdvGXM8WoXIiDabV9Vpxg+ie9rafLt2
-----END PRIVATE KEY-----
)";
}

TEST_CASE("CCert: importDer() parses an RSA/SHA-256 certificate's subject, issuer, validity, serial and thumbprint") {
    COctet der(RSA_CERT_DER, sizeof(RSA_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);
    CHECK_FALSE(cert.empty());

    CHECK(cert.rawData().size() == sizeof(RSA_CERT_DER));
    CHECK(cert.serialNumber().toSpan().sequencialEqual(SReadOnlyByteSpan(RSA_CERT_SERIAL, sizeof(RSA_CERT_SERIAL))));
    CHECK(cert.thumbprint().toSpan().sequencialEqual(SReadOnlyByteSpan(RSA_CERT_SHA1_THUMBPRINT, sizeof(RSA_CERT_SHA1_THUMBPRINT))));

    CHECK(cert.keyAlgo() == CString("RSA"));
    CHECK(cert.signAlgo() == CString("sha256WithRSAEncryption"));
    CHECK(cert.keyUsages() == EKUSE_NONE); // --> No KeyUsage extension on this cert.
    CHECK_FALSE(cert.rawPublicKey().empty());
    CHECK_FALSE(cert.subjectStr().empty());
    CHECK_FALSE(cert.issuerStr().empty());

    CName name;
    REQUIRE(cert.subject().tryGet(ENAME_C, name));
    CHECK(name == CName(ENAME_C, "US"));
    REQUIRE(cert.subject().tryGet(ENAME_ST, name));
    CHECK(name == CName(ENAME_ST, "California"));
    REQUIRE(cert.subject().tryGet(ENAME_L, name));
    CHECK(name == CName(ENAME_L, "San Francisco"));
    REQUIRE(cert.subject().tryGet(ENAME_O, name));
    CHECK(name == CName(ENAME_O, "libcertpp"));
    REQUIRE(cert.subject().tryGet(ENAME_OU, name));
    CHECK(name == CName(ENAME_OU, "Test"));
    REQUIRE(cert.subject().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "test.libcertpp.local"));

    // Self-signed: issuer is identical to subject.
    CHECK(cert.issuer() == cert.subject());

    CHECK(cert.notBefore().year == 2026);
    CHECK(cert.notBefore().month == 9);
    CHECK(cert.notBefore().day == 27);
    CHECK(cert.notAfter().year == 2036);
    CHECK(cert.notAfter().month == 9);
    CHECK(cert.notAfter().day == 24);
}

TEST_CASE("CCert: createHasher() returns a fresh hasher matching signAlgo()'s own digest") {
    COctet der(RSA_CERT_DER, sizeof(RSA_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);
    REQUIRE(cert.signAlgo() == CString("sha256WithRSAEncryption"));

    IHasherPtr hasher = cert.createHasher();
    REQUIRE(hasher);
    CHECK(hasher->byteWidth() == 32); // --> SHA-256, not thumbprint()'s SHA-1.
}

TEST_CASE("CCert: createHasher() + createAsymmetricContext() verify a real signature made with the certificate's public key") {
    COctet der(RSA_CERT_DER, sizeof(RSA_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    IAsymmetricContextPtr ctx = cert.createAsymmetricContext();
    REQUIRE(ctx);
    CHECK(ctx->sizeOfSign() == 128); // --> 1024-bit RSA key.

    IHasherPtr hasher = cert.createHasher();
    REQUIRE(hasher);

    // RSA_CERT_DER's tbsCertificate TLV (tag+length+content), sha256WithRSAEncryption-signed by
    // this same self-signed certificate's own key: bytes [4, 4+577) of the outer Certificate
    // SEQUENCE's content, per the ASN.1 structure this test data's own comment documents.
    SReadOnlyByteSpan tbsCertificate(RSA_CERT_DER + 4, 577);
    hasher->push(tbsCertificate);

    uint8_t digest[32];
    SByteSpan digestSpan(digest, sizeof(digest));
    REQUIRE(hasher->finish(digestSpan));

    // The last 128 bytes of RSA_CERT_DER are signatureValue's packed bits (the RSA signature).
    SReadOnlyByteSpan signature(RSA_CERT_DER + sizeof(RSA_CERT_DER) - 128, 128);

    CHECK(ctx->verify(SReadOnlyByteSpan(digest, digestSpan.size), signature) == ERET_OK);

    // A tampered digest must not verify.
    digest[0] ^= 0xFF;
    CHECK(ctx->verify(SReadOnlyByteSpan(digest, digestSpan.size), signature) != ERET_OK);
}

TEST_CASE("CCert: publicKey() lazily builds and caches the certificate's public key") {
    COctet der(RSA_CERT_DER, sizeof(RSA_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    IPublicKeyPtr pub = cert.publicKey();
    REQUIRE(pub);
    CHECK(pub->keySize() == 1024);

    // Same object on a second call -- proves this is a cache, not a rebuild-every-time.
    CHECK(cert.publicKey().get() == pub.get());
}

TEST_CASE("CCert: privateKey(IPrivateKeyPtr&) attaches a matching key and rejects a mismatched one") {
    COctet der(PK_CERT_DER, sizeof(PK_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);
    REQUIRE(cert.rawPrivateKey().empty());
    REQUIRE_FALSE(cert.privateKey());

    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    REQUIRE(rsa);

    // The wrong key (not this certificate's own) must be rejected, and must not disturb any
    // previously-attached state.
    IPrivateKeyPtr wrongKey = rsa->createPrivateKey(SReadOnlyByteSpan(OTHER_PRIVATE_KEY_DER, sizeof(OTHER_PRIVATE_KEY_DER)));
    REQUIRE(wrongKey);
    CHECK(cert.privateKey(wrongKey) == ERET_KEY_ERROR);
    CHECK(cert.rawPrivateKey().empty());
    CHECK_FALSE(cert.privateKey());

    // The certificate's own matching key must be accepted.
    IPrivateKeyPtr ownKey = rsa->createPrivateKey(SReadOnlyByteSpan(PK_PRIVATE_KEY_DER, sizeof(PK_PRIVATE_KEY_DER)));
    REQUIRE(ownKey);
    REQUIRE(cert.privateKey(ownKey) == ERET_OK);
    CHECK_FALSE(cert.rawPrivateKey().empty());

    IPrivateKeyPtr cachedPvt = cert.privateKey();
    REQUIRE(cachedPvt);
    CHECK(cachedPvt->keySize() == 1024);

    // createAsymmetricContext() now binds both halves, so it can sign as well as verify.
    IAsymmetricContextPtr ctx = cert.createAsymmetricContext();
    REQUIRE(ctx);

    uint8_t digest[32] = { 0 };
    uint8_t sig[128];
    SByteSpan sigSpan(sig, sizeof(sig));
    REQUIRE(ctx->sign(SReadOnlyByteSpan(digest, sizeof(digest)), sigSpan) == ERET_OK);
    CHECK(ctx->verify(SReadOnlyByteSpan(digest, sizeof(digest)), SReadOnlyByteSpan(sig, sigSpan.size)) == ERET_OK);
}

TEST_CASE("CCert: subjectKeyIdentifier()/authorityKeyIdentifier() match on a self-signed certificate") {
    COctet der(RSA_CERT_DER, sizeof(RSA_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    COctet ski, aki;
    REQUIRE(cert.subjectKeyIdentifier(ski) == ERET_OK);
    REQUIRE(cert.authorityKeyIdentifier(aki) == ERET_OK);

    CHECK(ski.size() == 20);
    CHECK(ski.toSpan().sequencialEqual(aki.toSpan())); // --> Self-signed: issuer == subject.
}

TEST_CASE("CCert: extensionOf() looks up an extension by OID, char and wchar_t") {
    COctet der(RSA_CERT_DER, sizeof(RSA_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    IExtensionPtr viaChar;
    REQUIRE(cert.extensionOf("2.5.29.14", viaChar) == ERET_OK); // --> subjectKeyIdentifier
    REQUIRE(viaChar);
    CHECK_FALSE(viaChar->value().empty());

    IExtensionPtr viaWide;
    REQUIRE(cert.extensionOf(L"2.5.29.14", viaWide) == ERET_OK);
    REQUIRE(viaWide);
    CHECK(viaChar->value().toSpan().sequencialEqual(viaWide->value().toSpan()));

    IExtensionPtr missing;
    CHECK(cert.extensionOf("2.5.29.99", missing) == ERET_INVAL);
}

TEST_CASE("CCert: extension<T>() looks up a typed extension, e.g. CBasicConstraintsExtension") {
    COctet der(KU_CERT_DER, sizeof(KU_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    auto basicConstraints = cert.extension<CBasicConstraintsExtension>();
    REQUIRE(basicConstraints);
    CHECK(basicConstraints->isCa());
    CHECK_FALSE(basicConstraints->hasPathLenConstraint());

    auto keyUsages = cert.extension<CKeyUsagesExtension>();
    REQUIRE(keyUsages);
    CHECK(keyUsages->bits() == cert.keyUsages());

    CHECK_FALSE(cert.extension<CEkuExtension>()); // --> not present on this cert.
}

TEST_CASE("CCert: NameConstraints extension decodes permitted/excluded GeneralSubtrees") {
    COctet der(NC_CERT_DER, sizeof(NC_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    auto basicConstraints = cert.extension<CBasicConstraintsExtension>();
    REQUIRE(basicConstraints);
    CHECK(basicConstraints->isCa());

    auto nc = cert.extension<CNameConstraintsExtension>();
    REQUIRE(nc);

    REQUIRE(nc->permittedSubtrees().size() == 1);
    const CGeneralSubtree& permitted = nc->permittedSubtrees()[0];
    CHECK(permitted.base().type() == EGNAME_DNS);
    CHECK(permitted.base().text() == CString("libcertpp.local"));
    CHECK(permitted.minimum() == 0);
    CHECK_FALSE(permitted.hasMaximum());

    REQUIRE(nc->excludedSubtrees().size() == 1);
    const CGeneralSubtree& excluded = nc->excludedSubtrees()[0];
    CHECK(excluded.base().type() == EGNAME_DNS);
    CHECK(excluded.base().text() == CString("evil.libcertpp.local"));
}

TEST_CASE("CCert: equals() compares certificates by their raw DER encoding") {
    COctet rsaDer(RSA_CERT_DER, sizeof(RSA_CERT_DER));
    COctet ecDer(EC_CERT_DER, sizeof(EC_CERT_DER));

    CCert a, b, c;
    REQUIRE(a.importDer(rsaDer) == ERET_OK);
    REQUIRE(b.importDer(rsaDer) == ERET_OK);
    REQUIRE(c.importDer(ecDer) == ERET_OK);

    CHECK(a.equals(b));
    CHECK_FALSE(a.equals(c));

    CCert empty;
    CHECK_FALSE(a.equals(empty));
}

TEST_CASE("CCert: importDer() parses an EC (P-256)/SHA-256 certificate") {
    COctet der(EC_CERT_DER, sizeof(EC_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    CHECK(cert.serialNumber().toSpan().sequencialEqual(SReadOnlyByteSpan(EC_CERT_SERIAL, sizeof(EC_CERT_SERIAL))));
    CHECK(cert.keyAlgo() == CString("EC"));
    CHECK(cert.signAlgo() == CString("ecdsa-with-SHA256"));

    // An uncompressed EC point: 0x04 || X || Y, 65 bytes for P-256.
    CHECK(cert.rawPublicKey().size() == 65);
    CHECK(cert.rawPublicKey().toPtr()[0] == 0x04);

    CName name;
    REQUIRE(cert.subject().tryGet(ENAME_C, name));
    CHECK(name == CName(ENAME_C, "KR"));
    REQUIRE(cert.subject().tryGet(ENAME_O, name));
    CHECK(name == CName(ENAME_O, "libcertpp"));
    REQUIRE(cert.subject().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "ec.libcertpp.local"));
    CHECK_FALSE(cert.subject().has(ENAME_OU));
}

TEST_CASE("CCert: importDer() decodes the KeyUsage extension into keyUsages()") {
    COctet der(KU_CERT_DER, sizeof(KU_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    // openssl x509 -text reports this cert's KeyUsage as "critical: Digital Signature,
    // Certificate Sign, CRL Sign" -- named bits 0, 5, 6.
    CHECK(cert.keyUsages() == (EKUSE_DIGITAL_SIGNATURE | EKUSE_KEY_CERT_SIGN | EKUSE_CRL_SIGN));
    CHECK_FALSE((cert.keyUsages() & EKUSE_KEY_ENCIPHERMENT));
    CHECK_FALSE((cert.keyUsages() & EKUSE_DATA_ENCIPHERMENT));
    CHECK_FALSE((cert.keyUsages() & EKUSE_KEY_AGREEMENT));
    CHECK_FALSE((cert.keyUsages() & EKUSE_NON_REPUDIATION));
    CHECK_FALSE((cert.keyUsages() & EKUSE_ENCIPHER_ONLY));
    CHECK_FALSE((cert.keyUsages() & EKUSE_DECIPHER_ONLY));
}

TEST_CASE("CCert: importDer() records Extension.critical, not just extnID/extnValue") {
    COctet der(KU_CERT_DER, sizeof(KU_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    // openssl x509 -text reports this cert's KeyUsage as "critical: ..." (see the KeyUsage
    // decode test above) -- the one extension in this fixture known to be marked critical.
    IExtensionPtr ku;
    REQUIRE(cert.extensionOf(CKeyUsagesExtension::OID, ku) == ERET_OK);
    REQUIRE(ku);
    CHECK(ku->critical());
}

TEST_CASE("CCertBuilder/CCert: a critical extension round-trips through build()/importDer()") {
    IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);
    SKeyPair kp;
    REQUIRE(ec->generateKeyPair(256, kp) == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Test CA")));
    builder.subject = builder.issuer;
    uint8_t serial[1] = { 0x01 };
    builder.serialNumber = COctet(serial, 1);
    builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;

    CKeyUsagesExtensionBuilder kub;
    kub.setBits(EKUSE_DIGITAL_SIGNATURE);
    IExtensionPtr ku = kub.build();
    REQUIRE(ku);
    ku->critical(true);
    builder.extensions.add(ku);

    CCert cert;
    REQUIRE(builder.build(cert) == ERET_OK);
    REQUIRE_FALSE(cert.empty());

    IExtensionPtr reparsed;
    REQUIRE(cert.extensionOf(CKeyUsagesExtension::OID, reparsed) == ERET_OK);
    REQUIRE(reparsed);
    CHECK(reparsed->critical());
}

TEST_CASE("CCertBuilder/CCert: a duplicate extension OID doesn't corrupt parsing or override the first instance") {
    IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);
    SKeyPair kp;
    REQUIRE(ec->generateKeyPair(256, kp) == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Test CA")));
    builder.subject = builder.issuer;
    uint8_t serial[1] = { 0x01 };
    builder.serialNumber = COctet(serial, 1);
    builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;

    // RFC 5280 4.2: "A certificate MUST NOT include more than one instance of a particular
    // extension" -- this deliberately builds a malformed one anyway (two KeyUsage extensions,
    // with different, distinguishable bit patterns) to confirm parseExtensions() keeps only the
    // first instance rather than silently accumulating both.
    CKeyUsagesExtensionBuilder first;
    first.setBits(EKUSE_DIGITAL_SIGNATURE);
    builder.extensions.add(first.build());

    CKeyUsagesExtensionBuilder second;
    second.setBits(EKUSE_KEY_CERT_SIGN);
    builder.extensions.add(second.build());

    CCert cert;
    REQUIRE(builder.build(cert) == ERET_OK);
    REQUIRE_FALSE(cert.empty());

    CHECK(cert.keyUsages() == EKUSE_DIGITAL_SIGNATURE);
    CHECK_FALSE((cert.keyUsages() & EKUSE_KEY_CERT_SIGN));
}

TEST_CASE("CCert: importDer() rejects empty input") {
    CCert cert;
    CHECK(cert.importDer(COctet()) == ERET_INVAL);
    CHECK(cert.empty());
}

TEST_CASE("CCert: importDer() rejects malformed DER") {
    const uint8_t garbage[] = { 0x30, 0x05, 0x02, 0x01, 0x01 }; // SEQUENCE { INTEGER 1 } -- not a Certificate
    COctet der(garbage, sizeof(garbage));

    CCert cert;
    CHECK(cert.importDer(der) == ERET_BADREQ);
    CHECK(cert.empty());
}

TEST_CASE("CCert: reset() restores an imported certificate to empty") {
    COctet der(RSA_CERT_DER, sizeof(RSA_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);
    REQUIRE_FALSE(cert.empty());

    cert.reset();
    CHECK(cert.empty());
    CHECK(cert.rawData().empty());
    CHECK(cert.subject().empty());
    CHECK(cert.serialNumber().empty());
}

TEST_CASE("CCert: copy and move preserve imported certificate data") {
    COctet der(RSA_CERT_DER, sizeof(RSA_CERT_DER));

    CCert original;
    REQUIRE(original.importDer(der) == ERET_OK);

    CCert copied(original);
    CHECK(copied.serialNumber().toSpan().sequencialEqual(original.serialNumber().toSpan()));
    CHECK(copied.subject() == original.subject());

    CCert moved(std::move(copied));
    CHECK(moved.serialNumber().toSpan().sequencialEqual(original.serialNumber().toSpan()));
    CHECK(moved.subject() == original.subject());
}

namespace {
    /* Concatenates two or more PEM blocks (or just returns one) as a single COctet, the shape
     * importPem() expects -- a real multi-block PEM file (cert + key) is just its blocks written
     * one after another. */
    COctet pemOctet(const CString& text) {
        return COctet(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text.toPtr()), text.size()));
    }
}

TEST_CASE("CCert: importPem() imports a certificate-only PEM, with no private key attached") {
    CCert cert;
    REQUIRE(cert.importPem(pemOctet(CString(PEM_CERT))) == ERET_OK);

    CHECK(cert.keyAlgo() == CString("RSA"));
    CName name;
    REQUIRE(cert.subject().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "pem.libcertpp.local"));

    CHECK(cert.rawPrivateKey().empty());
    CHECK_FALSE(cert.privateKey());
}

TEST_CASE("CCert: importPem() attaches a PKCS#1 \"RSA PRIVATE KEY\" block as the private key") {
    CString text(PEM_CERT);
    text.append(PEM_KEY_PKCS1);

    CCert cert;
    REQUIRE(cert.importPem(pemOctet(text)) == ERET_OK);

    CHECK_FALSE(cert.rawPrivateKey().empty());
    IPrivateKeyPtr pvt = cert.privateKey();
    REQUIRE(pvt);
    CHECK(pvt->keySize() == 1024);

    // The attached key is genuinely usable, not just stored -- createAsymmetricContext() binds
    // both halves, so it can sign as well as verify.
    IAsymmetricContextPtr ctx = cert.createAsymmetricContext();
    REQUIRE(ctx);
    uint8_t digest[32] = { 0 };
    uint8_t sig[128];
    SByteSpan sigSpan(sig, sizeof(sig));
    REQUIRE(ctx->sign(SReadOnlyByteSpan(digest, sizeof(digest)), sigSpan) == ERET_OK);
    CHECK(ctx->verify(SReadOnlyByteSpan(digest, sizeof(digest)), SReadOnlyByteSpan(sig, sigSpan.size)) == ERET_OK);
}

TEST_CASE("CCert: importPem() attaches a PKCS#8 \"PRIVATE KEY\" block as the private key") {
    CString text(PEM_CERT);
    text.append(PEM_KEY_PKCS8);

    CCert cert;
    REQUIRE(cert.importPem(pemOctet(text)) == ERET_OK);

    CHECK_FALSE(cert.rawPrivateKey().empty());
    IPrivateKeyPtr pvt = cert.privateKey();
    REQUIRE(pvt);
    CHECK(pvt->keySize() == 1024);
}

TEST_CASE("CCert: importPem() imports the certificate but leaves a mismatched key block unattached") {
    CString text(PEM_CERT);
    text.append(PEM_OTHER_KEY_PKCS8);

    CCert cert;
    REQUIRE(cert.importPem(pemOctet(text)) == ERET_OK);

    CHECK(cert.rawPrivateKey().empty());
    CHECK_FALSE(cert.privateKey());
}

TEST_CASE("CCert: importPem() rejects PEM data with no CERTIFICATE block") {
    CCert cert;
    CHECK(cert.importPem(pemOctet(CString(PEM_KEY_PKCS1))) == ERET_BADREQ);
    CHECK(cert.empty());
}

TEST_CASE("CCert: importPem() rejects empty input") {
    CCert cert;
    CHECK(cert.importPem(COctet()) == ERET_INVAL);
    CHECK(cert.empty());
}

TEST_CASE("CCert: exportDer() round-trips importDer()'s own raw bytes") {
    COctet der(RSA_CERT_DER, sizeof(RSA_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    COctet out;
    REQUIRE(cert.exportDer(out) == ERET_OK);
    CHECK(out.toSpan().sequencialEqual(der.toSpan()));
}

TEST_CASE("CCert: exportDer() rejects an empty certificate") {
    CCert cert;
    COctet out;
    CHECK(cert.exportDer(out) == ERET_INVAL);
}

TEST_CASE("CCert: exportPem()/importPem() round-trip a certificate with no private key") {
    COctet der(RSA_CERT_DER, sizeof(RSA_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    COctet pem;
    REQUIRE(cert.exportPem(pem) == ERET_OK);

    CCert reimported;
    REQUIRE(reimported.importPem(pem) == ERET_OK);
    CHECK(reimported.equals(cert));
    CHECK(reimported.rawPrivateKey().empty());
}

TEST_CASE("CCert: exportPem(includePrivateKey=true) round-trips an RSA key as a standard PKCS#1 block") {
    COctet der(PK_CERT_DER, sizeof(PK_CERT_DER));
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    REQUIRE(rsa);
    IPrivateKeyPtr ownKey = rsa->createPrivateKey(SReadOnlyByteSpan(PK_PRIVATE_KEY_DER, sizeof(PK_PRIVATE_KEY_DER)));
    REQUIRE(ownKey);

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);
    REQUIRE(cert.privateKey(ownKey) == ERET_OK);

    COctet pem;
    REQUIRE(cert.exportPem(pem, true) == ERET_OK);

    // The private-key block is a plain PKCS#1 "RSA PRIVATE KEY" -- rawPrivateKey() itself is
    // already that format, so exporting it needs no conversion.
    CString pemText(reinterpret_cast<const char*>(pem.toPtr()), pem.size());
    CHECK(pemText.find("-----BEGIN RSA PRIVATE KEY-----") >= 0);

    CCert reimported;
    REQUIRE(reimported.importPem(pem) == ERET_OK);
    REQUIRE(reimported.privateKey());
    CHECK(reimported.rawPrivateKey().toSpan().sequencialEqual(cert.rawPrivateKey().toSpan()));

    IAsymmetricContextPtr ctx = reimported.createAsymmetricContext();
    REQUIRE(ctx);
    uint8_t digest[32] = { 7 };
    uint8_t sig[128];
    SByteSpan sigSpan(sig, sizeof(sig));
    REQUIRE(ctx->sign(SReadOnlyByteSpan(digest, sizeof(digest)), sigSpan) == ERET_OK);
    CHECK(ctx->verify(SReadOnlyByteSpan(digest, sizeof(digest)), SReadOnlyByteSpan(sig, sigSpan.size)) == ERET_OK);
}

TEST_CASE("CCert: exportPem(includePrivateKey=true) round-trips an EC key as a standard SEC1 block") {
    CString text(PEM_EC_CERT);
    text.append(PEM_EC_KEY_PKCS8);

    CCert cert;
    REQUIRE(cert.importPem(pemOctet(text)) == ERET_OK);
    REQUIRE(cert.privateKey());

    COctet pem;
    REQUIRE(cert.exportPem(pem, true) == ERET_OK);

    // buildSec1PrivateKey() produces a genuine SEC1 ECPrivateKey (RFC 5915), not
    // rawPrivateKey()'s own internal wire format -- labeled "EC PRIVATE KEY", not "PRIVATE KEY".
    CString pemText(reinterpret_cast<const char*>(pem.toPtr()), pem.size());
    CHECK(pemText.find("-----BEGIN EC PRIVATE KEY-----") >= 0);

    CCert reimported;
    REQUIRE(reimported.importPem(pem) == ERET_OK);
    REQUIRE(reimported.privateKey());

    IAsymmetricContextPtr ctx = reimported.createAsymmetricContext();
    REQUIRE(ctx);
    uint8_t digest[32] = { 7 };
    uint8_t sig[128];
    SByteSpan sigSpan(sig, sizeof(sig));
    REQUIRE(ctx->sign(SReadOnlyByteSpan(digest, sizeof(digest)), sigSpan) == ERET_OK);
    CHECK(ctx->verify(SReadOnlyByteSpan(digest, sizeof(digest)), SReadOnlyByteSpan(sig, sigSpan.size)) == ERET_OK);
}

TEST_CASE("CCert: exportPem(includePrivateKey=true) round-trips a DSA key as a standard traditional block") {
    // Exercises convertPkcs8DsaInnerToNative()'s own regression -- PKCS#8's DSA inner blob is a
    // bare INTEGER x, and rawPublicKey() is a full DER INTEGER TLV, not a bare magnitude (see
    // buildDsaPublicKeyBlob()'s own comment); both had to be handled correctly for this to work.
    CString text(PEM_DSA_CERT);
    text.append(PEM_DSA_KEY_PKCS8);

    CCert cert;
    REQUIRE(cert.importPem(pemOctet(text)) == ERET_OK);
    REQUIRE(cert.privateKey());

    COctet pem;
    REQUIRE(cert.exportPem(pem, true) == ERET_OK);

    CString pemText(reinterpret_cast<const char*>(pem.toPtr()), pem.size());
    CHECK(pemText.find("-----BEGIN DSA PRIVATE KEY-----") >= 0);

    CCert reimported;
    REQUIRE(reimported.importPem(pem) == ERET_OK);
    REQUIRE(reimported.privateKey());

    IAsymmetricContextPtr ctx = reimported.createAsymmetricContext();
    REQUIRE(ctx);
    uint8_t digest[32] = { 7 };
    uint8_t sig[64];
    SByteSpan sigSpan(sig, sizeof(sig));
    REQUIRE(ctx->sign(SReadOnlyByteSpan(digest, sizeof(digest)), sigSpan) == ERET_OK);
    CHECK(ctx->verify(SReadOnlyByteSpan(digest, sizeof(digest)), SReadOnlyByteSpan(sig, sigSpan.size)) == ERET_OK);
}

TEST_CASE("CCert: exportPem(includePrivateKey=true) round-trips an Ed25519 key as a standard PKCS#8 block") {
    CString text(PEM_ED25519_CERT);
    text.append(PEM_ED25519_KEY_PKCS8);

    CCert cert;
    REQUIRE(cert.importPem(pemOctet(text)) == ERET_OK);
    REQUIRE(cert.privateKey());

    COctet pem;
    REQUIRE(cert.exportPem(pem, true) == ERET_OK);

    // buildPkcs8EddsaPrivateKey() produces a genuine RFC 8410 PKCS#8 PrivateKeyInfo -- labeled
    // plain "PRIVATE KEY" (there's no traditional-format PEM label for Ed25519 to match).
    CString pemText(reinterpret_cast<const char*>(pem.toPtr()), pem.size());
    CHECK(pemText.find("-----BEGIN PRIVATE KEY-----") >= 0);

    CCert reimported;
    REQUIRE(reimported.importPem(pem) == ERET_OK);
    REQUIRE(reimported.privateKey());

    IAsymmetricContextPtr ctx = reimported.createAsymmetricContext();
    REQUIRE(ctx);
    uint8_t digest[32] = { 7 }; // Ed25519's "digest" parameter is the raw message, not a hash.
    uint8_t sig[64];
    SByteSpan sigSpan(sig, sizeof(sig));
    REQUIRE(ctx->sign(SReadOnlyByteSpan(digest, sizeof(digest)), sigSpan) == ERET_OK);
    CHECK(ctx->verify(SReadOnlyByteSpan(digest, sizeof(digest)), SReadOnlyByteSpan(sig, sigSpan.size)) == ERET_OK);
}

TEST_CASE("CCert: exportPem(includePrivateKey=true) round-trips an Ed448 key as a standard PKCS#8 block") {
    CString text(PEM_ED448_CERT);
    text.append(PEM_ED448_KEY_PKCS8);

    CCert cert;
    REQUIRE(cert.importPem(pemOctet(text)) == ERET_OK);
    REQUIRE(cert.privateKey());

    COctet pem;
    REQUIRE(cert.exportPem(pem, true) == ERET_OK);

    CString pemText(reinterpret_cast<const char*>(pem.toPtr()), pem.size());
    CHECK(pemText.find("-----BEGIN PRIVATE KEY-----") >= 0);

    CCert reimported;
    REQUIRE(reimported.importPem(pem) == ERET_OK);
    REQUIRE(reimported.privateKey());

    IAsymmetricContextPtr ctx = reimported.createAsymmetricContext();
    REQUIRE(ctx);
    uint8_t digest[32] = { 7 }; // Ed448's "digest" parameter is the raw message, not a hash.
    uint8_t sig[128];
    SByteSpan sigSpan(sig, sizeof(sig));
    REQUIRE(ctx->sign(SReadOnlyByteSpan(digest, sizeof(digest)), sigSpan) == ERET_OK);
    CHECK(ctx->verify(SReadOnlyByteSpan(digest, sizeof(digest)), SReadOnlyByteSpan(sig, sigSpan.size)) == ERET_OK);
}

TEST_CASE("CCert: exportPem(includePrivateKey=true) round-trips an X25519 key as a standard PKCS#8 block") {
    // X25519 can't sign, so PEM_X25519_CERT is CA-issued (an RSA CA, via openssl's
    // -force_pubkey) rather than self-signed like every other fixture in this file -- import
    // still only looks at the certificate's own SubjectPublicKeyInfo (X25519), never the issuer's
    // signature algorithm, so this works the same way regardless.
    CString text(PEM_X25519_CERT);
    text.append(PEM_X25519_KEY_PKCS8);

    CCert cert;
    REQUIRE(cert.importPem(pemOctet(text)) == ERET_OK);
    REQUIRE(cert.keyAlgo() == CString("X25519"));
    REQUIRE(cert.privateKey());

    COctet pem;
    REQUIRE(cert.exportPem(pem, true) == ERET_OK);

    CString pemText(reinterpret_cast<const char*>(pem.toPtr()), pem.size());
    CHECK(pemText.find("-----BEGIN PRIVATE KEY-----") >= 0);

    CCert reimported;
    REQUIRE(reimported.importPem(pem) == ERET_OK);
    REQUIRE(reimported.privateKey());

    // X25519 has no sign()/verify() -- deriveSharedSecret() against its own public key is the
    // closest equivalent "the attached key pair is genuinely usable" check.
    IAsymmetricContextPtr ctx = reimported.createAsymmetricContext();
    REQUIRE(ctx);
    uint8_t secret[32];
    SByteSpan secretSpan(secret, sizeof(secret));
    CHECK(ctx->deriveSharedSecret(reimported.publicKey(), secretSpan) == ERET_OK);
}

TEST_CASE("CCert: exportAs() dispatches to exportDer()/exportPem(), and rejects ECERT_AUTO") {
    COctet der(RSA_CERT_DER, sizeof(RSA_CERT_DER));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    COctet derOut;
    REQUIRE(cert.exportAs(derOut, false, ECERT_DER) == ERET_OK);
    CHECK(derOut.toSpan().sequencialEqual(der.toSpan()));

    COctet pemOut;
    REQUIRE(cert.exportAs(pemOut, false, ECERT_PEM) == ERET_OK);
    CString pemText(reinterpret_cast<const char*>(pemOut.toPtr()), pemOut.size());
    CHECK(pemText.find("-----BEGIN CERTIFICATE-----") >= 0);

    COctet autoOut;
    CHECK(cert.exportAs(autoOut, false, ECERT_AUTO) == ERET_NOTSUP);
}

TEST_CASE("CCert: importFrom() with ECERT_AUTO detects DER vs PEM") {
    COctet der(RSA_CERT_DER, sizeof(RSA_CERT_DER));

    CCert fromDer;
    REQUIRE(fromDer.importFrom(der.toSpan()) == ERET_OK);
    CHECK(fromDer.keyAlgo() == CString("RSA"));

    CCert fromPem;
    REQUIRE(fromPem.importFrom(pemOctet(CString(PEM_CERT)).toSpan()) == ERET_OK);
    CHECK(fromPem.keyAlgo() == CString("RSA"));

    // Explicit formats still work regardless of what auto-detection would have picked.
    CCert explicitDer;
    REQUIRE(explicitDer.importFrom(der.toSpan(), ECERT_DER) == ERET_OK);
}

namespace {

    // Extracts tbsCertificate's full tag-length-value bytes and the raw signatureValue bytes
    // (unwrapped from its BIT STRING) directly from a Certificate DER blob, then independently
    // re-verifies the signature via the certificate's own decoded publicKey() -- a hermetic
    // stand-in for cross-checking against a real, independent X.509 implementation (verified
    // once against openssl during development; see this session's own scratch verification --
    // not re-run here so these tests have no external tool dependency).
    bool verifyCertSelfSigned(const CCert& cert) {
        COctet der;
        if (cert.exportDer(der) != ERET_OK) {
            return false;
        }

        SReadOnlyByteSpan outerCursor = der.toSpan();
        CTag outerTag; SReadOnlyByteSpan outerContent;
        if (!CDecoder::readNextElement(outerCursor, EAENC_DER, outerTag, outerContent)) {
            return false;
        }

        SReadOnlyByteSpan cursor = outerContent;
        SReadOnlyByteSpan beforeTbs = cursor;
        CTag tbsTag; SReadOnlyByteSpan tbsContent;
        if (!CDecoder::readNextElement(cursor, EAENC_DER, tbsTag, tbsContent)) {
            return false;
        }

        SReadOnlyByteSpan tbsFullTlv(beforeTbs.data, size_t(tbsContent.data + tbsContent.size - beforeTbs.data));

        CTag sigAlgoTag; SReadOnlyByteSpan sigAlgoContent;
        if (!CDecoder::readNextElement(cursor, EAENC_DER, sigAlgoTag, sigAlgoContent)) {
            return false;
        }

        CTag sigTag; SReadOnlyByteSpan sigBits;
        if (!CDecoder::readNextElement(cursor, EAENC_DER, sigTag, sigBits)) {
            return false;
        }

        SReadOnlyByteSpan sigValueBits;
        uint8_t unused = 0;
        if (!CDecoder::decodeBitString(sigBits, sigValueBits, unused) || unused != 0) {
            return false;
        }

        IPublicKeyPtr pub = cert.publicKey();
        if (!pub) {
            return false;
        }

        IAsymmetricContextPtr ctx = cert.createAsymmetricContext();
        if (!ctx) {
            return false;
        }

        IHasherPtr hasher = cert.createHasher();
        if (hasher) {
            CBuffer digest;
            if (!digest.resize(hasher->byteWidth())
                || !hasher->push(tbsFullTlv)
                || !hasher->finish(SByteSpan(digest.toPtr(), digest.size())))
            {
                return false;
            }

            return ctx->verify(digest.toSpan(), sigValueBits) == ERET_OK;
        }

        // Self-hashing (EdDSA): the TBSCertificate bytes are the message itself.
        return ctx->verify(tbsFullTlv, sigValueBits) == ERET_OK;
    }

}

TEST_CASE("CCertBuilder: builds and self-signs an RSA certificate with a verifiable signature") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair kp;
    REQUIRE(rsa->generateKeyPair(1024, kp) == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Test CA")));
    builder.subject = builder.issuer;
    uint8_t serial[1] = { 0x01 };
    builder.serialNumber = COctet(serial, 1);
    builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;

    CCert cert;
    REQUIRE(builder.build(cert) == ERET_OK);
    REQUIRE_FALSE(cert.empty());
    CHECK(cert.keyAlgo() == CString("RSA"));
    CHECK(cert.signAlgo() == CString("sha256WithRSAEncryption"));
    CHECK(cert.subjectStr() == cert.issuerStr());
    CHECK(verifyCertSelfSigned(cert));
}

TEST_CASE("CCertBuilder: builds and self-signs a DSA certificate with a verifiable signature") {
    IAsymmetricPtr dsa = IAsymmetric::builtIn(EASYM_DSA);
    SKeyPair kp;
    ERetCode rc;
    do {
        rc = dsa->generateKeyPair(1024, kp);
    } while (rc == ERET_AGAIN);
    REQUIRE(rc == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Test CA")));
    builder.subject = builder.issuer;
    uint8_t serial[1] = { 0x01 };
    builder.serialNumber = COctet(serial, 1);
    builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;

    CCert cert;
    REQUIRE(builder.build(cert) == ERET_OK);
    REQUIRE_FALSE(cert.empty());
    CHECK(cert.keyAlgo() == CString("DSA"));
    CHECK(cert.signAlgo() == CString("dsa-with-sha256"));
    CHECK(verifyCertSelfSigned(cert));
}

TEST_CASE("CCertBuilder: builds and self-signs a P-256 certificate with a verifiable signature") {
    IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);
    SKeyPair kp;
    REQUIRE(ec->generateKeyPair(256, kp) == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Test CA")));
    builder.subject = builder.issuer;
    uint8_t serial[1] = { 0x01 };
    builder.serialNumber = COctet(serial, 1);
    builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;

    CBasicConstraintsExtensionBuilder bcb;
    bcb.setIsCa(true);
    builder.extensions.add(bcb.build());

    CCert cert;
    REQUIRE(builder.build(cert) == ERET_OK);
    REQUIRE_FALSE(cert.empty());
    CHECK(cert.keyAlgo() == CString("EC"));
    CHECK(cert.signAlgo() == CString("ecdsa-with-SHA256"));
    CHECK(verifyCertSelfSigned(cert));

    auto bc = cert.extension<CBasicConstraintsExtension>();
    REQUIRE(bc);
    CHECK(bc->isCa());
}

TEST_CASE("CCertBuilder: builds and self-signs an Ed25519 certificate with a verifiable signature") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    SKeyPair kp;
    REQUIRE(ed->generateKeyPair(256, kp) == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Test CA")));
    builder.subject = builder.issuer;
    uint8_t serial[1] = { 0x01 };
    builder.serialNumber = COctet(serial, 1);
    builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;

    CCert cert;
    REQUIRE(builder.build(cert) == ERET_OK);
    REQUIRE_FALSE(cert.empty());
    CHECK(cert.keyAlgo() == CString("Ed25519"));
    CHECK(cert.signAlgo() == CString("Ed25519"));
    CHECK(verifyCertSelfSigned(cert));
}

TEST_CASE("CCertBuilder: builds and self-signs an Ed448 certificate with a verifiable signature") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED448);
    SKeyPair kp;
    REQUIRE(ed->generateKeyPair(456, kp) == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Test CA")));
    builder.subject = builder.issuer;
    uint8_t serial[1] = { 0x01 };
    builder.serialNumber = COctet(serial, 1);
    builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;

    CCert cert;
    REQUIRE(builder.build(cert) == ERET_OK);
    REQUIRE_FALSE(cert.empty());
    CHECK(cert.keyAlgo() == CString("Ed448"));
    CHECK(cert.signAlgo() == CString("Ed448"));
    CHECK(verifyCertSelfSigned(cert));
}

TEST_CASE("CCertBuilder: builds and self-signs an RSA certificate with each PKCS#1 v1.5 digestAlgo") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair kp;
    REQUIRE(rsa->generateKeyPair(1024, kp) == ERET_OK);

    struct { EHashers hash; const char* name; } cases[] = {
        { EHASH_MD5,    "md5WithRSAEncryption" },
        { EHASH_SHA1,   "sha1WithRSAEncryption" },
        { EHASH_SHA224, "sha224WithRSAEncryption" },
        { EHASH_SHA384, "sha384WithRSAEncryption" },
        { EHASH_SHA512, "sha512WithRSAEncryption" },
    };

    for (const auto& c : cases) {
        CAPTURE(c.name);

        CCertBuilder builder;
        REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Test CA")));
        builder.subject = builder.issuer;
        uint8_t serial[1] = { 0x01 };
        builder.serialNumber = COctet(serial, 1);
        builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
        builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
        builder.subjectKey = kp.publicKey;
        builder.issuerKeyPair = kp;
        builder.digestAlgo = c.hash;

        CCert cert;
        REQUIRE(builder.build(cert) == ERET_OK);
        CHECK(cert.signAlgo() == CString(c.name));
        CHECK(verifyCertSelfSigned(cert));
    }
}

TEST_CASE("CCertBuilder: builds and self-signs a DSA certificate with each digestAlgo") {
    IAsymmetricPtr dsa = IAsymmetric::builtIn(EASYM_DSA);
    SKeyPair kp;
    ERetCode rc;
    do {
        rc = dsa->generateKeyPair(1024, kp);
    } while (rc == ERET_AGAIN);
    REQUIRE(rc == ERET_OK);

    struct { EHashers hash; const char* name; } cases[] = {
        { EHASH_SHA1,   "dsa-with-sha1" },
        { EHASH_SHA224, "dsa-with-sha224" },
    };

    for (const auto& c : cases) {
        CAPTURE(c.name);

        CCertBuilder builder;
        REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Test CA")));
        builder.subject = builder.issuer;
        uint8_t serial[1] = { 0x01 };
        builder.serialNumber = COctet(serial, 1);
        builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
        builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
        builder.subjectKey = kp.publicKey;
        builder.issuerKeyPair = kp;
        builder.digestAlgo = c.hash;

        CCert cert;
        REQUIRE(builder.build(cert) == ERET_OK);
        CHECK(cert.signAlgo() == CString(c.name));
        CHECK(verifyCertSelfSigned(cert));
    }
}

TEST_CASE("CCertBuilder: builds and self-signs a P-256 certificate with each digestAlgo") {
    IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);
    SKeyPair kp;
    REQUIRE(ec->generateKeyPair(256, kp) == ERET_OK);

    struct { EHashers hash; const char* name; } cases[] = {
        { EHASH_SHA1,   "ecdsa-with-SHA1" },
        { EHASH_SHA224, "ecdsa-with-SHA224" },
        { EHASH_SHA384, "ecdsa-with-SHA384" },
        { EHASH_SHA512, "ecdsa-with-SHA512" },
    };

    for (const auto& c : cases) {
        CAPTURE(c.name);

        CCertBuilder builder;
        REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Test CA")));
        builder.subject = builder.issuer;
        uint8_t serial[1] = { 0x01 };
        builder.serialNumber = COctet(serial, 1);
        builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
        builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
        builder.subjectKey = kp.publicKey;
        builder.issuerKeyPair = kp;
        builder.digestAlgo = c.hash;

        CCert cert;
        REQUIRE(builder.build(cert) == ERET_OK);
        CHECK(cert.signAlgo() == CString(c.name));
        CHECK(verifyCertSelfSigned(cert));
    }
}

TEST_CASE("CCertBuilder: build() rejects a digestAlgo with no defined OID for the issuer's family") {
    IAsymmetricPtr dsa = IAsymmetric::builtIn(EASYM_DSA);
    SKeyPair kp;
    ERetCode rc;
    do {
        rc = dsa->generateKeyPair(1024, kp);
    } while (rc == ERET_AGAIN);
    REQUIRE(rc == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Test CA")));
    builder.subject = builder.issuer;
    uint8_t serial[1] = { 0x01 };
    builder.serialNumber = COctet(serial, 1);
    builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;
    builder.digestAlgo = EHASH_SHA384; // dsa-with-sha384 doesn't exist as a standard OID

    CCert cert;
    CHECK(builder.build(cert) == ERET_NOTSUP);
    CHECK(cert.empty());
}

TEST_CASE("CCertBuilder: build() rejects rsaPss with a non-RSA issuer key") {
    IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);
    SKeyPair kp;
    REQUIRE(ec->generateKeyPair(256, kp) == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Test CA")));
    builder.subject = builder.issuer;
    uint8_t serial[1] = { 0x01 };
    builder.serialNumber = COctet(serial, 1);
    builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;
    builder.rsaPss = true;

    CCert cert;
    CHECK(builder.build(cert) == ERET_NOTSUP);
    CHECK(cert.empty());
}

TEST_CASE("CCertBuilder: builds and self-signs an RSASSA-PSS certificate with a verifiable signature") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair kp;
    REQUIRE(rsa->generateKeyPair(1024, kp) == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Test CA")));
    builder.subject = builder.issuer;
    uint8_t serial[1] = { 0x01 };
    builder.serialNumber = COctet(serial, 1);
    builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;
    builder.rsaPss = true; // digestAlgo left at its EHASH_SHA256 default

    CCert cert;
    REQUIRE(builder.build(cert) == ERET_OK);
    REQUIRE_FALSE(cert.empty());

    // signAlgo() resolves by OID, and the hash/salt that OID doesn't name come from the
    // AlgorithmIdentifier's own parameters -- which importDer() parses back out, so the
    // round-trip through build() -> importDer() has to report exactly what buildRsaPssParams()
    // wrote: SHA-256 for both the digest and MGF1, a salt the length of that digest, and
    // trailerField left at its DER default.
    CHECK(cert.signAlgo() == CString("rsassaPss"));

    SRsaPssParams pss;
    REQUIRE(cert.rsaPssParams(pss));
    CHECK(pss.hashAlgo == EHASH_SHA256);
    CHECK(pss.mgfHashAlgo == EHASH_SHA256);
    CHECK(pss.saltLength == 32);
    CHECK(pss.trailerField == 1);

    // And so verifyBy() can check it directly, routing through verifyPss() with those
    // parameters rather than PKCS#1 v1.5's verify().
    CHECK(cert.verifyBy(cert) == ERET_OK);

    COctet der;
    REQUIRE(cert.exportDer(der) == ERET_OK);

    SReadOnlyByteSpan outerCursor = der.toSpan();
    CTag outerTag; SReadOnlyByteSpan outerContent;
    REQUIRE(CDecoder::readNextElement(outerCursor, EAENC_DER, outerTag, outerContent));

    SReadOnlyByteSpan cursor = outerContent;
    SReadOnlyByteSpan beforeTbs = cursor;
    CTag tbsTag; SReadOnlyByteSpan tbsContent;
    REQUIRE(CDecoder::readNextElement(cursor, EAENC_DER, tbsTag, tbsContent));
    SReadOnlyByteSpan tbsFullTlv(beforeTbs.data, size_t(tbsContent.data + tbsContent.size - beforeTbs.data));

    CTag sigAlgoTag; SReadOnlyByteSpan sigAlgoContent;
    REQUIRE(CDecoder::readNextElement(cursor, EAENC_DER, sigAlgoTag, sigAlgoContent));

    CTag sigTag; SReadOnlyByteSpan sigBits;
    REQUIRE(CDecoder::readNextElement(cursor, EAENC_DER, sigTag, sigBits));

    SReadOnlyByteSpan sigValueBits;
    uint8_t unused = 0;
    REQUIRE(CDecoder::decodeBitString(sigBits, sigValueBits, unused));
    REQUIRE(unused == 0);

    IHasherPtr hasher;
    REQUIRE(IHasher::create(EHASH_SHA256, hasher) == ERET_OK);
    CBuffer digest;
    REQUIRE(digest.resize(hasher->byteWidth()));
    REQUIRE(hasher->push(tbsFullTlv));
    REQUIRE(hasher->finish(SByteSpan(digest.toPtr(), digest.size())));

    IAsymmetricContextPtr ctx = cert.createAsymmetricContext();
    REQUIRE(ctx);
    CHECK(ctx->verifyPss(digest.toSpan(), EHASH_SHA256, digest.size(), sigValueBits) == ERET_OK);

    // A tampered digest must not verify.
    CBuffer tampered = digest;
    tampered[0] = uint8_t(tampered[0] ^ 0xFF);
    CHECK(ctx->verifyPss(tampered.toSpan(), EHASH_SHA256, digest.size(), sigValueBits) != ERET_OK);
}

TEST_CASE("CCertBuilder: build() rejects an X25519 issuer key (no signing capability)") {
    IAsymmetricPtr x25519 = IAsymmetric::builtIn(EASYM_X25519);
    SKeyPair kp;
    REQUIRE(x25519->generateKeyPair(256, kp) == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Test CA")));
    builder.subject = builder.issuer;
    uint8_t serial[1] = { 0x01 };
    builder.serialNumber = COctet(serial, 1);
    builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;

    CCert cert;
    CHECK(builder.build(cert) == ERET_NOTSUP);
    CHECK(cert.empty());
}

TEST_CASE("CCertBuilder: build() rejects missing required fields") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair kp;
    REQUIRE(rsa->generateKeyPair(1024, kp) == ERET_OK);

    CCertBuilder builder; // everything left default/empty
    CCert cert;
    CHECK(builder.build(cert) == ERET_INVAL);
    CHECK(cert.empty());

    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;
    // issuer/subject/serialNumber still unset.
    CHECK(builder.build(cert) == ERET_INVAL);
    CHECK(cert.empty());
}
