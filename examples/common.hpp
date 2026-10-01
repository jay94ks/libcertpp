// Small shared helpers for the examples/ programs -- not part of libcertpp's own public API,
// just file I/O and printing boilerplate so each example can focus on the certpp calls that
// actually matter.
#ifndef __CERTPP_EXAMPLES_COMMON_HPP__
#define __CERTPP_EXAMPLES_COMMON_HPP__

#include <certpp.hpp>
#include <cstdio>
#include <string>
#include <vector>

namespace examples {

    // CERTPP_EXAMPLE_OUTPUT_DIR is injected by CMakeLists.txt: an absolute path to
    // examples/output/, so the certificates these examples produce always land in one
    // predictable, gitignored place regardless of the current working directory the example
    // happens to be run from.
    inline std::string outputPath(const char* fileName) {
#ifdef CERTPP_EXAMPLE_OUTPUT_DIR
        return std::string(CERTPP_EXAMPLE_OUTPUT_DIR) + "/" + fileName;
#else
        return fileName;
#endif
    }

    inline bool writeFile(const std::string& path, const certpp::COctet& data) {
        FILE* f = std::fopen(path.c_str(), "wb");
        if (!f) {
            return false;
        }

        bool ok = std::fwrite(data.toPtr(), 1, data.size(), f) == data.size();
        std::fclose(f);
        return ok;
    }

    inline bool readFile(const std::string& path, certpp::COctet& out) {
        FILE* f = std::fopen(path.c_str(), "rb");
        if (!f) {
            return false;
        }

        std::fseek(f, 0, SEEK_END);
        long size = std::ftell(f);
        std::fseek(f, 0, SEEK_SET);

        if (size <= 0) {
            std::fclose(f);
            return false;
        }

        std::vector<uint8_t> buf(static_cast<size_t>(size));
        bool ok = std::fread(buf.data(), 1, buf.size(), f) == buf.size();
        std::fclose(f);

        if (!ok) {
            return false;
        }

        out = certpp::COctet(buf.data(), buf.size());
        return true;
    }

    // Loads a certificate (and, if the PEM file has one, its private key) from a PEM file
    // previously written by one of these examples' own writeCertPem(), printing a clear error
    // if it's missing -- almost every example after the first one starts by loading whatever
    // the previous example issued.
    inline bool loadCertPem(const char* fileName, certpp::x509::CCert& out) {
        certpp::COctet pem;
        std::string path = outputPath(fileName);
        if (!readFile(path, pem)) {
            std::fprintf(stderr, "Couldn't read %s -- run the previous example first.\n", path.c_str());
            return false;
        }

        certpp::ERetCode rc = out.importPem(pem);
        if (rc != certpp::ERET_OK) {
            std::fprintf(stderr, "Failed to parse %s (rc=%d)\n", path.c_str(), int(rc));
            return false;
        }

        return true;
    }

    // Exports cert as PEM (optionally including its attached private key) and writes it to
    // examples/output/<fileName>.
    inline bool writeCertPem(const char* fileName, const certpp::x509::CCert& cert, bool includePrivateKey) {
        certpp::COctet pem;
        if (cert.exportPem(pem, includePrivateKey) != certpp::ERET_OK) {
            std::fprintf(stderr, "Failed to export %s\n", fileName);
            return false;
        }

        std::string path = outputPath(fileName);
        if (!writeFile(path, pem)) {
            std::fprintf(stderr, "Failed to write %s\n", path.c_str());
            return false;
        }

        std::printf("Wrote %s (%zu bytes)\n", path.c_str(), pem.size());
        return true;
    }

    // A random, always-positive serial number (RFC 5280 recommends an unpredictable one; a
    // 20-byte value is the largest this library's own COctet-based serialNumber() convention
    // ever needs to represent -- see CCert::serialNumber()'s own doc comment).
    inline certpp::COctet randomSerialNumber() {
        uint8_t bytes[16];
        certpp::crypto::CRng::fill(certpp::SByteSpan(bytes, sizeof(bytes)));
        bytes[0] &= 0x7F; // clear the sign bit so this always DER-encodes as a positive INTEGER
        return certpp::COctet(bytes, sizeof(bytes));
    }

    inline void printCertSummary(const certpp::x509::CCert& cert) {
        std::printf("  Subject:     %s\n", cert.subjectStr().toPtr());
        std::printf("  Issuer:      %s\n", cert.issuerStr().toPtr());
        std::printf("  Key algo:    %s\n", cert.keyAlgo().toPtr());
        std::printf("  Sign algo:   %s\n", cert.signAlgo().toPtr());
        std::printf("  Not before:  %04u-%02u-%02u\n", cert.notBefore().year, cert.notBefore().month, cert.notBefore().day);
        std::printf("  Not after:   %04u-%02u-%02u\n", cert.notAfter().year, cert.notAfter().month, cert.notAfter().day);
    }

}

#endif
