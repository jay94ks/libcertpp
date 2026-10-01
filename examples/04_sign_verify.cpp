// Example 4: sign and verify data using a certificate's own asymmetric key pair.
//
// CCert::signData()/verifyData() hash arbitrary data with the certificate's own signature
// algorithm (signAlgo()'s digest, or none at all for a self-hashing scheme like Ed25519/Ed448)
// and sign/verify it with the certificate's private/public key -- signData() needs a private
// key attached (via importPem() parsing one out of the file, or privateKey(IPrivateKeyPtr&)),
// verifyData() only ever needs the public key, which every certificate always has.
//
// Run 01_issue_ca_root.cpp, 02_issue_intermediate.cpp, and 03_issue_leaf.cpp first, to produce
// the leaf certificate + private key this example signs with.

#include "common.hpp"
#include <cstring>

using namespace certpp;
using namespace certpp::x509;

int main() {
    // 1. Load the leaf certificate + private key example 3 wrote.
    CCert leafCert;
    if (!examples::loadCertPem("leaf.pem", leafCert)) {
        return 1;
    }

    if (!leafCert.privateKey()) {
        std::fprintf(stderr, "leaf.pem has no private key attached\n");
        return 1;
    }

    std::printf("Signing with:\n");
    examples::printCertSummary(leafCert);

    // 2. Sign a message with the leaf's own private key.
    const char* message = "This message was signed by leaf.pem's private key.";
    SReadOnlyByteSpan messageSpan(reinterpret_cast<const uint8_t*>(message), std::strlen(message));

    uint8_t signatureBuf[512];
    SByteSpan signature(signatureBuf, sizeof(signatureBuf));

    ERetCode rc = leafCert.signData(messageSpan, signature);
    if (rc != ERET_OK) {
        std::fprintf(stderr, "signData failed: rc=%d\n", int(rc));
        return 1;
    }

    std::printf("\nSigned %zu bytes of data, producing a %zu-byte signature.\n", messageSpan.size, signature.size);

    // 3. Verify it back against the same certificate -- verifyData() only reads the public key,
    // so this would work identically even if leafCert had never had a private key attached
    // (e.g. a certificate received from a peer, imported via importDer()/importPem() alone).
    rc = leafCert.verifyData(messageSpan, SReadOnlyByteSpan(signature.data, signature.size));
    std::printf("Verifying the genuine message: %s\n", rc == ERET_OK ? "OK" : "FAILED");
    if (rc != ERET_OK) {
        return 1;
    }

    // 4. A tampered message must fail verification -- this is the whole point of signing.
    const char* tampered = "This message was NOT signed by leaf.pem's private key.";
    SReadOnlyByteSpan tamperedSpan(reinterpret_cast<const uint8_t*>(tampered), std::strlen(tampered));

    rc = leafCert.verifyData(tamperedSpan, SReadOnlyByteSpan(signature.data, signature.size));
    std::printf("Verifying a tampered message:  %s (expected to fail)\n", rc == ERET_OK ? "OK" : "FAILED");
    if (rc == ERET_OK) {
        std::fprintf(stderr, "a tampered message verified successfully -- this should never happen\n");
        return 1;
    }

    // 5. The same check again, this time using only the public certificate (no private key at
    // all) -- exactly what a peer receiving leaf.pem over the network, without leaf's private
    // key, would do to authenticate data signed by it.
    COctet publicOnlyDer;
    if (leafCert.exportDer(publicOnlyDer) != ERET_OK) {
        return 1;
    }

    CCert publicOnlyCert;
    if (publicOnlyCert.importDer(publicOnlyDer) != ERET_OK) {
        return 1;
    }

    rc = publicOnlyCert.verifyData(messageSpan, SReadOnlyByteSpan(signature.data, signature.size));
    std::printf("Verifying with the public key alone: %s\n", rc == ERET_OK ? "OK" : "FAILED");

    return rc == ERET_OK ? 0 : 1;
}
