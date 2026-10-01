// Example 1: issue a self-signed CA root certificate.
//
// A root CA certificate is the trust anchor of a certification path: its issuer and subject
// are the same name, and it's signed by its own private key rather than someone else's. This
// example generates a fresh P-256 key pair, builds a root certificate around it with
// CCertBuilder, and writes both the certificate and its private key to examples/output/.
//
// Run this before 02_issue_intermediate.cpp, which signs an intermediate certificate with the
// root key pair this example produces.

#include "common.hpp"

using namespace certpp;
using namespace certpp::x509;
using namespace certpp::crypto;

int main() {
    // 1. Generate the root CA's own key pair. P-256 (NIST P-256 / secp256r1) is a solid,
    // widely-interoperable modern default; generateKeyPair() can occasionally reject a freshly
    // generated candidate (ERET_AGAIN) if it fails CEcdsa's own internal validation, so retrying
    // is the documented way to handle that -- see IAsymmetric::generateKeyPair()'s doc comment.
    IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);

    SKeyPair rootKeyPair;
    ERetCode rc;
    do {
        rc = ec->generateKeyPair(256, rootKeyPair);
    } while (rc == ERET_AGAIN);

    if (rc != ERET_OK) {
        std::fprintf(stderr, "generateKeyPair failed: rc=%d\n", int(rc));
        return 1;
    }

    // 2. Compute the root's SubjectKeyIdentifier up front (SHA-1 of its own public key bytes,
    // RFC 5280 4.2.1.2 method 1): the intermediate certificate the next example issues will
    // reference this same value in its own AuthorityKeyIdentifier extension, letting a path-
    // building verifier match a child certificate back to the issuer that signed it.
    COctet rootPublicKeyBytes;
    if (rootKeyPair.publicKey->serialize(rootPublicKeyBytes) != ERET_OK) {
        std::fprintf(stderr, "failed to serialize the root public key\n");
        return 1;
    }

    IHasherPtr sha1;
    IHasher::create(EHASH_SHA1, sha1);
    uint8_t skiBytes[20];
    sha1->push(rootPublicKeyBytes.toSpan());
    sha1->finish(SByteSpan(skiBytes, sizeof(skiBytes)));
    COctet rootSki(skiBytes, sizeof(skiBytes));

    // 3. Fill in CCertBuilder's fields. issuer == subject (both this root's own name) is what
    // makes exportPem()/importPem() -- and any other implementation -- treat this as self-signed.
    CCertBuilder builder;
    if (!CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp Demo, CN=libcertpp Demo Root CA"))) {
        std::fprintf(stderr, "failed to parse the root's distinguished name\n");
        return 1;
    }
    builder.subject = builder.issuer;

    builder.serialNumber = examples::randomSerialNumber();

    builder.notBefore = SDateTime::now(true);
    builder.notAfter = builder.notBefore;
    builder.notAfter.year += 20; // a long validity period, typical for a root CA

    builder.subjectKey = rootKeyPair.publicKey;
    builder.issuerKeyPair = rootKeyPair; // signs itself

    // A root CA certificate's extensions: it may certify other CAs (no pathLenConstraint, so
    // any number of intermediates may follow it), its key is only ever used to sign
    // certificates/CRLs (never to directly sign TLS traffic), and it carries its own SKI so
    // children can reference it via their own AuthorityKeyIdentifier.
    CBasicConstraintsExtensionBuilder basicConstraints;
    basicConstraints.setIsCa(true);
    builder.extensions.add(basicConstraints.build());

    CKeyUsagesExtensionBuilder keyUsage;
    keyUsage.setBits(EKUSE_KEY_CERT_SIGN | EKUSE_CRL_SIGN);
    builder.extensions.add(keyUsage.build());

    CSkiExtensionBuilder ski;
    ski.setKeyIdentifier(rootSki);
    builder.extensions.add(ski.build());

    // 4. Build and sign.
    CCert rootCert;
    rc = builder.build(rootCert);
    if (rc != ERET_OK) {
        std::fprintf(stderr, "CCertBuilder::build failed: rc=%d\n", int(rc));
        return 1;
    }

    std::printf("Issued root CA certificate:\n");
    examples::printCertSummary(rootCert);

    // 5. CCertBuilder::build() never attaches a private key to the certificate it returns (see
    // its own doc comment) -- reattach the same key pair's private half explicitly, so
    // exportPem() below can include it.
    if (rootCert.privateKey(rootKeyPair.privateKey) != ERET_OK) {
        std::fprintf(stderr, "failed to attach the root's own private key\n");
        return 1;
    }

    // 6. Save both the certificate and its private key -- the next example needs the private
    // key to sign the intermediate certificate with.
    if (!examples::writeCertPem("ca_root.pem", rootCert, /*includePrivateKey=*/true)) {
        return 1;
    }

    return 0;
}
