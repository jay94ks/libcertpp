// Example 2: issue an intermediate CA certificate, signed by a root CA.
//
// An intermediate certificate sits between a root and the leaf certificates it eventually
// signs: its issuer is the root's subject, and it's signed with the root's private key rather
// than its own. This example loads the root CA example 1 produced, generates a fresh key pair
// for the intermediate, and issues a certificate for that key signed by the root.
//
// Run 01_issue_ca_root.cpp first. Run this before 03_issue_leaf.cpp, which signs a leaf
// certificate with the intermediate key pair this example produces.

#include "common.hpp"

using namespace certpp;
using namespace certpp::x509;
using namespace certpp::crypto;

int main() {
    // 1. Load the root CA certificate + private key example 1 wrote.
    CCert rootCert;
    if (!examples::loadCertPem("ca_root.pem", rootCert)) {
        return 1;
    }

    IPrivateKeyPtr rootPrivateKey = rootCert.privateKey();
    if (!rootPrivateKey) {
        std::fprintf(stderr, "ca_root.pem has no private key attached\n");
        return 1;
    }

    // 2. Generate the intermediate's own key pair.
    IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);

    SKeyPair intermediateKeyPair;
    ERetCode rc;
    do {
        rc = ec->generateKeyPair(256, intermediateKeyPair);
    } while (rc == ERET_AGAIN);

    if (rc != ERET_OK) {
        std::fprintf(stderr, "generateKeyPair failed: rc=%d\n", int(rc));
        return 1;
    }

    // 3. This certificate's own SubjectKeyIdentifier, the same way example 1 computed the
    // root's -- the leaf certificate the next example issues will reference this value in its
    // own AuthorityKeyIdentifier.
    COctet intermediatePublicKeyBytes;
    if (intermediateKeyPair.publicKey->serialize(intermediatePublicKeyBytes) != ERET_OK) {
        std::fprintf(stderr, "failed to serialize the intermediate public key\n");
        return 1;
    }

    IHasherPtr sha1;
    IHasher::create(EHASH_SHA1, sha1);
    uint8_t skiBytes[20];
    sha1->push(intermediatePublicKeyBytes.toSpan());
    sha1->finish(SByteSpan(skiBytes, sizeof(skiBytes)));
    COctet intermediateSki(skiBytes, sizeof(skiBytes));

    // 4. The root's own SubjectKeyIdentifier, extracted from the certificate we just loaded --
    // this becomes the intermediate's AuthorityKeyIdentifier, tying the two together the way a
    // path-building verifier expects.
    COctet rootSki;
    if (rootCert.subjectKeyIdentifier(rootSki) != ERET_OK) {
        std::fprintf(stderr, "ca_root.pem has no SubjectKeyIdentifier extension\n");
        return 1;
    }

    // 5. Fill in CCertBuilder's fields. The issuer is the root's own subject (i.e. this
    // certificate's issuer name must match the root's, for the certification path to link up).
    CCertBuilder builder;
    builder.issuer = rootCert.subject();
    if (!CDistinguishedName::tryParse(builder.subject, CString("C=US, O=libcertpp Demo, CN=libcertpp Demo Intermediate CA"))) {
        std::fprintf(stderr, "failed to parse the intermediate's distinguished name\n");
        return 1;
    }

    builder.serialNumber = examples::randomSerialNumber();

    builder.notBefore = SDateTime::now(true);
    builder.notAfter = builder.notBefore;
    builder.notAfter.year += 10; // shorter than the root's own validity period

    builder.subjectKey = intermediateKeyPair.publicKey;
    builder.issuerKeyPair = SKeyPair(rootCert.publicKey(), rootPrivateKey); // signed by the root

    // pathLenConstraint(0) means no further intermediates may follow this one -- only leaf
    // certificates may be issued directly under it.
    CBasicConstraintsExtensionBuilder basicConstraints;
    basicConstraints.setIsCa(true).setPathLenConstraint(0);
    builder.extensions.add(basicConstraints.build());

    CKeyUsagesExtensionBuilder keyUsage;
    keyUsage.setBits(EKUSE_KEY_CERT_SIGN | EKUSE_CRL_SIGN);
    builder.extensions.add(keyUsage.build());

    CSkiExtensionBuilder ski;
    ski.setKeyIdentifier(intermediateSki);
    builder.extensions.add(ski.build());

    CAkiExtensionBuilder aki;
    aki.setKeyIdentifier(rootSki);
    builder.extensions.add(aki.build());

    // 6. Build and sign.
    CCert intermediateCert;
    rc = builder.build(intermediateCert);
    if (rc != ERET_OK) {
        std::fprintf(stderr, "CCertBuilder::build failed: rc=%d\n", int(rc));
        return 1;
    }

    std::printf("Issued intermediate CA certificate:\n");
    examples::printCertSummary(intermediateCert);

    // 7. CCertBuilder::build() never attaches a private key to the certificate it returns --
    // reattach the intermediate's own private half explicitly, so exportPem() below can
    // include it.
    if (intermediateCert.privateKey(intermediateKeyPair.privateKey) != ERET_OK) {
        std::fprintf(stderr, "failed to attach the intermediate's own private key\n");
        return 1;
    }

    // 8. Save both the certificate and its private key -- the next example needs the private
    // key to sign the leaf certificate with.
    if (!examples::writeCertPem("intermediate.pem", intermediateCert, /*includePrivateKey=*/true)) {
        return 1;
    }

    return 0;
}
