// Example 3: issue a leaf (end-entity) certificate, signed by an intermediate CA.
//
// A leaf certificate is what actually gets presented by a server (or client, or whatever the
// end entity is) -- it can't itself sign other certificates, and it typically carries usage-
// restricting extensions a CA certificate wouldn't (here: ExtendedKeyUsage restricting it to
// TLS server authentication, and a SubjectAltName carrying the DNS name it's valid for).
//
// Run 01_issue_ca_root.cpp and 02_issue_intermediate.cpp first. Run this before
// 04_sign_verify.cpp, which uses the leaf key pair this example produces to sign and verify
// arbitrary data.

#include "common.hpp"

using namespace certpp;
using namespace certpp::x509;
using namespace certpp::crypto;

int main() {
    // 1. Load the intermediate CA certificate + private key example 2 wrote.
    CCert intermediateCert;
    if (!examples::loadCertPem("intermediate.pem", intermediateCert)) {
        return 1;
    }

    IPrivateKeyPtr intermediatePrivateKey = intermediateCert.privateKey();
    if (!intermediatePrivateKey) {
        std::fprintf(stderr, "intermediate.pem has no private key attached\n");
        return 1;
    }

    // 2. Generate the leaf's own key pair.
    IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);

    SKeyPair leafKeyPair;
    ERetCode rc;
    do {
        rc = ec->generateKeyPair(256, leafKeyPair);
    } while (rc == ERET_AGAIN);

    if (rc != ERET_OK) {
        std::fprintf(stderr, "generateKeyPair failed: rc=%d\n", int(rc));
        return 1;
    }

    // 3. This certificate's own SubjectKeyIdentifier, and the intermediate's SubjectKeyIdentifier
    // (from the certificate we just loaded) for this leaf's own AuthorityKeyIdentifier -- same
    // pattern as example 2 used against the root.
    COctet leafPublicKeyBytes;
    if (leafKeyPair.publicKey->serialize(leafPublicKeyBytes) != ERET_OK) {
        std::fprintf(stderr, "failed to serialize the leaf public key\n");
        return 1;
    }

    IHasherPtr sha1;
    IHasher::create(EHASH_SHA1, sha1);
    uint8_t skiBytes[20];
    sha1->push(leafPublicKeyBytes.toSpan());
    sha1->finish(SByteSpan(skiBytes, sizeof(skiBytes)));
    COctet leafSki(skiBytes, sizeof(skiBytes));

    COctet intermediateSki;
    if (intermediateCert.subjectKeyIdentifier(intermediateSki) != ERET_OK) {
        std::fprintf(stderr, "intermediate.pem has no SubjectKeyIdentifier extension\n");
        return 1;
    }

    // 4. Fill in CCertBuilder's fields.
    CCertBuilder builder;
    builder.issuer = intermediateCert.subject();
    if (!CDistinguishedName::tryParse(builder.subject, CString("C=US, O=libcertpp Demo, CN=example.libcertpp.local"))) {
        std::fprintf(stderr, "failed to parse the leaf's distinguished name\n");
        return 1;
    }

    builder.serialNumber = examples::randomSerialNumber();

    builder.notBefore = SDateTime::now(true);
    builder.notAfter = builder.notBefore;
    builder.notAfter.year += 1; // short-lived, typical for a leaf/end-entity certificate

    builder.subjectKey = leafKeyPair.publicKey;
    builder.issuerKeyPair = SKeyPair(intermediateCert.publicKey(), intermediatePrivateKey);

    // A TLS server leaf's usual extension set: not a CA at all, restricted to digital-signature
    // and key-encipherment use (TLS 1.2's RSA/ECDHE key exchange and signing), restricted to
    // TLS server authentication specifically, and the DNS name(s) it's actually valid for.
    CBasicConstraintsExtensionBuilder basicConstraints;
    basicConstraints.setIsCa(false);
    builder.extensions.add(basicConstraints.build());

    CKeyUsagesExtensionBuilder keyUsage;
    keyUsage.setBits(EKUSE_DIGITAL_SIGNATURE | EKUSE_KEY_ENCIPHERMENT);
    builder.extensions.add(keyUsage.build());

    CEkuExtensionBuilder eku;
    eku.addPurpose(CEkuExtension::OID_SERVER_AUTH);
    builder.extensions.add(eku.build());

    CSanExtensionBuilder san;
    san.addName(CGeneralName(EGNAME_DNS, CString("example.libcertpp.local")));
    san.addName(CGeneralName(EGNAME_DNS, CString("www.example.libcertpp.local")));
    builder.extensions.add(san.build());

    CSkiExtensionBuilder ski;
    ski.setKeyIdentifier(leafSki);
    builder.extensions.add(ski.build());

    CAkiExtensionBuilder aki;
    aki.setKeyIdentifier(intermediateSki);
    builder.extensions.add(aki.build());

    // 5. Build and sign.
    CCert leafCert;
    rc = builder.build(leafCert);
    if (rc != ERET_OK) {
        std::fprintf(stderr, "CCertBuilder::build failed: rc=%d\n", int(rc));
        return 1;
    }

    std::printf("Issued leaf certificate:\n");
    examples::printCertSummary(leafCert);

    // 6. CCertBuilder::build() never attaches a private key to the certificate it returns --
    // reattach the leaf's own private half explicitly, so exportPem() below can include it.
    if (leafCert.privateKey(leafKeyPair.privateKey) != ERET_OK) {
        std::fprintf(stderr, "failed to attach the leaf's own private key\n");
        return 1;
    }

    // 7. Save both the certificate and its private key -- the next example signs data with it.
    if (!examples::writeCertPem("leaf.pem", leafCert, /*includePrivateKey=*/true)) {
        return 1;
    }

    return 0;
}
