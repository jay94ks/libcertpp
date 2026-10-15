#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;
using namespace certpp::crypto;
using namespace certpp::x509;

namespace {

    SKeyPair generate() {
        IAsymmetricPtr algorithm = IAsymmetric::builtIn(EASYM_P256);
        SKeyPair pair;
        if (algorithm) {
            algorithm->generateKeyPair(256, pair);
        }
        return pair;
    }

    IExtensionPtr basicConstraints(bool isCa, int pathLen = -1) {
        CBasicConstraintsExtensionBuilder builder;
        builder.setIsCa(isCa);
        if (pathLen >= 0) {
            builder.setPathLenConstraint(pathLen);
        }
        IExtensionPtr result = builder.build();
        if (result) {
            result->critical(true);
        }
        return result;
    }

    IExtensionPtr keyUsage(uint16_t bits) {
        CKeyUsagesExtensionBuilder builder;
        builder.setBits(bits);
        IExtensionPtr result = builder.build();
        if (result) {
            result->critical(true);
        }
        return result;
    }

    bool issue(
        CCert& out,
        const char* subject,
        const char* issuer,
        const IPublicKeyPtr& subjectKey,
        const SKeyPair& issuerKey,
        uint8_t serial,
        const TArray<IExtensionPtr>& extensions,
        const SDateTime& notBefore = SDateTime(2025, 1, 1, 0, 0, 0, 0, true),
        const SDateTime& notAfter = SDateTime(2035, 1, 1, 0, 0, 0, 0, true)
    ) {
        CCertBuilder builder;
        if (!CDistinguishedName::tryParse(builder.subject, CString(subject))
            || !CDistinguishedName::tryParse(builder.issuer, CString(issuer)))
        {
            return false;
        }

        builder.serialNumber = COctet(&serial, 1);
        builder.notBefore = notBefore;
        builder.notAfter = notAfter;
        builder.subjectKey = subjectKey;
        builder.issuerKeyPair = issuerKey;
        builder.extensions = extensions;
        return builder.build(out) == ERET_OK;
    }

    struct SHierarchy {
        SKeyPair rootKey;
        SKeyPair intermediateKey;
        SKeyPair leafKey;
        CCert root;
        CCert intermediate;
        CCert leaf;

        bool build(
            int rootPathLen = 1,
            uint16_t intermediateUsage = EKUSE_KEY_CERT_SIGN,
            const IExtensionPtr& leafExtra = nullptr,
            const IExtensionPtr& intermediateExtra = nullptr
        ) {
            rootKey = generate();
            intermediateKey = generate();
            leafKey = generate();
            if (!rootKey.publicKey || !intermediateKey.publicKey || !leafKey.publicKey) {
                return false;
            }

            TArray<IExtensionPtr> rootExtensions;
            rootExtensions.add(basicConstraints(true, rootPathLen));
            rootExtensions.add(keyUsage(EKUSE_KEY_CERT_SIGN | EKUSE_CRL_SIGN));

            TArray<IExtensionPtr> intermediateExtensions;
            intermediateExtensions.add(basicConstraints(true, 0));
            intermediateExtensions.add(keyUsage(intermediateUsage));
            if (intermediateExtra) {
                intermediateExtensions.add(intermediateExtra);
            }

            TArray<IExtensionPtr> leafExtensions;
            leafExtensions.add(keyUsage(EKUSE_DIGITAL_SIGNATURE));
            if (leafExtra) {
                leafExtensions.add(leafExtra);
            }

            return issue(root, "CN=Root", "CN=Root", rootKey.publicKey, rootKey, 1, rootExtensions)
                && issue(intermediate, "CN=Intermediate", "CN=Root", intermediateKey.publicKey,
                         rootKey, 2, intermediateExtensions)
                && issue(leaf, "CN=Leaf", "CN=Intermediate", leafKey.publicKey,
                         intermediateKey, 3, leafExtensions);
        }

        CCertCollection intermediates() const {
            CCertCollection result;
            size_t index = 0;
            result.add(intermediate, index);
            return result;
        }

        CTrustStore trustStore() const {
            CTrustStore result;
            result.add(root);
            return result;
        }
    };

} // namespace

TEST_CASE("CPathValidator builds and validates a trusted hierarchy") {
    SHierarchy hierarchy;
    REQUIRE(hierarchy.build());

    SPathValidationPolicy policy;
    policy.validationTime = SDateTime(2026, 6, 1, 0, 0, 0, 0, true);
    policy.requiredLeafKeyUsages = EKUSE_DIGITAL_SIGNATURE;

    SPathValidationResult result = CPathValidator::validate(
        hierarchy.leaf, hierarchy.intermediates(), hierarchy.trustStore(), policy
    );
    REQUIRE(result.ok());
    CHECK(result.path.size() == 3);
    CHECK(result.path[0].subject() == hierarchy.leaf.subject());
    CHECK(result.path[2].subject() == hierarchy.root.subject());
}

TEST_CASE("CPathValidator requires an explicit trust anchor") {
    SHierarchy hierarchy;
    REQUIRE(hierarchy.build());

    CTrustStore emptyTrust;
    SPathValidationPolicy policy;
    policy.validationTime = SDateTime(2026, 6, 1, 0, 0, 0, 0, true);
    SPathValidationResult result = CPathValidator::validate(
        hierarchy.leaf, hierarchy.intermediates(), emptyTrust, policy
    );
    CHECK(result.status == EPATH_INCOMPLETE);

    TArray<CCert> ordered;
    ordered.add(hierarchy.leaf);
    ordered.add(hierarchy.intermediate);
    ordered.add(hierarchy.root);
    result = CPathValidator::validateOrdered(ordered, emptyTrust, policy);
    CHECK(result.status == EPATH_UNTRUSTED_ROOT);
}

TEST_CASE("CPathValidator enforces CA and KeyUsage constraints") {
    SHierarchy hierarchy;
    REQUIRE(hierarchy.build(1, EKUSE_DIGITAL_SIGNATURE));

    SPathValidationPolicy policy;
    policy.validationTime = SDateTime(2026, 6, 1, 0, 0, 0, 0, true);
    SPathValidationResult result = CPathValidator::validate(
        hierarchy.leaf, hierarchy.intermediates(), hierarchy.trustStore(), policy
    );
    CHECK(result.status == EPATH_KEY_USAGE);
    CHECK(result.certificateIndex == 1);
}

TEST_CASE("CPathValidator enforces validity periods") {
    SHierarchy hierarchy;
    REQUIRE(hierarchy.build());

    SPathValidationPolicy policy;
    policy.validationTime = SDateTime(2040, 1, 1, 0, 0, 0, 0, true);
    SPathValidationResult result = CPathValidator::validate(
        hierarchy.leaf, hierarchy.intermediates(), hierarchy.trustStore(), policy
    );
    CHECK(result.status == EPATH_EXPIRED);
    CHECK(result.certificateIndex == 0);
}

TEST_CASE("CPathValidator enforces DNS NameConstraints") {
    CSanExtensionBuilder sanBuilder;
    sanBuilder.addName(CGeneralName(EGNAME_DNS, CString("www.example.com")));

    CNameConstraintsExtensionBuilder permittedBuilder;
    permittedBuilder.addPermittedSubtree(
        CGeneralSubtree(CGeneralName(EGNAME_DNS, CString("example.com")), 0, false, 0)
    );
    IExtensionPtr permitted = permittedBuilder.build();
    REQUIRE(permitted);
    permitted->critical(true);

    SHierarchy accepted;
    REQUIRE(accepted.build(1, EKUSE_KEY_CERT_SIGN, sanBuilder.build(), permitted));
    SPathValidationPolicy policy;
    policy.validationTime = SDateTime(2026, 6, 1, 0, 0, 0, 0, true);
    CHECK(CPathValidator::validate(
        accepted.leaf, accepted.intermediates(), accepted.trustStore(), policy
    ).ok());

    CSanExtensionBuilder badSanBuilder;
    badSanBuilder.addName(CGeneralName(EGNAME_DNS, CString("www.invalid.test")));
    SHierarchy rejected;
    REQUIRE(rejected.build(1, EKUSE_KEY_CERT_SIGN, badSanBuilder.build(), permitted));
    SPathValidationResult rejectedResult = CPathValidator::validate(
        rejected.leaf, rejected.intermediates(), rejected.trustStore(), policy
    );
    CHECK(rejectedResult.status == EPATH_NAME_CONSTRAINT);
    CHECK(rejectedResult.certificateIndex == 0);
}

TEST_CASE("CPathValidator rejects an unknown critical extension") {
    uint8_t nullValue[] = { 0x05, 0x00 };
    IExtensionPtr unknown = IExtension::create(COid("1.3.6.1.4.1.55555.1"), COctet(nullValue, sizeof(nullValue)));
    REQUIRE(unknown);
    unknown->critical(true);

    SHierarchy hierarchy;
    REQUIRE(hierarchy.build(1, EKUSE_KEY_CERT_SIGN, unknown));
    SPathValidationPolicy policy;
    policy.validationTime = SDateTime(2026, 6, 1, 0, 0, 0, 0, true);
    SPathValidationResult result = CPathValidator::validate(
        hierarchy.leaf, hierarchy.intermediates(), hierarchy.trustStore(), policy
    );
    CHECK(result.status == EPATH_UNKNOWN_CRITICAL_EXTENSION);
    CHECK(result.certificateIndex == 0);
}

TEST_CASE("CPathValidator reports unavailable optional validation capabilities") {
    SHierarchy hierarchy;
    REQUIRE(hierarchy.build());

    SPathValidationPolicy policy;
    policy.validationTime = SDateTime(2026, 6, 1, 0, 0, 0, 0, true);
    policy.requireRevocation = true;
    CHECK(CPathValidator::validate(
        hierarchy.leaf, hierarchy.intermediates(), hierarchy.trustStore(), policy
    ).status == EPATH_REVOCATION_UNAVAILABLE);

    policy.requireRevocation = false;
    policy.requirePolicyProcessing = true;
    CHECK(CPathValidator::validate(
        hierarchy.leaf, hierarchy.intermediates(), hierarchy.trustStore(), policy
    ).status == EPATH_POLICY_PROCESSING_UNAVAILABLE);
}
