#ifndef __INCLUDE_CERTPP_X509_VALIDATOR_HPP__
#define __INCLUDE_CERTPP_X509_VALIDATOR_HPP__

#include <certpp/common.hpp>
#include <certpp/io/array.hpp>
#include <certpp/oid.hpp>
#include <certpp/time.hpp>
#include <certpp/x509/cert.hpp>
#include <certpp/x509/chain.hpp>
#include <vector>

namespace certpp {
namespace x509 {

    /** The outcome of certification-path validation. */
    enum EPathValidationStatus {
        EPATH_OK = 0,
        EPATH_EMPTY,
        EPATH_TOO_DEEP,
        EPATH_INCOMPLETE,
        EPATH_UNTRUSTED_ROOT,
        EPATH_ISSUER_NAME_MISMATCH,
        EPATH_SIGNATURE_INVALID,
        EPATH_NOT_YET_VALID,
        EPATH_EXPIRED,
        EPATH_CA_REQUIRED,
        EPATH_KEY_USAGE,
        EPATH_EXTENDED_KEY_USAGE,
        EPATH_PATH_LENGTH,
        EPATH_UNKNOWN_CRITICAL_EXTENSION,
        EPATH_UNSUPPORTED_CRITICAL_EXTENSION,
        EPATH_NAME_CONSTRAINT,
        EPATH_UNSUPPORTED_NAME_CONSTRAINT,
        EPATH_REVOCATION_UNAVAILABLE,
        EPATH_POLICY_PROCESSING_UNAVAILABLE,
    };

    /** Policy inputs for CPathValidator. */
    struct CERTPP_API SPathValidationPolicy {
        /** Time at which the path is evaluated; zero means current UTC time. */
        SDateTime validationTime;

        /** Required KeyUsage bits on the leaf; zero means no application-specific requirement. */
        uint16_t requiredLeafKeyUsages = 0;

        /** Required EKU purpose on the leaf and any constraining CA; empty means no EKU requirement. */
        COid requiredExtendedKeyPurpose;

        /** Maximum number of certificates in the completed path, leaf and anchor included. */
        size_t maxDepth = CCertCollection::MAX_DEPTH;

        /** Whether every certificate must contain the validation time. */
        bool checkTime = true;

        /** Whether supported DNS, email, URI, and IP name constraints are enforced. */
        bool checkNameConstraints = true;

        /** Whether an unrecognized critical extension rejects the path. */
        bool rejectUnknownCriticalExtensions = true;

        /** Requests a capability the core validator does not claim to provide yet. */
        bool requireRevocation = false;

        /** Requests RFC 5280 policy-tree processing, which is not provided yet. */
        bool requirePolicyProcessing = false;
    };

    /** A diagnostic validation result. certificateIndex is leaf-first. */
    struct CERTPP_API SPathValidationResult {
        /** Overall validation outcome. */
        EPathValidationStatus status = EPATH_EMPTY;
        /** Index of the failing certificate in the leaf-first path, or size_t(-1). */
        size_t certificateIndex = size_t(-1);
        /** Lower-level error when a signature or decode operation supplies one. */
        ERetCode detail = ERET_OK;
        /** Completed leaf-first path, including the trust anchor when one was found. */
        TArray<CCert> path;

        /** Returns true exactly when status is EPATH_OK. */
        inline bool ok() const { return status == EPATH_OK; }
        /** Allows a result to be tested directly in a condition. */
        inline operator bool() const { return ok(); }
    };

    /** Explicit set of trust anchors used by CPathValidator. */
    class CERTPP_API CTrustStore {
    private:
        std::vector<CCert> _anchors;

    public:
        /** Adds a parsed certificate as an explicit trust anchor. */
        ERetCode add(const CCert& anchor);
        /** Removes every trust anchor. */
        void clear();
        /** Returns the number of trust anchors. */
        size_t count() const;
        /** Copies the anchor at index into out, returning false for an invalid index. */
        bool at(size_t index, CCert& out) const;
        /** Returns whether an anchor with the same DER certificate is present. */
        bool contains(const CCert& cert) const;
    };

    /**
     * Builds and validates an X.509 certification path against explicit trust anchors.
     *
     * The core profile checks signatures, validity, CA constraints, KeyUsage, an optional EKU,
     * supported NameConstraints, critical extensions, and trust-anchor membership. Revocation
     * and RFC 5280 policy-tree processing are separate capabilities and are never implied by
     * EPATH_OK; asking for either through the policy returns an explicit unavailable status.
     */
    class CERTPP_API CPathValidator {
    public:
        /** Builds a path from leaf through intermediates and validates it against trustStore. */
        static SPathValidationResult validate(
            const CCert& leaf,
            const CCertCollection& intermediates,
            const CTrustStore& trustStore,
            const SPathValidationPolicy& policy = SPathValidationPolicy()
        );

        /** Validates an already leaf-first path; its last item must be in trustStore. */
        static SPathValidationResult validateOrdered(
            const TArray<CCert>& path,
            const CTrustStore& trustStore,
            const SPathValidationPolicy& policy = SPathValidationPolicy()
        );
    };

} // namespace x509
} // namespace certpp

#endif
