#include <certpp.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::x509;
using namespace certpp::crypto;

// Each example is one function, preceded by a `// === <TypeName> ===` marker. The function body
// is what gets published as that type's example, dedented, so write it as the code a caller
// would write -- not as a test. See the brief for the rules.

// === CAiaExtension ===
// Finds the OCSP responder to ask about this certificate. AuthorityInformationAccess holds
// several kinds of location at once, so the accessMethod OID has to be matched before the
// accessLocation means anything -- and what comes back is a URI this process still has to
// fetch itself; the extension only says where to look.
void exampleCAiaExtension(const CCert& cert) {
    auto aia = cert.extension<CAiaExtension>();
    if (!aia) {
        return; // no AIA: there is no OCSP responder to ask, and no issuer URL to chase
    }

    CString ocspUri;
    CString caIssuersUri;
    for (const CAccessDescription& ad : aia->descriptions()) {
        if (ad.accessLocation().type() != EGNAME_URI) {
            continue; // a directoryName accessLocation is legal but not fetchable as a URL
        }
        if (ad.accessMethod().compare(CAiaExtension::OID_OCSP_METHOD) == 0) {
            ocspUri = ad.accessLocation().text();
        } else if (ad.accessMethod().compare(CAiaExtension::OID_CA_ISSUERS_METHOD) == 0) {
            caIssuersUri = ad.accessLocation().text();
        }
    }

    if (!ocspUri.empty()) {
        // POST a COcspRequest to ocspUri from here; caIssuersUri serves the issuing CA's own
        // certificate, for a peer that sent an incomplete chain
    }
}

// === CAiaExtensionBuilder ===
// Attaches the two access descriptions a public CA normally publishes: an OCSP responder, and
// a URL serving this CA's own certificate so a relying party that received an incomplete chain
// can complete it. RFC 5280 4.2.2.1 requires AIA to be non-critical, so nothing here sets the
// critical flag.
void exampleCAiaExtensionBuilder(CCertBuilder& builder) {
    CAiaExtensionBuilder aia;
    aia.addDescription(CAccessDescription(
        CAiaExtension::OID_OCSP_METHOD,
        CGeneralName(EGNAME_URI, CString("http://ocsp.example.com/"))
    ));
    aia.addDescription(CAccessDescription(
        CAiaExtension::OID_CA_ISSUERS_METHOD,
        CGeneralName(EGNAME_URI, CString("http://crt.example.com/issuing-ca.cer"))
    ));

    IExtensionPtr ext = aia.build();
    if (!ext) {
        return; // a malformed method OID, or non-ASCII text in a URI, encodes to nothing
    }

    builder.extensions.add(ext);
}

// === CAkiExtension ===
// Uses the AuthorityKeyIdentifier to pick the right key out of a CA that holds several -- a CA
// that has re-keyed keeps the same subject name, so the name alone no longer identifies which
// of its certificates signed this one. The identifier is only a hint for choosing a candidate:
// verifyBy() is what decides.
void exampleCAkiExtension(const CCert& cert, const CCert& candidateIssuer) {
    auto aki = cert.extension<CAkiExtension>();
    if (!aki || !aki->hasKeyIdentifier()) {
        // Every field of AuthorityKeyIdentifier is OPTIONAL, so an AKI that is present can
        // still carry no keyIdentifier at all -- fall back to matching by issuer name.
        return;
    }

    COctet issuerSki;
    if (candidateIssuer.subjectKeyIdentifier(issuerSki) != ERET_OK) {
        return;
    }

    const COctet& wanted = aki->keyIdentifier();
    if (wanted.size() != issuerSki.size()
        || std::memcmp(wanted.toPtr(), issuerSki.toPtr(), wanted.size()) != 0) {
        return; // a different key of the same CA, or a different CA altogether
    }

    if (cert.verifyBy(candidateIssuer) == ERET_OK) {
        // this one link holds -- dates, basicConstraints and revocation are still unchecked
    }
}

// === CAkiExtensionBuilder ===
// Points a certificate being issued at the key that signed it, by copying the issuer's own
// SubjectKeyIdentifier bytes verbatim. Copy them rather than recomputing a hash of the issuer's
// public key: the CA chose those bytes, and only a value that matches its CSkiExtension exactly
// lets a path builder pair the two.
void exampleCAkiExtensionBuilder(CCertBuilder& builder, const CCert& issuerCert) {
    COctet issuerSki;
    if (issuerCert.subjectKeyIdentifier(issuerSki) != ERET_OK) {
        return; // the issuer carries no SubjectKeyIdentifier, so there is nothing to point at
    }

    CAkiExtensionBuilder aki;
    aki.setKeyIdentifier(issuerSki);

    // Deliberately no addAuthorityCertIssuer()/setAuthorityCertSerialNumber(): that pair pins
    // this certificate to one exact issuing certificate, which stops resolving the moment the
    // CA re-issues or gets cross-signed. The key identifier survives both.

    IExtensionPtr ext = aki.build();
    if (!ext) {
        return;
    }

    builder.extensions.add(ext);
}

// === CBasicConstraintsExtension ===
// Decides whether a candidate issuer is allowed to sit where it does in a path. An absent
// pathLenConstraint means "any number of intermediates may follow", not zero -- so
// hasPathLenConstraint() must be consulted before pathLenConstraint() is believed.
void exampleCBasicConstraintsExtension(const CCert& caCert, size_t intermediatesBelow) {
    auto bc = caCert.extension<CBasicConstraintsExtension>();
    if (!bc || !bc->isCa()) {
        return; // absent, or cA false: this certificate may not sign other certificates at all
    }

    if (!bc->hasPathLenConstraint()) {
        return; // unconstrained depth; nothing further to check here
    }

    if (int64_t(intermediatesBelow) > bc->pathLenConstraint()) {
        return; // too many non-self-issued intermediates follow this CA: the path is invalid
    }

    // caCert may certify the subordinate CA beneath it
}

// === CBasicConstraintsExtensionBuilder ===
// Issues an intermediate that may sign end-entity certificates and nothing else:
// setPathLenConstraint(0) means zero further CAs may follow it, which is a real restriction,
// not the default. The flag has to be set explicitly -- RFC 5280 4.2.1.9 requires
// BasicConstraints to be critical on a CA certificate.
void exampleCBasicConstraintsExtensionBuilder(CCertBuilder& builder) {
    CBasicConstraintsExtensionBuilder bc;
    bc.setIsCa(true).setPathLenConstraint(0);

    IExtensionPtr ext = bc.build();
    if (!ext) {
        return;
    }

    ext->critical(true);
    builder.extensions.add(ext);
}

// === CCdpExtension ===
// Collects the URL of a CRL that covers the revocation reason being checked. A distribution
// point with no reasons field covers every reason; one that names reasons is a partition, and
// skipping the partition that carries the reason you care about looks exactly like "not
// revoked".
void exampleCCdpExtension(const CCert& cert) {
    auto cdp = cert.extension<CCdpExtension>();
    if (!cdp) {
        return; // no CRL distribution point published; revocation has to come from OCSP
    }

    CString crlUri;
    for (const CDistributionPoint& point : cdp->points()) {
        if (point.hasReasons() && (point.reasons() & ECRLR_KEY_COMPROMISE) == 0) {
            continue; // this partition does not cover keyCompromise
        }

        for (const CGeneralName& name : point.fullName()) {
            if (name.type() == EGNAME_URI) {
                crlUri = name.text();
            }
        }
    }

    if (!crlUri.empty()) {
        // fetch crlUri, parse it with CCrlReader, and verifyBy() the issuer before trusting it
    }
}

// === CCdpExtensionBuilder ===
// Publishes the single CRL URL covering every revocation reason, which is what almost every CA
// wants. CDistributionPoint has no setters, so its fields are passed to the constructor at
// once: hasReasons false (one unpartitioned CRL), and an empty crlIssuer meaning the
// certificate's own issuer also issues its CRL.
void exampleCCdpExtensionBuilder(CCertBuilder& builder) {
    TArray<CGeneralName> fullName;
    fullName.add(CGeneralName(EGNAME_URI, CString("http://crl.example.com/issuing-ca.crl")));

    CCdpExtensionBuilder cdp;
    cdp.addPoint(CDistributionPoint(
        fullName,
        COctet(),               // nameRelativeToCrlIssuer: unused when fullName is given
        false,                  // hasReasons: this CRL covers every reason
        ECRLR_NONE,
        TArray<CGeneralName>()  // crlIssuer: same as the certificate's own issuer
    ));

    IExtensionPtr ext = cdp.build();
    if (!ext) {
        return;
    }

    builder.extensions.add(ext);
}

// === CPoliciesExtension ===
// Checks a certificate against a policy OID a relying party insists on. anyPolicy satisfies any
// requirement, which is the subtlety here: a CA that asserts it has asserted nothing specific,
// so treating anyPolicy as a match is a policy decision and not a free one.
void exampleCPoliciesExtension(const CCert& cert, const char* requiredPolicyOid) {
    auto cp = cert.extension<CPoliciesExtension>();
    if (!cp) {
        return; // no CertificatePolicies: the certificate asserts no policy to match against
    }

    for (const CPolicyInformation& policy : cp->policies()) {
        if (policy.policyIdentifier().compare(requiredPolicyOid) == 0) {
            // the exact policy was asserted; policyQualifiersRaw() holds the CPS pointer and
            // user notices, still DER-encoded, if this caller ever needs them
            return;
        }

        if (policy.policyIdentifier().compare(CPoliciesExtension::OID_ANY_POLICY) == 0) {
            return; // accepted only because this caller chose to honour anyPolicy
        }
    }

    // no policy matched: reject
}

// === CPoliciesExtensionBuilder ===
// Asserts one CA-specific policy OID on a certificate being issued. The empty COctet is the
// policyQualifiers field: PolicyInformation keeps qualifiers as raw DER rather than modelling
// CPSuri/UserNotice, so passing nothing is how a certificate asserts a bare policy identifier
// -- which is what the overwhelming majority do.
void exampleCPoliciesExtensionBuilder(CCertBuilder& builder) {
    CPoliciesExtensionBuilder cp;
    cp.addPolicy(CPolicyInformation(CString("1.3.6.1.4.1.99999.1.2"), COctet()));

    IExtensionPtr ext = cp.build();
    if (!ext) {
        return; // the policy identifier wasn't well-formed dotted-decimal
    }

    builder.extensions.add(ext);
}

// === CEkuExtension ===
// Decides whether a certificate may be used for TLS server authentication. The two failure
// modes run opposite ways: no ExtendedKeyUsage at all means the key is unrestricted and the use
// is permitted, while an ExtendedKeyUsage that exists and omits serverAuth forbids it outright.
void exampleCEkuExtension(const CCert& cert) {
    auto eku = cert.extension<CEkuExtension>();
    if (!eku) {
        return; // unrestricted: a certificate with no EKU may be used for anything
    }

    if (eku->has(CEkuExtension::OID_SERVER_AUTH)) {
        return; // explicitly permitted
    }

    if (eku->has(CEkuExtension::OID_ANY_EXTENDED_KEY_USAGE)) {
        return; // anyExtendedKeyUsage waives the restriction the extension otherwise imposes
    }

    // Present, and serverAuth is not among its purposes: refuse this certificate for TLS,
    // however valid the rest of it is. A code-signing certificate lands here.
}

// === CEkuExtensionBuilder ===
// Restricts a leaf to the two TLS roles it actually fills. Every addPurpose() widens what the
// certificate may do, so the restriction is in what is left out -- and adding
// OID_ANY_EXTENDED_KEY_USAGE alongside them would cancel the whole extension's effect.
void exampleCEkuExtensionBuilder(CCertBuilder& builder) {
    CEkuExtensionBuilder eku;
    eku.addPurpose(CEkuExtension::OID_SERVER_AUTH);
    eku.addPurpose(CEkuExtension::OID_CLIENT_AUTH);

    IExtensionPtr ext = eku.build();
    if (!ext) {
        return; // a purpose string that isn't well-formed dotted-decimal encodes to nothing
    }

    builder.extensions.add(ext);
}

// === CKeyUsagesExtension ===
// Checks that a CA's key is actually permitted to sign certificates before a path is built
// through it. Reading the extension rather than CCert::keyUsages() is the point: that shortcut
// returns EKUSE_NONE both for an absent extension (no restriction) and for one that permits
// nothing, and those two mean opposite things.
void exampleCKeyUsagesExtension(const CCert& caCert) {
    auto ku = caCert.extension<CKeyUsagesExtension>();
    if (!ku) {
        return; // no KeyUsage extension at all: the key is unrestricted
    }

    if ((ku->bits() & EKUSE_KEY_CERT_SIGN) == 0) {
        return; // present, and this key may not verify certificate signatures -- whatever
                // BasicConstraints claims about it being a CA
    }

    if ((ku->bits() & EKUSE_CRL_SIGN) != 0) {
        // the same CA key may also sign the CRL this certificate's CDP points at
    }
}

// === CKeyUsagesExtensionBuilder ===
// Gives a CA certificate the only two usages a CA key should hold. setBits() replaces the whole
// set rather than OR-ing into it, so the combination goes in one call -- two calls would leave
// only the second. RFC 5280 4.2.1.3 says KeyUsage SHOULD be critical, which is a separate step
// on the built extension.
void exampleCKeyUsagesExtensionBuilder(CCertBuilder& builder) {
    CKeyUsagesExtensionBuilder ku;
    ku.setBits(EKUSE_KEY_CERT_SIGN | EKUSE_CRL_SIGN);

    IExtensionPtr ext = ku.build();
    if (!ext) {
        return;
    }

    ext->critical(true);
    builder.extensions.add(ext);
}

// === CNameConstraintsExtension ===
// Applies a CA's name constraints to a name it is about to be trusted for. Excluded subtrees
// are checked first and win over any permitted subtree that also matches; and a subtree
// carrying a non-zero minimum or any maximum must not be honoured at all, because RFC 5280
// 4.2.1.10 forbids both fields outright.
void exampleCNameConstraintsExtension(const CCert& caCert, const CString& dnsName) {
    auto nc = caCert.extension<CNameConstraintsExtension>();
    if (!nc) {
        return; // an unconstrained CA: it may certify any name at all
    }

    for (const CGeneralSubtree& subtree : nc->excludedSubtrees()) {
        if (subtree.base().type() == EGNAME_DNS
            && subtree.base().text().compare(dnsName.toPtr()) == 0) {
            return; // excluded, regardless of what permittedSubtrees() says about it
        }
    }

    for (const CGeneralSubtree& subtree : nc->permittedSubtrees()) {
        if (subtree.minimum() != 0 || subtree.hasMaximum()) {
            return; // a subtree using the forbidden fields: reject the certificate
        }

        if (subtree.base().type() == EGNAME_DNS
            && subtree.base().text().compare(dnsName.toPtr()) == 0) {
            // permitted (a full matcher also walks DNS suffixes, not just exact bases)
            return;
        }
    }

    // A non-empty permittedSubtrees() that matched nothing excludes the name.
}

// === CNameConstraintsExtensionBuilder ===
// Constrains an intermediate to one DNS namespace, minus a sub-domain carved out of it: on
// overlap, the excluded subtree wins. The 0/false/0 tail of each CGeneralSubtree is minimum,
// hasMaximum and maximum -- RFC 5280 permits no other values, so those are the only ones to
// pass. NameConstraints only has meaning on a CA certificate, and must be critical.
void exampleCNameConstraintsExtensionBuilder(CCertBuilder& builder) {
    CNameConstraintsExtensionBuilder nc;
    nc.addPermittedSubtree(CGeneralSubtree(
        CGeneralName(EGNAME_DNS, CString("example.com")), 0, false, 0
    ));
    nc.addExcludedSubtree(CGeneralSubtree(
        CGeneralName(EGNAME_DNS, CString("internal.example.com")), 0, false, 0
    ));

    IExtensionPtr ext = nc.build();
    if (!ext) {
        return;
    }

    ext->critical(true);
    builder.extensions.add(ext);
}

// === CSanExtension ===
// Matches a peer's hostname against the certificate. SubjectAltName is the field identity is
// matched against -- a hostname that only appears in the subject DN's common name is not a
// match, and a certificate with no SAN at all fails rather than falling back to the CN.
void exampleCSanExtension(const CCert& cert, const CString& expectedHost) {
    auto san = cert.extension<CSanExtension>();
    if (!san) {
        return; // no SubjectAltName: reject, rather than reading cert.subject()'s CN instead
    }

    for (const CGeneralName& name : san->names()) {
        if (name.type() != EGNAME_DNS) {
            continue; // an iPAddress entry carries 4 or 16 bytes in raw(), not text()
        }

        if (name.text().compare(expectedHost.toPtr()) == 0) {
            return; // this certificate is bound to the host being connected to
        }
    }

    // No SAN entry matched: reject, even if cert.subject()'s CN happens to equal expectedHost.
}

// === CSanExtensionBuilder ===
// Attaches the identities a TLS leaf is actually valid for, both DNS names and an IP address --
// an iPAddress entry is raw address octets in a COctet, not text. The criticality is
// conditional: when the subject DN carries no common name, SubjectAltName is the certificate's
// only identity and RFC 5280 4.2.1.6 requires it to be critical.
void exampleCSanExtensionBuilder(CCertBuilder& builder) {
    CSanExtensionBuilder san;
    san.addName(CGeneralName(EGNAME_DNS, CString("example.com")));
    san.addName(CGeneralName(EGNAME_DNS, CString("www.example.com")));

    const uint8_t ipv4[4] = { 192, 0, 2, 10 };
    san.addName(CGeneralName(EGNAME_IP_ADDRESS, COctet(ipv4, sizeof(ipv4))));

    IExtensionPtr ext = san.build();
    if (!ext) {
        return; // non-ASCII text in a dNSName or URI can't be encoded as IA5String
    }

    CName commonName;
    if (!builder.subject.tryGet(ENAME_CN, commonName)) {
        ext->critical(true);
    }

    builder.extensions.add(ext);
}

// === CSkiExtension ===
// Reads the bytes a store indexes CA certificates by: a child's CAkiExtension names the issuer
// it wants by exactly this value. The bytes are opaque -- usually the SHA-1 of the public key,
// but nothing requires that -- so they are compared, never recomputed and checked.
void exampleCSkiExtension(const CCert& caCert) {
    auto ski = caCert.extension<CSkiExtension>();
    if (!ski) {
        return; // no SubjectKeyIdentifier: children of this CA can only name it by issuer DN
    }

    const COctet& keyId = ski->keyIdentifier();
    if (keyId.empty()) {
        return; // present, but its extnValue didn't decode as an OCTET STRING
    }

    // keyId.toPtr()/keyId.size() is the key to store caCert under in the issuer store that
    // CAkiExtension lookups go through. 20 bytes is RFC 5280 4.2.1.2's method-1 length, but a
    // CA may choose any other, so nothing here may assume a length.
}

// === CSkiExtensionBuilder ===
// Computes a SubjectKeyIdentifier the RFC 5280 4.2.1.2 "method 1" way -- the SHA-1 of the
// subject public key -- and attaches it while issuing. The digest is taken over the serialized
// public key, and SubjectKeyIdentifier is never critical: it identifies a key, it does not
// constrain its use.
void exampleCSkiExtensionBuilder(CCertBuilder& builder, const IPublicKeyPtr& subjectKey) {
    COctet publicKeyBytes;
    if (subjectKey->serialize(publicKeyBytes) != ERET_OK) {
        return;
    }

    IHasherPtr sha1;
    if (IHasher::create(EHASH_SHA1, sha1) != ERET_OK) {
        return;
    }

    uint8_t digest[20];
    sha1->push(publicKeyBytes.toSpan());
    if (!sha1->finish(SByteSpan(digest, sizeof(digest)))) {
        return;
    }

    CSkiExtensionBuilder ski;
    ski.setKeyIdentifier(COctet(digest, sizeof(digest)));

    IExtensionPtr ext = ski.build();
    if (!ext) {
        return;
    }

    builder.extensions.add(ext);
}
