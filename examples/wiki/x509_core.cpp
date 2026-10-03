#include <certpp.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::x509;
using namespace certpp::crypto;

// Each example is one function, preceded by a `// === <TypeName> ===` marker. The function body
// is what gets published as that type's example, dedented, so write it as the code a caller
// would write -- not as a test. See the brief for the rules.

// === CCert ===
// Parses a DER certificate and reads the fields callers reach for first. importDer() also
// succeeds for an algorithm this library cannot resolve -- keyAlgo()/signAlgo() then hold the
// raw OID text and publicKey() is null, so check the key before using it rather than after.
void exampleCCert(const COctet& der) {
    CCert cert;
    if (cert.importDer(der) != ERET_OK) {
        return;
    }

    CName cn;
    if (cert.subject().tryGet(ENAME_CN, cn)) {
        // cn holds the subject common name
    }

    if (!cert.publicKey()) {
        // An algorithm this library does not implement: keyAlgo() is its dotted-decimal OID,
        // every other parsed field is still good, and no signature work is possible.
        return;
    }

    // notBefore()/notAfter() are just data -- nothing in CCert compares them against a clock.
    if (cert.keyUsages() & EKUSE_KEY_CERT_SIGN) {
        // this certificate's key is allowed to sign other certificates
    }
}

// === CCertBuilder ===
// Issues a leaf certificate signed by a CA's key pair. subjectKey is only the key being
// certified; issuerKeyPair is what signs. build() never attaches a private key to the
// certificate it hands back, so the subject's own private half has to be set separately.
void exampleCCertBuilder(const CCert& caCert, const SKeyPair& caKeyPair,
                         const IPublicKeyPtr& subjectKey, const COctet& serial) {
    CCertBuilder builder;
    builder.issuer = caCert.subject();
    if (!CDistinguishedName::tryParse(builder.subject, CString("CN=leaf.example.com"))) {
        return;
    }

    builder.serialNumber = serial;
    builder.notBefore = SDateTime::now(true);
    builder.notAfter = builder.notBefore;
    builder.notAfter.year += 1;

    builder.subjectKey = subjectKey;
    builder.issuerKeyPair = caKeyPair;
    builder.digestAlgo = EHASH_SHA256;

    CBasicConstraintsExtensionBuilder bc;
    bc.setIsCa(false);

    IExtensionPtr bcExt = bc.build();
    if (!bcExt) {
        return; // build() reports an unencodable extension with null, and a null entry fails below
    }
    builder.extensions.add(bcExt);

    CCert leaf;
    if (builder.build(leaf) != ERET_OK) {
        return;
    }
    // leaf.verifyBy(caCert) now holds -- which is a statement about one signature and no more
}

// === ECertFormat ===
// ECERT_AUTO, the default, sniffs DER from PEM out of the data itself, which is what to pass for
// a file whose format is not known up front. It is an import-only value: exportAs() has nothing
// to detect from and reports ERET_NOTSUP, so an export must name ECERT_DER or ECERT_PEM.
void exampleECertFormat(const SReadOnlyByteSpan& fileContents) {
    CCert cert;
    if (cert.importFrom(fileContents, ECERT_AUTO) != ERET_OK) {
        return;
    }

    COctet pem;
    if (cert.exportAs(pem, false, ECERT_PEM) != ERET_OK) {
        return;
    }
    // pem holds a "-----BEGIN CERTIFICATE-----" block; ECERT_AUTO here would have been ERET_NOTSUP
}

// === SRsaPssParams ===
// Reads the RSASSA-PSS parameters a certificate's signature was actually made with. All four
// fields are DEFAULTed, so a default-constructed SRsaPssParams already means SHA-1/MGF1-SHA-1/
// salt 20 -- almost never what a real certificate uses, which is why these must be read.
void exampleSRsaPssParams(const CCert& cert) {
    SRsaPssParams pss;
    if (!cert.rsaPssParams(pss)) {
        return; // not an id-RSASSA-PSS signature, or its parameters did not parse
    }

    // A SHA-256 PSS certificate reports EHASH_SHA256 with saltLength 32, not the 20-byte default.
    IHasherPtr hasher;
    if (IHasher::create(pss.hashAlgo, hasher) != ERET_OK) {
        return;
    }

    if (pss.mgfHashAlgo != pss.hashAlgo || pss.trailerField != 1) {
        return; // legal to encode, but not a shape this library's own verifyPss() expresses
    }
    // verifyBy() applies all of this itself; this is the route for verifying by hand
}

// === CAccessDescription ===
// Picks the OCSP responder out of a certificate's AuthorityInformationAccess extension.
// accessMethod() is an OID in dotted-decimal text, so match it against the id-ad-ocsp constant
// rather than guessing the service from the location's URL scheme.
void exampleCAccessDescription(const CCert& cert) {
    auto aia = cert.extension<CAiaExtension>();
    if (!aia) {
        return;
    }

    CString ocspUrl;
    for (const CAccessDescription& desc : aia->descriptions()) {
        if (desc.accessMethod() == CString(CAiaExtension::OID_OCSP_METHOD)
            && desc.accessLocation().type() == EGNAME_URI)
        {
            ocspUrl = desc.accessLocation().text();
            break;
        }
    }
    // ocspUrl stays empty when this certificate names no OCSP responder at all
}

// === CDistributionPoint ===
// Reads the CRL locations out of a CRLDistributionPoints extension. hasReasons() being false is
// not "no reasons" -- it means the CRL at this point covers every revocation reason, which is
// the case to handle rather than skip.
void exampleCDistributionPoint(const CCert& cert) {
    auto cdp = cert.extension<CCdpExtension>();
    if (!cdp) {
        return;
    }

    for (const CDistributionPoint& point : cdp->points()) {
        if (point.hasReasons() && (point.reasons() & ECRLR_KEY_COMPROMISE) == 0) {
            continue; // this point's CRL would not list a key-compromise revocation
        }

        if (!point.crlIssuer().empty()) {
            continue; // issued by a different CA than the certificate's own issuer
        }

        for (const CGeneralName& name : point.fullName()) {
            if (name.type() == EGNAME_URI) {
                // name.text() is a CRL to fetch and hand to CCrlReader::decode()
            }
        }
    }
}

// === CPolicyInformation ===
// One certificate policy OID out of (or into) a CertificatePolicies extension. The qualifiers
// stay as raw DER rather than parsed, because what a caller checks is the identifier itself --
// a specific CA/Browser Forum policy, or anyPolicy.
void exampleCPolicyInformation(const CCert& cert, CCertBuilder& issuing) {
    auto policies = cert.extension<CPoliciesExtension>();
    if (policies) {
        for (const CPolicyInformation& policy : policies->policies()) {
            if (policy.policyIdentifier() == CString(CPoliciesExtension::OID_ANY_POLICY)) {
                // anyPolicy: this certificate asserts no named policy at all
            }
        }
    }

    // Asserting one on a certificate being issued; the qualifiers may simply be left empty.
    CPoliciesExtensionBuilder builder;
    builder.addPolicy(CPolicyInformation(CString("2.23.140.1.2.1"), COctet()));

    IExtensionPtr ext = builder.build();
    if (!ext) {
        return; // a policyIdentifier that is not well-formed dotted-decimal
    }
    issuing.extensions.add(ext);
}

// === CGeneralName ===
// The CHOICE every name-bearing extension uses, and which constructor to pick matters: a text
// alternative takes a CString, but iPAddress takes raw address octets (4 or 16 of them) through
// the COctet constructor -- handing dotted-quad text to the CString one would encode the text.
void exampleCGeneralName(CSanExtensionBuilder& san, const COctet& addressOctets) {
    san.addName(CGeneralName(EGNAME_DNS, CString("example.com")));
    san.addName(CGeneralName(EGNAME_URI, CString("https://example.com/")));

    if (addressOctets.size() != 4 && addressOctets.size() != 16) {
        return;
    }
    san.addName(CGeneralName(EGNAME_IP_ADDRESS, addressOctets));

    IExtensionPtr ext = san.build();
    if (!ext) {
        return; // one of the names above could not be encoded (non-ASCII in an IA5String, say)
    }
    // ext is a SubjectAlternativeName ready for CCertBuilder::extensions
}

// === CGeneralSubtree ===
// One permitted or excluded name for a NameConstraints extension. minimum()/maximum() are
// essentially never used in practice -- pass 0 and false -- and a DNS subtree is written with a
// leading dot, which is what makes the constraint cover everything below the name.
void exampleCGeneralSubtree(CCertBuilder& issuing) {
    CNameConstraintsExtensionBuilder nc;
    nc.addPermittedSubtree(
        CGeneralSubtree(CGeneralName(EGNAME_DNS, CString(".example.com")), 0, false, 0)
    );
    nc.addExcludedSubtree(
        CGeneralSubtree(CGeneralName(EGNAME_DNS, CString(".internal.example.com")), 0, false, 0)
    );

    IExtensionPtr ext = nc.build();
    if (!ext) {
        return;
    }

    // RFC 5280 4.2.1.10 requires NameConstraints to be marked critical.
    ext->critical(true);
    issuing.extensions.add(ext);
}

// === IExtension ===
// create() is the factory: it dispatches on the OID to a concrete type under x509/exts/ and
// falls back to a generic oid()/value()-only instance for anything this library does not model,
// so it never returns null -- and a critical extension nobody recognizes invalidates a
// certificate rather than being ignorable (RFC 5280 4.2).
void exampleIExtension(const CString& oid, const COctet& extnValue, bool wasCritical) {
    IExtensionPtr ext = IExtension::create(oid, extnValue);
    ext->critical(wasCritical);

    auto bc = std::dynamic_pointer_cast<CBasicConstraintsExtension>(ext);
    if (bc) {
        if (bc->isCa() && bc->hasPathLenConstraint()) {
            // bc->pathLenConstraint() bounds how many intermediates may follow
        }
        return;
    }

    if (ext->critical()) {
        return; // unrecognized and critical: refuse the certificate
    }

    CBuffer der;
    if (!ext->encode(der)) {
        return;
    }
    // der holds value()'s bytes, ready to splice back into an Extension SEQUENCE
}

// === IExtensionBuilder ===
// The interface every x509/exts/ builder implements, which is what lets one policy table hand
// back extensions of different types. build() reports a field it cannot DER-encode by returning
// null rather than throwing, and a null entry in CCertBuilder::extensions fails the whole build.
void exampleIExtensionBuilder(CCertBuilder& issuing) {
    auto ku = std::make_shared<CKeyUsagesExtensionBuilder>();
    ku->setBits(EKUSE_DIGITAL_SIGNATURE | EKUSE_KEY_ENCIPHERMENT);

    auto eku = std::make_shared<CEkuExtensionBuilder>();
    eku->addPurpose(CEkuExtension::OID_SERVER_AUTH);

    IExtensionBuilderPtr policy[] = { ku, eku };

    for (const IExtensionBuilderPtr& builder : policy) {
        IExtensionPtr ext = builder->build();
        if (!ext) {
            return;
        }

        ext->critical(true);
        issuing.extensions.add(ext);
    }
}

// === CCrlReader ===
// Decodes a CRL and asks whether it revokes a certificate. check() only looks the serial up:
// verifyBy() and the issuer-name comparison are separate and both necessary, since a CRL from an
// unrelated CA with a colliding serial would otherwise produce a verdict of its own.
void exampleCCrlReader(const COctet& crlDer, const CCert& issuerCert, const CCert& cert) {
    CCrlReader crl;
    if (crl.decode(crlDer) != ERET_OK) {
        return;
    }

    if (crl.verifyBy(issuerCert) != ERET_OK) {
        return; // one signature check, and nothing else -- not thisUpdate()/nextUpdate()
    }

    if (crl.issuer() != cert.issuer()) {
        return; // a real CRL about some other CA's certificates
    }

    ERetCode rc = crl.check(cert);
    if (rc == ERET_ALREADY) {
        // cert is listed: revoked
    } else if (rc != ERET_OK) {
        return; // a genuine error, not a revocation verdict either way
    }
}

// === CCrlRevokationInfo ===
// Finds a certificate's own entry in a CRL, which is what carries the revocation time and
// reason. reason() is ECRLR_NONE for an entry with no cRLReason extension: that is an absent
// reason code, not a weaker revocation.
void exampleCCrlRevokationInfo(const CCrlReader& crl, const CCert& cert) {
    CCrlRevokationInfo info;
    if (crl.find(cert, info) != ERET_OK) {
        return; // not listed in this CRL
    }

    if (info.timestamp().isZero()) {
        return; // no revocationDate to act on
    }

    if (info.reason() == ECRLR_KEY_COMPROMISE) {
        // the key itself is compromised, so signatures made before revocationDate are suspect
        // too -- unlike ECRLR_SUPERSEDED, where only the certificate was replaced
    }
    // info.rawData() is the entry's own DER, as CCrlWriter would re-embed it verbatim
}

// === CCrlWriter ===
// Issues a CRL. build() signs with the issuer certificate's attached private key, so that
// certificate must be one privateKey(IPrivateKeyPtr&) was called on; issuer() is optional and,
// when set, must equal that certificate's own subject() rather than naming anything else.
void exampleCCrlWriter(const CCert& caCert, const CCert& revokedCert, COctet& out) {
    CCrlWriter writer;
    writer.version(1)                     // v2, the version a CRL with extensions needs
          .issuer(caCert.subject())
          .thisUpdate(SDateTime::now(true));

    SDateTime nextUpdate = writer.thisUpdate();
    nextUpdate.year += 1;
    writer.nextUpdate(nextUpdate);

    if (writer.add(revokedCert, SDateTime::now(true), ECRLR_KEY_COMPROMISE) != ERET_OK) {
        return;
    }

    if (writer.build(caCert, out) != ERET_OK) {
        return; // ERET_KEY_EMPTY when caCert carries no private key to sign with
    }
    // out is a DER CertificateList a CCrlReader can decode and verifyBy(caCert)
}

// === CCertRequest ===
// Imports a PKCS#10 request on the CA side. importDer() verifies the self-signature before it
// reports success, because that signature is the only thing a CSR attests: until it holds every
// field is an unauthenticated claim, and once it holds they are still only a request.
void exampleCCertRequest(const COctet& csrDer) {
    CCertRequest request;
    if (request.importDer(csrDer) != ERET_OK) {
        return; // malformed, or the self-signature did not hold
    }

    if (!request.publicKey()) {
        return; // an algorithm this library does not implement
    }

    // The requester proved possession of that key and of nothing else. A requested extension is
    // a wish: read the specific one this CA will grant, check it, and decide -- there is
    // deliberately no API that copies them into a certificate.
    auto san = request.extension<CSanExtension>();
    if (san) {
        for (const CGeneralName& name : san->names()) {
            if (name.type() == EGNAME_DNS) {
                // check name.text() against what this requester actually controls
            }
        }
    }
}

// === CCertRequestBuilder ===
// Produces a CSR on the requester's side. The key is set as a whole key pair -- subjectKeyPair,
// never a public key on its own -- because build() signs with the private half to prove it is
// the match for the public half it embeds, and refuses a mismatched pair with ERET_KEY_ERROR.
void exampleCCertRequestBuilder(const SKeyPair& myKeyPair, CCertRequest& out) {
    CCertRequestBuilder builder;
    if (!CDistinguishedName::tryParse(builder.subject, CString("CN=example.com"))) {
        return;
    }

    builder.subjectKeyPair = myKeyPair;
    builder.digestAlgo = EHASH_SHA256;

    // These are what the CA is *asked* for, carried in a PKCS#9 extensionRequest attribute.
    CSanExtensionBuilder san;
    san.addName(CGeneralName(EGNAME_DNS, CString("example.com")));

    IExtensionPtr sanExt = san.build();
    if (!sanExt) {
        return;
    }
    builder.extensions.add(sanExt);

    if (builder.build(out) != ERET_OK) {
        return;
    }
    // build() handed the result through importDer(), so out's signature has already been checked
}

// === SCertRequestAttribute ===
// One PKCS#10 attribute, with `values` meaning the same bytes in both directions -- the content
// octets of the attribute's values SET, without that SET's own tag and length -- so an attribute
// read off one request goes straight into a builder for another.
void exampleSCertRequestAttribute(const CCertRequest& request, CCertRequestBuilder& builder) {
    for (const SCertRequestAttribute& attr : request.attributes()) {
        if (attr.oid == CString(CCertRequest::OID_EXTENSION_REQUEST)) {
            // builder.extensions writes this attribute itself; a second copy is rejected
            continue;
        }
        builder.attributes.add(attr);
    }

    // A new attribute has the same shape: DER elements, not bare text. This is one UTF8String
    // inside the values SET, which is how PKCS#9's unstructuredName is encoded.
    const uint8_t unstructuredName[] = { 0x0c, 0x03, 'a', 'b', 'c' };
    builder.attributes.add(SCertRequestAttribute(
        CString("1.2.840.113549.1.9.2"),
        COctet(unstructuredName, sizeof(unstructuredName))
    ));
}

// === CCertCollection ===
// Collects certificates and orders them into a chain. buildChain() orders by who issued whom and
// verifies nothing at all; verifyLinks() adds each link's signature and is still not path
// validation -- dates, basicConstraints, revocation and trust-anchor choice stay with the caller.
void exampleCCertCollection(const CCert& leaf, const CCert& intermediate, const CCert& root) {
    CCertCollection col;
    size_t leafIndex = 0, index = 0;
    if (col.add(leaf, leafIndex) != ERET_OK
        || col.add(intermediate, index) != ERET_OK
        || col.add(root, index) != ERET_OK)
    {
        return;
    }

    TArray<size_t> chain;
    if (col.buildChain(leafIndex, chain) != ECHAINRES_OK) {
        return; // chain still holds the partial walk assembled before the problem
    }

    if (col.verifyLinks(chain) != ERET_OK) {
        return;
    }
    // every link's signature holds -- a chain rooted in an attacker's own CA gets this far too
}

// === SCertEntry ===
// One entry read out of a collection. A collection normally holds a mixture -- the end-entity
// certificate with its key, the CA certificates above it without -- so hasPrivateKey() is the
// test, and checkKeyPairing() is what establishes the key really is that certificate's.
void exampleSCertEntry(const CCertCollection& col, size_t index) {
    SCertEntry entry;
    if (col.at(index, entry) != ERET_OK) {
        return; // index was at or beyond col.count()
    }

    if (!entry.hasPrivateKey()) {
        return; // a CA certificate in the chain, not the entry holding the key
    }

    // add() does not check the two against each other, because this costs a signature operation.
    if (col.checkKeyPairing(index) != ERET_OK) {
        return; // ERET_KEY_ERROR: the key does not actually belong to entry.cert
    }
    // entry.friendlyName/entry.localKeyId are the PKCS#9 attributes a PFX pairs bags with
}

// === EChainResults ===
// ECHAINRES_PARTIAL is the case worth writing code for: the walk ran out of issuers, and the
// output keeps what it found so the caller can go and fetch the missing one. Only ECHAINRES_OK
// means the walk reached a self-issued certificate held in the collection.
void exampleEChainResults(const CCertCollection& col, const CCert& leaf) {
    TArray<size_t> chain;
    EChainResults res = col.buildChainFor(leaf, chain);

    if (res == ECHAINRES_PARTIAL) {
        SCertEntry topMost;
        if (chain.size() && col.at(chain[chain.size() - 1], topMost) == ERET_OK) {
            // topMost.cert.issuer() names the certificate still to be fetched
        }
        return;
    }

    if (res != ECHAINRES_OK) {
        return; // ECHAINRES_CYCLE or ECHAINRES_TOO_DEEP: the collection itself is the problem
    }
    // chain holds the issuers above leaf, nearest first -- leaf has no index in col
}

// === EChainFormats ===
// Picks the container implementation for a buffer whose format is not known. The two are not
// interchangeable: ECHAINFMT_PEM has no password and no encryption, so needsPassword() returning
// false is a warning about what a private key in the collection would become, not a convenience.
void exampleEChainFormats(const COctet& container, const COctet& password) {
    EChainFormats which = IChainFormat::detect(container.toSpan());
    if (which == ECHAINFMT_UNKNOWN) {
        return; // not a container shape this library recognizes
    }

    IChainFormatPtr format = IChainFormat::builtIn(which);
    if (!format) {
        return; // a format this build does not implement
    }

    CCertCollection col;
    if (format->load(container.toSpan(), password.toSpan(), col) != ERET_OK) {
        return; // malformed container, wrong password, or an algorithm not implemented
    }
    // load() appends, so loading a second container into col merges the two
}

// === IChainFormat ===
// Starts from builtIn() and writes a collection out. A PEM container has no password and no
// encryption at all, so a private key held in the collection is written in the clear -- check
// needsPassword() and choose ECHAINFMT_PFX when the key is going to rest on disk.
void exampleIChainFormat(const CCertCollection& col, const COctet& password) {
    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    if (!format) {
        return;
    }

    if (!format->needsPassword()) {
        // Nothing in this container will be encrypted, whatever password is passed.
    } else if (password.empty()) {
        return; // save() would refuse with ERET_BADREQ
    }

    CBuffer out;
    if (format->save(col, password.toSpan(), out) != ERET_OK) {
        return; // ERET_NOTSUP when an entry holds a key this format cannot carry
    }
    // out holds the container's bytes; format->format() reports which format they are
}

// === COcspCertId ===
// Identifies a certificate to a responder by hashes of its issuer's name and key. The one-
// argument make() lifts the issuerKeyHash out of the certificate's own AuthorityKeyIdentifier
// and is SHA-1 only; the general form hashes the issuer certificate itself and always works.
void exampleCOcspCertId(const CCert& cert, const CCert& issuer) {
    COcspCertId id;
    if (COcspCertId::make(cert, id) != ERET_OK) {
        // ERET_NOTSUP: no AuthorityKeyIdentifier keyIdentifier to reuse, so hash the issuer's
        // own Name and SubjectPublicKeyInfo.subjectPublicKey directly (RFC 6960 4.1.1).
        if (COcspCertId::make(cert, issuer, EHASH_SHA256, id) != ERET_OK) {
            return;
        }
    }

    if (!id.isFor(cert)) {
        return;
    }

    COctet der;
    if (id.encode(der) != ERET_OK) {
        return;
    }
    // der is a complete CertID SEQUENCE TLV, the exact inverse of COcspCertId::decode()
}

// === COcspRequest ===
// The responder side. decode() takes a CBuffer, not a COctet, and an unsigned request is both
// legal and the common case -- requestorName() being present is a claim and not evidence, so
// verifySignature() is what settles it, reporting ERET_INVAL for a request carrying no signature.
void exampleCOcspRequest(const CBuffer& requestDer, const CCert& requestorCert, const CCert& cert) {
    COcspRequest request;
    if (request.decode(requestDer) != ERET_OK) {
        return;
    }

    if (!request.requestorName().empty()) {
        if (request.verifySignature(requestorCert) != ERET_OK) {
            return; // unsigned, or not signed by the key requestorCert carries
        }
    }

    if (!request.contains(cert)) {
        return; // no CertID in this request matches cert
    }

    if (request.nonceBytes().empty()) {
        return; // no RFC 8954 nonce was sent, so there is nothing to echo back
    }
    // pass request.nonceBytes() to COcspResponseBuilder::nonceBytes() unchanged
}

// === COcspRequestBuilder ===
// Builds a client's status request. Setting requestorCert() is taken as an instruction to sign,
// so that certificate must carry a private key; leave it unset for the ordinary unsigned
// request. Keep the generated nonce -- it is what rules out a replayed response later.
void exampleCOcspRequestBuilder(const CCert& cert, const CCert& issuer,
                                COctet& outRequest, COctet& outNonce) {
    COcspRequestBuilder builder;
    if (builder.add(cert, issuer, EHASH_SHA1) != ERET_OK) {
        return;
    }

    if (builder.generateNonce(16) != ERET_OK) {
        return; // the CSPRNG failed; sending an un-nonced request is a separate decision
    }
    outNonce = builder.nonceBytes();

    if (builder.build(outRequest) != ERET_OK) {
        return; // ERET_INVAL when no certificate ID was added
    }
    // outRequest is the DER OCSPRequest to POST; the response's nonce must equal outNonce
}

// === COcspResponse ===
// The client side. status() is the top-level responseStatus and has to be checked first: any
// value but EOCSP_OK carries no entries, no responder and no signature at all, so skipping it
// makes an EOCSP_TRY_LATER read as "this responder knows nothing about my certificate".
void exampleCOcspResponse(const COctet& responseDer, const CCert& responderCert,
                          const CCert& cert, const COctet& sentNonce) {
    COcspResponse response;
    if (response.decode(responseDer) != ERET_OK) {
        return;
    }

    if (response.status() != EOCSP_OK) {
        return; // nothing beyond the status: retry, or treat the service as unavailable
    }

    if (response.verifySignature(responderCert) != ERET_OK) {
        return; // whether responderCert may answer for cert at all is a separate check
    }

    if (!CSecure::equals(response.nonceBytes().toSpan(), sentNonce.toSpan())) {
        return; // a replay, or an answer to somebody else's request
    }

    ERetCode rc = response.check(cert);
    if (rc == ERET_ALREADY) {
        // cert is revoked
    } else if (rc != ERET_OK) {
        return; // ERET_NOTSUP for an unknown certificate, ERET_INVAL for no entry at all
    }
}

// === COcspEntry ===
// One SingleResponse out of a response. status() is the only field always meaningful:
// revocationTime()/reason() say nothing unless status() is EOCSPENT_REVOKED, and nextUpdate() is
// optional, reporting SDateTime::isZero() when the responder offered no caching guidance.
void exampleCOcspEntry(const COcspResponse& response, const CCert& cert) {
    COcspEntry entry;
    if (response.find(cert, entry) != ERET_OK) {
        return; // this response carries no entry for cert
    }

    if (entry.status() == EOCSPENT_REVOKED) {
        if (entry.revocationTime().isZero()) {
            return; // a revoked entry with no revocationTime is malformed
        }
        // entry.reason() is ECRLR_NONE when the responder gave no reason code
        return;
    }

    if (entry.status() != EOCSPENT_GOOD) {
        return; // EOCSPENT_UNKNOWN: this responder does not answer for cert
    }

    if (entry.nextUpdate().isZero()) {
        return; // good, but with no stated horizon -- do not cache the answer
    }
    // entry.thisUpdate() is when the status was known correct, and is always present
}

// === COcspResponseBuilder ===
// Produces a responder's answer. status() defaults to EOCSP_INTERNAL rather than EOCSP_OK, so a
// successful response has to say so explicitly, and build() signs with the responder
// certificate's attached private key.
void exampleCOcspResponseBuilder(const CCert& responderCert, const CCert& cert,
                                 const CCert& issuer, const COctet& requestNonce, COctet& out) {
    SDateTime thisUpdate = SDateTime::now(true);
    SDateTime nextUpdate = thisUpdate;
    nextUpdate.year += 1;

    COcspResponseBuilder builder;
    builder.status(EOCSP_OK)
           .producedAt(thisUpdate)
           .nonceBytes(requestNonce);    // echoed back from the request, unchanged

    if (builder.add(cert, issuer, EOCSPENT_GOOD, thisUpdate, nextUpdate) != ERET_OK) {
        return;
    }

    if (builder.build(responderCert, out) != ERET_OK) {
        return; // ERET_KEY_EMPTY when responderCert has no private key attached
    }
    // out is a DER OCSPResponse a COcspResponse can decode and verifySignature(responderCert)
}

// === EOcspEntryStatus ===
// Selects what a responder asserts about one certificate. EOCSPENT_GOOD and EOCSPENT_REVOKED are
// both positive statements; EOCSPENT_UNKNOWN means this responder does not answer for the
// certificate at all and is not a synonym for "not revoked".
void exampleEOcspEntryStatus(COcspResponseBuilder& builder, const CCert& cert, const CCert& issuer,
                             bool isRevoked, const SDateTime& revokedAt) {
    SDateTime thisUpdate = SDateTime::now(true);

    if (!isRevoked) {
        if (builder.add(cert, issuer, EOCSPENT_GOOD, thisUpdate) != ERET_OK) {
            return;
        }
        return;
    }

    // revocationTime is required for EOCSPENT_REVOKED -- the trailing argument, after the
    // optional nextUpdate and reason, so count the positions rather than copying from above.
    ERetCode rc = builder.add(
        cert, issuer, EOCSPENT_REVOKED, thisUpdate, SDateTime(), ECRLR_KEY_COMPROMISE, revokedAt
    );
    if (rc != ERET_OK) {
        return;
    }
}

// === EOcspStatus ===
// The top-level responseStatus, which answers for the *request* and is separate from any
// certificate's own status. A non-successful response has no room for anything else: build()
// encodes the single ENUMERATED and ignores the responder certificate, entries and producedAt.
void exampleEOcspStatus(const CCert& responderCert, const COcspRequest& request, COctet& out) {
    COcspResponseBuilder builder;

    if (request.certIds().empty()) {
        builder.status(EOCSP_MALFORMED);
    } else if (request.certIds().size() > 16) {
        builder.status(EOCSP_UNAUTHORIZED);
    } else {
        builder.status(EOCSP_TRY_LATER);
    }

    if (builder.build(responderCert, out) != ERET_OK) {
        return;
    }
    // out carries the status and nothing more -- a client must read status() before entries()
}

// === CPemChainFormat ===
// Loads a PEM bundle as a collection, then writes the ordered chain back out. The format object
// is obtained from builtIn(), which returns the certificates-only form: writing private keys is
// a separate constructor argument because PEM has no encryption, so a key it writes is in the
// clear and should never be one a caller got by accident.
void exampleCPemChainFormat(const SReadOnlyByteSpan& pemFile) {
    IChainFormatPtr pem = IChainFormat::builtIn(ECHAINFMT_PEM);
    if (!pem) {
        return;
    }

    // The password argument is ignored outright in both directions -- needsPassword() is false,
    // and that is a warning, not a convenience.
    CCertCollection collection;
    ERetCode rc = pem->load(pemFile, SReadOnlyByteSpan(), collection);
    if (rc != ERET_OK) {
        return;         // ERET_BADREQ: malformed container. ERET_NOTSUP: an encrypted key block.
    }

    TArray<size_t> chain;
    if (collection.buildChain(0, chain) != ECHAINRES_OK) {
        return;         // ordered, still not validated -- see CCertCollection
    }

    CBuffer out;
    pem->save(collection, SReadOnlyByteSpan(), out);
}

// === CPfxFormat ===
// Writes a collection as a PKCS#12/PFX container and reads one back. Unlike PEM, this format
// encrypts, so the password is load-bearing rather than ignored -- needsPassword() returns true.
// The iteration count is a constructor argument because it is a cost/strength trade-off only the
// caller can make; the default is 600,000, against RFC 7292's 1024 and OpenSSL's 2048.
void exampleCPfxFormat(const CCertCollection& collection, const SReadOnlyByteSpan& password) {
    IChainFormatPtr pfx = IChainFormat::builtIn(ECHAINFMT_PFX);
    if (!pfx) {
        return;
    }

    CBuffer container;
    if (pfx->save(collection, password, container) != ERET_OK) {
        return;         // ERET_BADREQ for an empty collection or an empty password
    }

    // Reading back verifies the MAC before decrypting anything, so a wrong password or a
    // tampered container fails without any plaintext having been produced.
    CCertCollection loaded;
    ERetCode rc = pfx->load(
        SReadOnlyByteSpan(container.toPtr(), container.size()), password, loaded);
    if (rc != ERET_OK) {
        // ERET_KEY_ERROR: the MAC did not verify -- wrong password, or the file was altered.
        // ERET_NOTSUP: a legacy PBES1 cipher (RC2, 3DES) this format deliberately will not read.
        return;
    }

    // Confirm a loaded key really belongs to its certificate, by signing rather than by
    // comparing serialized keys -- which only works for some algorithms.
    loaded.checkKeyPairing(0);
}
