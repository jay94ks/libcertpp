# Extensions and revocation

[한국어](validation.ko.md)

## X.509 extensions

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`x509/ext.hpp` / `src/x509/ext.cpp`** define `IExtension`, the concrete
  (not pure-virtual, despite the `I` prefix -- it's fully usable on its own
  for an OID this library doesn't model further) base every decoded X.509
  extension is: `oid()` (dotted-decimal text) + `value()` (the raw,
  still-DER-encoded `extnValue` octets) + `critical()` (`Extension.critical`,
  RFC 5280 4.2; defaults to `false`, matching DER's own default for an
  absent field), plus `IExtensionPtr` and the static `IExtension::create(oid,
  value)` factory. `create()` dispatches by OID to the matching concrete
  class under `x509/exts/` (see below), falling back to the private
  `UnknownExtension` (defined in `ext.cpp`, not part of the public API) for
  any OID this library doesn't model in full -- so `CCert::extensionOf()`/
  `extension<T>()` (see `cert.hpp` below) always return *something* for a
  present extension, never null, whether or not its specific type is
  recognized. `critical()` has a public setter (not threaded through every
  concrete subclass's own constructor, which only takes oid/value) so
  `CCert::parseExtensions()` can record the value it read from a parsed
  certificate's `Extension.critical` field as a separate step after
  `create()` returns, and so an `IExtensionBuilder` can opt an extension it
  builds into being critical before adding it to `CCertBuilder::extensions`
  (`CCertBuilder::build()` DER-canonically omits the `critical` BOOLEAN when
  false, writing it only when true). This library parses and preserves
  `critical()`; it does not itself enforce RFC 5280's "reject a certificate
  with an unrecognized critical extension" rule anywhere -- `CCert` has no
  chain-validation engine at all (see this document's own scope note), so
  that policy decision is left to whatever code consumes `CCert`'s parsed
  extensions and does build a validator on top of it.
- **`x509/generalname.hpp` / `src/x509/generalname.cpp`** define
  `CGeneralName`, one `GeneralName` (RFC 5280 4.2.1.6), a 9-way CHOICE
  (`EGeneralNameType`, context-specific tags 0-8) used by four different
  extensions (`SubjectAltName`, `AuthorityKeyIdentifier`'s
  `authorityCertIssuer`, `CRLDistributionPoints`' `fullName`,
  `AuthorityInformationAccess`'s `accessLocation`, and
  `NameConstraints`'s `GeneralSubtree.base`) -- factored out once, here,
  rather than duplicating a 9-way CHOICE decoder in each. Only the
  alternatives realistically seen in commercial certificates get a typed
  accessor (`text()` for `rfc822Name`/`dNSName`/`uniformResourceIdentifier`/
  `registeredID`, `directoryName()` for the `directoryName` alternative);
  `otherName`/`x400Address`/`ediPartyName` keep only their raw,
  still-DER-encoded content (`raw()`) rather than modeling those rarer
  shapes in full. `decode()`'s `directoryName` case unwraps one extra TLV
  layer before reaching the inner `RDNSequence`, since `directoryName [4]`
  must be EXPLICIT (`Name` is itself a CHOICE, which ASN.1 forbids
  implicitly tagging) -- unlike every other alternative here, which is
  IMPLICIT. `decodeList()` decodes a whole `GeneralNames` `SEQUENCE OF
  GeneralName`, skipping (not aborting on) any individual element `decode()`
  can't parse, matching this module's established best-effort philosophy
  (see `cert.hpp` below). `CGeneralSubtree` (`NameConstraints`'
  `GeneralSubtree`: a `base` `GeneralName` plus optional `minimum`/`maximum`
  distance bounds) lives in this same file, immediately below
  `CGeneralName`, since it's a `GeneralName`-shaped value with no identity
  of its own beyond that.
- **`x509/access.hpp` / `src/x509/access.cpp`** define `CAccessDescription`
  (`AuthorityInformationAccess`'s `AccessDescription`: an access method OID
  + a `CGeneralName` location) and, below it, `ECrlReasons` +
  `CDistributionPoint` (`CRLDistributionPoints`' `DistributionPoint`:
  `fullName`/`nameRelativeToCrlIssuer` CHOICE, optional `reasons` bit flags,
  optional `crlIssuer`). `ECrlReasons`' bit positions map directly to the
  `ReasonFlags` BIT STRING's own RFC 5280 4.2.1.13 named-bit numbering (bit
  1 = `keyCompromise` .. bit 8 = `aACompromise`), unlike `exts/ku.hpp`'s
  `EKeyUsages` (see below) -- there's no pre-existing/tested bit layout to
  preserve here, so the natural RFC numbering is used as-is rather than
  propagating `EKeyUsages`' historical inversion to unrelated new code.
  `CDistributionPoint::decode()`'s `distributionPoint [0]` case unwraps one
  extra TLV layer for the same EXPLICIT-CHOICE reason `CGeneralName`'s
  `directoryName` case does (`DistributionPointName` is a CHOICE). Both
  classes are grouped into this one file, rather than living next to the
  single extension class each backs, since a future caller may want to
  construct/compare them independently of `CCdpExtension`/
  `CAiaExtension`.
- **`x509/policy.hpp`** defines `CPolicyInformation`
  (`CertificatePolicies`' `PolicyInformation`: a policy OID +
  `policyQualifiersRaw()`). The `policyQualifiers` `SEQUENCE OF
  PolicyQualifierInfo` is deliberately kept as raw, still-DER-encoded
  content rather than modeling `PolicyQualifierInfo`'s own
  `CPSuri`/`UserNotice` CHOICE in full -- callers overwhelmingly only need
  `policyIdentifier()` itself (e.g. to check for a specific CA/Browser
  Forum policy OID like `OID_ANY_POLICY`), so the added parsing complexity
  isn't worth it yet. Entirely inline, so it has no matching `.cpp`.
- **`x509/exts/`** holds one concrete `IExtension` subclass per RFC 5280
  extension this library models, named by its common short-hand rather than
  spelled out in full (`bc.hpp` = `CBasicConstraintsExtension`, `ku.hpp` =
  `CKeyUsagesExtension` (+ `EKeyUsages`), `eku.hpp` =
  `CEkuExtension`, `san.hpp` = `CSanExtension`,
  `ski.hpp` = `CSkiExtension`, `aki.hpp` =
  `CAkiExtension`, `cdp.hpp` =
  `CCdpExtension`, `aia.hpp` =
  `CAiaExtension`, `cp.hpp` =
  `CPoliciesExtension`, `nc.hpp` = `CNameConstraintsExtension`).
  Every one follows the same shape: a `public static constexpr const char*
  OID` naming its own extension OID (matched by `ext.cpp`'s dispatch table),
  a single constructor taking the raw `extnValue` octets and parsing them
  best-effort (a malformed field is left at a safe default rather than
  failing the whole extension, mirroring `CCert::importDer()`'s own philosophy
  below), and read-only accessors over the decoded result. Each also has a
  matching `C<Name>ExtensionBuilder` over `IExtension::encodeValue(CBuffer&)`
  and the pure-virtual `IExtensionBuilder::build()` (`x509/ext.hpp`) for the
  encoding direction -- all ten parse/build pairs exist, so an extension can
  be round-tripped, and `CCertBuilder::extensions` takes the builders.
  `EKeyUsages` (`ku.hpp`) is the one exception to "natural RFC bit order":
  its bit positions are historically inverted from the `KeyUsage` BIT
  STRING's own named-bit numbering, preserved exactly as `CCert` originally
  defined it (and as existing tests already assert) rather than "corrected"
  to match `ECrlReasons`' RFC-direct convention above, since changing an
  already-tested public enum's values would be a breaking, not a fixing,
  change. `eku.hpp` additionally defines well-known `KeyPurposeId` OID
  constants (`OID_SERVER_AUTH`, `OID_CLIENT_AUTH`, ...) and a `has(oid)`
  convenience query. `cdp.hpp`/`aia.hpp`/`cp.hpp`/`nc.hpp` are each a thin
  extension-level wrapper (an OID + a `TArray` of decoded entries) around
  the value types `x509/access.hpp`/`x509/policy.hpp`/`x509/generalname.hpp`
  actually define, per those files' own bullets above.

## CRL, OCSP, and certification requests

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`x509/crl.hpp` / `src/x509/crl.cpp`** define the CRL (RFC 5280 5)
  side, split across three types rather than one read/write class:
  `CCrlRevokationInfo` is a single `revokedCertificates` entry
  (`serialNumber()`, `timestamp()`, `reason()`, plus `isFor(cert)` to test
  it against a certificate and `encode()`/`decode()` for its own TLV);
  `CCrlReader` parses a `CertificateList` (`decode()`, then `version()`/
  `issuer()`/`thisUpdate()`/`nextUpdate()`/`revokations()`) and answers the
  two questions a caller actually has -- `find(cert, out)` for the matching
  entry and `check(cert)` for a plain revoked/not-revoked verdict; and
  `CCrlWriter` builds one (`add(cert, when, reason)`/`remove(cert)`, then
  `build(issuer, out)` to sign it with the issuer's key). The reader/writer
  split mirrors `asn1`'s own `CReader`/`CWriter` rather than `CCert`'s
  single import/export class, because a CRL is naturally produced and
  consumed by different parties.
  `ECrlReasons` (`x509/access.hpp`) is shared with the CRLDistributionPoints
  extension; the ENUMERATED-to-flag mapping between RFC 5280 5.3.1's
  `CRLReason` wire values and those flag bits is deliberately not
  one-to-one (`ReasonFlags` bits 7/8 vs. ENUMERATED 9/10, and ENUMERATED 8
  `removeFromCRL` has no flag at all), so it lives in its own private
  `CrlReasonCodec` (`src/x509/crlreason.hpp`) instead of being open-coded
  at each call site.
  `verifyBy(issuer)`/`tbsCertList()`/`signature()` mirror `CCert`'s own
  three exactly, down to deciding hash-versus-raw from the issuer key's
  algorithm -- see that bullet for the reasoning.
  Two scope notes: `check()` reports only whether the certificate appears
  in the list -- it verifies no signature of its own (call `verifyBy()`
  separately) and does not confirm the CRL was issued by the certificate's
  own issuer, so a CRL from an unrelated CA with a colliding serial number
  would still produce a verdict -- and `CCrlWriter` emits no
  `crlExtensions`, so the `CRLNumber`/`AuthorityKeyIdentifier` RFC 5280
  5.1.2 expects are absent from CRLs it produces.
- **`x509/ocsp.hpp` / `src/x509/ocsp.cpp`** define the OCSP (RFC 6960)
  request/response pair, the one place in `x509/` where signature
  *verification* exists. `COcspCertId` is the `CertID` that identifies a
  certificate by issuer-name hash, issuer-key hash and serial, under a
  caller-chosen `hashAlgo()` (SHA-1 by default, as deployed responders
  expect); `COcspEntry` is one `SingleResponse` (`certId()`, `status()`,
  `reason()`, `thisUpdate()`/`nextUpdate()`/`revocationTime()`).
  `COcspRequest`/`COcspRequestBuilder` and
  `COcspResponse`/`COcspResponseBuilder` then follow the same parse-side/
  build-side split as the CRL types: the builders take certificates
  (`add(cert, issuer, hashAlgo)`), generate a nonce (`generateNonce()`) and
  `build()` the DER; the parse side exposes `decode()`, the decoded
  entries, and -- unlike `CCert`/`CCrlReader` -- a real
  `verifySignature(responderCert)`. `EOcspStatus` carries the top-level
  `responseStatus`, and only `EOCSP_OK` carries anything further by the
  grammar, which is why `COcspResponse::status()` has to be checked before
  any other accessor means anything. `find()`/`check()` mirror
  `CCrlReader`'s. The shared wire helpers both sides need (the nonce and
  basic-response OIDs, single-extension list encoding, `GeneralizedTime`
  formatting) live in a private `OcspCodec` (`src/x509/ocspcodec.hpp`).
- **`x509/csr.hpp` / `src/x509/csr.cpp`** define the PKCS#10 (RFC 2986)
  certification-request pair, `CCertRequest`/`CCertRequestBuilder`, named
  after `COcspRequest`/`COcspRequestBuilder` -- the closest precedent, since a
  CSR is likewise one object that one party produces and another consumes.
  The parse side mirrors `CCert`'s surface (`importDer()`/`importPem()`/
  `importFrom()` with the same `ECertFormat`, `exportDer()`/`exportPem()`/
  `exportAs()`, `subject()`, `keyAlgo()`/`signAlgo()`, `rawPublicKey()`/
  `publicKey()`, `signature()`, `rsaPssParams()`, `extensionOf()`/
  `extension<T>()`), plus `certificationRequestInfo()` -- the exact signed
  bytes, in the same original-bytes-not-a-re-encoding sense as
  `CCert::tbsCertificate()`.

  Three things are specific to PKCS#10 and worth knowing:

  1. **The import verifies the self-signature and fails without it.** Every
     field of a CSR is an unauthenticated claim by whoever produced it; the
     self-signature is the single thing a request attests (possession of the
     private half of `subjectPKInfo`), so `importDer()` refuses to report
     `ERET_OK` until it checks out, and a request signed with an algorithm
     this library cannot verify is rejected rather than imported unchecked.
     That is the opposite of `CCert::importDer()`'s deliberate leniency, and
     for a reason: a certificate's fields are still meaningful to a caller
     who can't reach the issuer's key, a request's are not. `verify()` is
     public as well, for re-checking by hand.
  2. **`attributes [0] IMPLICIT Attributes` is not OPTIONAL.** A request with
     nothing to carry still writes a present-but-empty SET (`A0 00`), and one
     that omits the field is rejected -- OpenSSL itself accepts such a
     request, so the check has to be explicit. `SCertRequestAttribute` holds
     one attribute's type OID plus its `values SET OF` content verbatim, with
     the same meaning in both directions so a parsed attribute feeds straight
     back into a builder. PKCS#9's `extensionRequest`
     (`CCertRequest::OID_EXTENSION_REQUEST`) is the one attribute decoded
     further: its `Extensions` value goes through `CCert::parseExtensions()`,
     so a requested SubjectAlternativeName surfaces as the same
     `CSanExtension` a certificate's own would.
  3. **The key is supplied as a whole `SKeyPair` and nothing else.**
     `CCertRequestBuilder` has no way to name a public key separately from the
     private key that signs for it, and `build()` re-derives the public half
     and compares -- so there is no path to an unsigned request, nor to one
     asking for a key the requester can't prove. `build()` hands its output to
     `CCertRequest::importDer()`, which means the signature it just produced
     is re-verified over the bytes as written.

  The CA-side half is **`CCertBuilder::subjectFrom(request)`**, which copies
  the request's subject name and public key into the certificate builder and
  deliberately nothing else. There is no method that copies a request's
  requested extensions, because that is how a CA ends up issuing a CA
  certificate, or a certificate for a domain the requester doesn't control,
  because the requester asked for it; a CA that wants to grant one reads that
  specific extension (`request.extension<CSanExtension>()`), checks it against
  its own policy and pushes it onto `extensions` itself.

  Almost all of the DER work is shared with `CCert` rather than duplicated:
  `encodeName()`, `encodeAlgorithmIdentifier()`,
  `encodeSubjectPublicKeyInfo()`/`decodeSubjectPublicKeyInfo()`,
  `makePublicKey()`, `encodeExtensions()`, `parseExtensions()`,
  `resolveSigAlgoForSigning()`/`resolveSigAlgo()`/`parseRsaPssParams()`,
  `signTbs()` and `verifySignedBlob()` are all `CCert` statics reached through
  friendship, several of them factored out of `CCertBuilder::build()`'s body
  for exactly this. `signTbs()`/`verifySignedBlob()` matter most: they are the
  single place that decides hash-then-sign versus sign-the-message (via
  `signsMessageDirectly()`) and PKCS#1 v1.5 versus PSS, so a CSR's
  self-signature cannot be checked by subtly different rules than a
  certificate's.
