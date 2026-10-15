# Certificates and containers

[한국어](certificates.ko.md)

## X.509 certificates

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`x509/cert.hpp` / `src/x509/cert.cpp`** define `CCert`, parsing a DER
  X.509 `Certificate` (`importDer(data)`) into subject/issuer
  (`CDistinguishedName`), validity (`SDateTime`), serial number, key/
  signature algorithm identifiers, the raw `SubjectPublicKeyInfo`, and every
  extension. Only fields this class exposes a getter for are retained --
  `issuerUniqueID`/`subjectUniqueID` and the TBSCertificate-embedded copy of
  the signature algorithm are read past but discarded. Parsing follows one
  consistent best-effort contract: `importDer()` builds every field into local
  variables first and only commits them to `*this` at the very end (so a
  failure partway through never leaves the object half-populated), but an
  *algorithm* it doesn't recognize (an unlisted key/signature/curve OID) is
  never itself a parse failure -- `keyAlgo()`/`signAlgo()` fall back to the
  OID's own dotted-decimal text, and `publicKey()`/`createHasher()` simply
  return null, since the rest of a certificate's data is still meaningful
  even when this library can't act on its cryptographic algorithm. The
  three private static tables `KEY_ALGOS`/`SIG_ALGOS`/`EC_CURVES` (each
  `{oid, name, which}`) drive that resolution; a DSA key's split
  `SubjectPublicKeyInfo` representation (`Dss-Parms {p, q, g}` +
  a bare `INTEGER y`) is re-assembled into the standalone `SEQUENCE {p, q,
  g, y}` blob `DSA::createPublicKey()` expects via `buildDsaPublicKeyBlob()`,
  the one algorithm needing this extra step.

  `signatureAlgorithm`'s `parameters` field is read for exactly one
  algorithm, id-RSASSA-PSS (1.2.840.113549.1.1.10, RFC 4055) -- the only
  signature algorithm here whose parameters carry information the verifier
  needs rather than a NULL placeholder, since the OID itself names no digest.
  `parseRsaPssParams()` (the inverse of `buildRsaPssParams()`) reads
  `RSASSA-PSS-params` into `SRsaPssParams`, exposed by `rsaPssParams(out)`,
  and `_sigHashAlgo` is then set from its `hashAlgorithm` so `createHasher()`
  and `verifyBy()` work as they do for every other algorithm. All four fields
  are `DEFAULT`ed and DER omits a field equal to its default, so the parse
  starts from `SRsaPssParams`' own constructor -- which holds exactly those
  defaults (SHA-1, MGF1-SHA-1, salt 20, `trailerFieldBC`) -- and an absent
  field is reported as its default rather than as "absent", because under DER
  those are the same statement. Parameters that *don't* parse follow the same
  best-effort contract as an unresolved OID: `signAlgo()` still reads
  `rsassaPss`, but `_sigHashAlgo` stays `EHASH_UNKNOWN`, so `verifyBy()`
  reports `ERET_NOTSUP` instead of falling back to those SHA-1 defaults --
  which would be a guess at what a signature covers.

  `publicKey()`/`privateKey()` are genuinely lazy: `_cachedPub`/`_cachedPvt`
  (`mutable`) are cleared (not rebuilt) by `importDer()`, and only actually
  constructed the first time each accessor is called -- a caller that never
  asks for the key pays nothing for it. `privateKey(IPrivateKeyPtr&)`
  (the setter) validates the incoming key is genuinely this certificate's
  own by comparing its derived public key against `publicKey()`
  (`IKeyBase::compare()`) before accepting it. `createHasher()` resolves the
  *signature* algorithm's own digest (`_sigHashAlgo`, set from
  `signAlgo()`'s OID during `importDer()`) -- unrelated to `thumbprint()`,
  which is unconditionally the whole raw certificate's SHA-1 digest
  regardless of the certificate's actual signature algorithm, matching the
  conventional meaning of a certificate "fingerprint" in most tooling.

  Extensions are held as `std::vector<IExtensionPtr>` (`_extensions`,
  populated once by the private `parseExtensions()` via `IExtension::
  create()`, which also records each extension's `critical()` flag and
  skips a repeated OID -- keeping only the first occurrence -- rather than
  accumulating a RFC-5280-prohibited duplicate pair `extensionOf()`'s
  first-match lookup and a caller iterating `_extensions` directly could
  otherwise disagree about), looked up by OID through `extensionOf(oid, out)`
  (linear scan -- the extension count on a real certificate is always small,
  so this needs no map) or, more commonly, through the public
  `template<typename TExtension> extension<TExtension>()` helper, which
  looks up `TExtension::OID` and `dynamic_pointer_cast`s the result --
  e.g. `cert.extension<CBasicConstraintsExtension>()`. `keyUsages()`,
  `subjectKeyIdentifier()`, and `authorityKeyIdentifier()` are all just
  thin callers of `extension<T>()` over `exts/ku.hpp`/`ski.hpp`/`aki.hpp`
  respectively, kept as their own named methods (rather than requiring
  every caller to spell out `extension<CKeyUsagesExtension>()` etc.
  themselves) since they're the three extensions virtually every consumer
  needs.

  `verifyBy(issuer)` answers "did this issuer sign this certificate?" --
  pass `*this` for a self-signed one. It hashes `tbsCertificate()` (the
  original TBS TLV as it appears in `rawData()`, never a re-encoding of the
  parsed fields: the signature covers the issuer's bytes, and re-encoding
  would silently "repair" any quirk they contain) and checks it against
  `signature()` with the issuer's public key. Whether to hash at all is
  decided from the *issuer key's* own algorithm rather than from
  `_sigHashAlgo == EHASH_UNKNOWN`, because that value is ambiguous --
  `resolveSigAlgo()` leaves it untouched for an unregistered OID, which is
  indistinguishable from EdDSA's legitimate "no separate hash", and reading
  it as EdDSA would hand raw TBS bytes to an ECDSA/DSA verify as though they
  were a digest.

  That decision is `CCert::signsMessageDirectly(which)`, one function rather
  than a predicate repeated at each site -- Ed25519, Ed448 and all three ML-DSA
  parameter sets sign the message itself. Four places have to agree about it
  (`CCert::verifyBy()`, `CCrlReader::verifyBy()` and both OCSP
  `verifySignature()`s), and a site that misses an entry does not fail to
  compile or fail loudly: it hands raw TBS bytes to a hash-then-sign verify, or
  hands a digest to ML-DSA and signs that 32-byte string instead of the
  message. Both have been real bugs here, and neither is visible to a
  self-signed round trip.

  For a self-hashing algorithm the signature BIT STRING's content is passed
  through whole. ML-DSA's signature is one opaque blob (`c-tilde || z || h`)
  with no internal ASN.1, exactly like EdDSA's `R || S`, unlike ECDSA's
  `SEQUENCE { r, s }` -- which the EC implementation unpacks itself rather than
  `verifyBy()` doing it.

  `verifyBy()` is a *single-link* check: no name chaining, no validity
  window, no constraint enforcement. An RSASSA-PSS-signed certificate is
  routed through `IAsymmetricContext::verifyPss()` with the hash and salt
  length its own `RSASSA-PSS-params` specify, rather than PKCS#1 v1.5's
  `verify()`. Two encodable-but-unsupported cases fail closed with
  `ERET_NOTSUP` rather than being approximated: a `maskGenAlgorithm` naming a
  different hash than `hashAlgorithm` (this library's `verifyPss()` takes one
  hash algorithm and uses it for both, the only pairing RFC 8017 recommends),
  and a `trailerField` other than `trailerFieldBC`. Verifying with the wrong
  MGF1 hash would reject every valid signature, which a caller cannot tell
  apart from a forgery.

  `importDer()` enforces several DER rules whose absence had been
  exploitable, each covered by `tests/x509/malformed.cpp`: the `Certificate`
  SEQUENCE must be the entire input (a trailing suffix is kept verbatim in
  `_rawData`, so accepting one gave a single certificate unlimited
  `thumbprint()` values and made `exportDer()` replay non-DER bytes); the
  `extensions [3]` wrapper must be constructed and must parse, since
  treating a malformed one as "no extensions present" turned a constrained
  certificate into an unconstrained one that still imported successfully;
  `TBSCertificate.signature` must name the same algorithm as
  `Certificate.signatureAlgorithm` (RFC 5280 4.1.1.2 -- the inner copy is
  signed, the outer is not, yet the outer is what drives verification); and
  `signatureValue`'s BIT STRING must declare zero unused bits, as the
  `SubjectPublicKeyInfo` one already had to.

  Real commercial certificates are checked into
  `tests/x509/certs/implemented/` as `.der` files. Tests read them through
  `readCertFile()` using the `CERTPP_TEST_DIR` compile definition assigned to
  every test target by `CMakeLists.txt`. `identrust-mldsa-root.der` is the real
  "IdenTrust Pilot Root TLS ML-DSA CA 1"
  (OID 2.16.840.1.101.3.4.3.19, which is **id-ml-dsa-87**; the arc runs
  .17/.18/.19 for ML-DSA-44/65/87, and the certificate's own 2592-byte key and
  4627-byte signature confirm which), and because it is self-signed
  `cert.verifyBy(cert)` verifies a third-party post-quantum certificate end to
  end. A companion test case flips one bit in the TBS, signature, and public
  key in turn and requires each verification to fail.

## Certificate chains and containers

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`x509/chain.hpp` / `src/x509/chain.cpp`** define `SCertEntry` (a
  certificate, an optional private key, and the PKCS#9 `friendlyName`/
  `localKeyId` a PKCS#12 bag carries), `CCertCollection` (the lookups and
  `buildChain()` that order a set of certificates by who issued whom -- *not*
  path validation, see the scope note) and `IChainFormat`, the interface a
  container format implements. `IChainFormat::builtIn()` is the only place
  that has to know which formats exist, so adding one is a change there and
  nowhere else; `detect()` tells PEM from PFX by their first bytes.
- **`x509/chain/pem.hpp` / `src/x509/chain/pem.cpp`** define
  `CPemChainFormat`, and with it **all** of this library's PEM handling.
  Multi-block scanning, encapsulation boundaries, labels, base64 framing and
  "this file also carries a private key" are container concerns, so they live
  here rather than in `CCert`, whose native form is DER;
  `CCert::importPem()`/`exportPem()`/`detectCertFormat()` are thin
  delegations, kept because one certificate in a file is the common case.
  `load()` appends and commits nothing until the whole file has parsed, so a
  container that breaks half way through leaves the collection as it was;
  key blocks are paired with certificates by `CCert::privateKey()`'s own
  public-key comparison rather than by position, so a crossed or
  someone-else's key in the file cannot be mispaired. A certificate whose
  algorithm this library doesn't implement is loaded rather than dropped (it
  parses; only its key is unavailable), a structurally broken block makes the
  whole container `ERET_BADREQ`, and a password-encrypted key block --
  `ENCRYPTED PRIVATE KEY`, or RFC 1421's `Proc-Type: 4,ENCRYPTED` -- is
  `ERET_NOTSUP`, because PEM has no password to open it with. **PEM has no
  confidentiality at all**: `needsPassword()` is false, the `password`
  argument is ignored outright, and a private key written out goes to disk in
  the clear -- which is why writing one is opt-in (`CPemChainFormat(true)`,
  what `CCert::exportPem(out, true)` constructs) and `builtIn()` returns the
  certificates-only form. PKCS#9 attributes ride outside the boundaries in
  openssl's own `Bag Attributes` shape, which RFC 7468 5.2 explicitly allows
  and any other reader skips.
- **`x509/chain/pfx.hpp` / `src/x509/chain/pfx.cpp`** define `CPfxFormat`,
  PKCS#12/PFX (RFC 7292) as an `IChainFormat`. The structure it writes is a v3
  PFX whose AuthenticatedSafe holds the certificate bags as a
  `pkcs7-encryptedData` and the key bags as `pkcs7-data` carrying one
  `pkcs8ShroudedKeyBag` each, with a `MacData` HMAC over the whole
  AuthenticatedSafe. The decisions worth recording:

  - **Encryption is PBES2 only** (PBKDF2-HMAC-SHA256 + AES-256-CBC, fresh salt
    and IV per encrypted part). The legacy PKCS#12 PBES1 ciphers
    (RC2-40-CBC, `pbeWithSHAAnd3-KeyTripleDES-CBC`) are neither written nor
    read: such a container comes back `ERET_NOTSUP`, which says "I cannot read
    this" rather than decrypting it under a broken cipher or reporting it as
    malformed. This is also what OpenSSL 3 writes by default, so refusing the
    legacy ciphers costs nothing in practice.
  - **The MAC is HMAC-SHA-256**, where RFC 7292's examples and every tool up
    to about 2021 used SHA-1. SHA-1 MACs are still *verified* on read, because
    refusing them would mean refusing most containers in existence.
  - **`MacData`'s key comes from RFC 7292 Appendix B's own KDF with purpose
    byte 3, not from PBKDF2**, and that is not a choice: RFC 7292 section 4
    specifies that derivation, so reading any real container requires it. Its
    use is confined to exactly that one key -- no PBES1 key or IV is ever
    derived with it -- and it is a file-local helper in `pfx.cpp` rather than
    anything in `crypto/`, because unlike `CPbkdf2` it is a legacy
    PKCS#12-only construction that nothing else should reach for. RFC 9579's
    PBMAC1, which does let PBKDF2 derive the MAC key, is not implemented.
  - **The password is encoded two different ways in the same file**, and this
    is the likeliest single cause of a container no other tool can read. PBES2
    is PKCS#5 and takes the password bytes as given; Appendix B's KDF is
    PKCS#12's own and takes them as a NUL-terminated big-endian UTF-16
    BMPString. `CPfxFormat` reads the `password` span as UTF-8 to make that
    conversion, matching OpenSSL 3 (which converts UTF-8, where the older
    `OPENSSL_asc2uni` zero-extended each byte Latin-1 style). For an ASCII
    password the two agree, which is why only a container written elsewhere
    under a non-ASCII password actually pins it --
    `fixtures/openssl-utf8-password.p12` is there for that and nothing else.
  - **The MAC is verified before anything inside is decrypted or parsed.**
    Until it passes, the AuthenticatedSafe is attacker-controlled bytes:
    decrypting first would make the class a padding oracle, and parsing first
    would expose the ASN.1 reader to input nobody has vouched for. A container
    with no `MacData` at all is refused the same way, since RFC 7292 making it
    OPTIONAL is a statement about the ASN.1 and not permission to trust an
    unauthenticated blob. The comparison goes through `CSecure::equals()`, and
    a wrong password, a failed MAC and a missing MAC all return
    `ERET_KEY_ERROR` -- indistinguishable on purpose, since an implementation
    that separates "wrong password" from "damaged file" has told an attacker
    which to keep trying.
  - **`MAX_MAC_ITERATIONS` caps the one unauthenticated computation.** The MAC
    key must be derived before the MAC can be checked, so `MacData`'s iteration
    count is the only one in the format chosen by whoever supplied the file
    rather than by whoever wrote it — and a 200-byte container claiming two
    billion iterations is minutes of CPU for whoever opens it. The ceiling is
    10,000,000, far above RFC 7292's 1024, OpenSSL's 2048 or this library's own
    600,000, so it costs no interoperability; it bounds damage and is not a
    judgement about strength, and there is deliberately no *lower* bound on the
    counts in a container being read.
  - **`DEFAULT_ITERATIONS` is 600,000**, OWASP's 2023 figure for
    PBKDF2-HMAC-SHA256, measured at roughly 0.3 s per derivation in a release
    build here. The number needing justification is not this one but the
    alternatives: RFC 7292's examples say 1024 and OpenSSL still defaults to
    2048. A container is written once and attacked for years, so the cost
    belongs on the writing side. It is not a floor on *reading* -- a container
    is read with whatever count it carries.
  - **`save()` refuses an empty password** (`ERET_BADREQ`), per
    `IChainFormat::needsPassword()`. An entry with a private key but no
    `localKeyId` is given one -- the certificate's SHA-1 thumbprint, which is
    what OpenSSL uses -- because that attribute is the only thing pairing a
    key bag back to its certificate bag on the way in.
  - Keys travel as PKCS#8, through `CCert::exportPkcs8PrivateKey()` /
    `importPkcs8PrivateKey()`. Those were factored out of `CCert`'s existing
    PEM-side PKCS#8 handling rather than written twice; see `cert.hpp`'s own
    doc comments for what each algorithm puts inside the `privateKey` OCTET
    STRING, and note that a PKCS#8 DSA key carries no `y`, so reading one
    costs a `g^x mod p`.
