# Development model

[한국어](development.ko.md)

## Tests and project files

← [Repository layout](../CONCEPTS.md#detailed-concept-pages)

```
tests/
  time.cpp                  # SDateTime / STimeSpan test cases
  string.cpp                 # TString<T> test cases
  name.cpp                    # CName test cases
  oid.cpp                     # SRawOid/COid parse, format, ordering, cache-index, concurrency, and all-known-OID coverage
  utils/
    djb.cpp                    # CDjb hash test cases
    json.cpp                    # JSON/BSON primitives, nested values, malformed input, escapes and round trips
    base64.cpp                  # CBase64 streaming/one-shot encode/decode test cases, incl. PEM line breaking
    bignum.cpp                 # CBigNum arithmetic/modexp/modinverse/primality test cases
    divmod.cpp                  # CBigNum::divMod() differentially fuzzed against a bit-serial reference built from the public API, plus constructed inputs for Algorithm D's add-back branch (unreachable by random testing)
    montgomery.cpp               # CMontgomery differentially fuzzed against the CBigNum operations it is the fast path for, over every modulus the library ships (the 29 curves' p and n, edwards448's p and L) plus random odd moduli from 1 to 32 limbs
    secure.cpp                   # CSecure test cases: equals()/equalsMask()/select() over every differing-byte position and length, and that zero() leaves nothing behind in a buffer still in scope
    gf2m.cpp                     # CGf2m field-axiom/known-answer-vector/encode-decode test cases, one known-answer vector per field size, independently cross-derived via a standalone Python implementation
  io/
    array.cpp                 # TArray<T> test cases
    octet.cpp                   # COctet test cases
    stream.cpp                    # IStream/MemStream test cases
  asn1/
    tag.cpp                   # CTag test cases
    decoder.cpp                 # CDecoder test cases
    encoder.cpp                   # CEncoder test cases
    reader.cpp                      # CReader test cases
    writer.cpp                       # CWriter test cases
    roundtrip.cpp                   # encode/decode integration tests
    der.cpp                           # CDer test cases
    malformed.cpp                      # adversarial/negative DER: length-rule, tag-form, BIT STRING, INTEGER, OID and time gates fed bytes they must reject
  crypto/
    asyms/
      rsa.cpp                        # RSA keygen/DER round-trip/sign-verify/encrypt-decrypt test cases
      dsa.cpp                        # DSA keygen/DER round-trip/sign-verify test cases (shares one generated key pair across cases -- domain parameter generation is expensive)
      p192.cpp                       # P192 keygen/DER round-trip/sign-verify test cases (shares one generated key pair across cases)
      p224.cpp                       # P224: same coverage as p192.cpp
      p256.cpp                       # P256: same coverage as p192.cpp
      p384.cpp                       # P384: same coverage as p192.cpp
      p521.cpp                       # P521: same coverage as p192.cpp
      secp256k1.cpp                  # SECP256K1: same coverage as p192.cpp
      kat_ecdsa.cpp                   # ECDSA verification against NIST CAVP 186-4 SigVer vectors (K-163/B-163/B-233/K-283/B-283 + P-256 control), positives and negatives -- external oracle for the FIPS 186-4 digest-truncation rule the per-curve round trips can't see
      kat_dsa.cpp                      # DSA verification against NIST CAVP 186-3 SigVer vectors (L=1024/N=160, L=2048/N=256)
      kat_rsa.cpp                       # RSA PKCS#1 v1.5 verification against NIST CAVP 186-3 SigVer15 vectors
      kat_ecdh.cpp                       # prime-curve ECDH against RFC 5903 8.1/8.2 (P-256/P-384) vectors, plus a constructed leading-zero-byte secret (the published ones don't exercise the left-pad), two-direction agreement over generated keys, and the invalid-curve rejections
      bpool160r1.cpp, bpool192r1.cpp, bpool224r1.cpp, bpool256r1.cpp,
      bpool320r1.cpp, bpool384r1.cpp, bpool512r1.cpp, bpool160t1.cpp,
      bpool192t1.cpp, bpool224t1.cpp, bpool256t1.cpp, bpool320t1.cpp,
      bpool384t1.cpp, bpool512t1.cpp
                                     # the 14 Brainpool curves (RFC 5639), each: same coverage as p192.cpp
      fe25519.cpp                    # Fe25519 test cases, every operation checked against CBigNum as an exact oracle (random values, the carry-chain edges exhaustively paired, aliasing, inversion, square root vs. CBigNum's Legendre symbol) -- compiles fe25519.cpp into its own executable, see CERTPP_TEST_PRIVATE_SOURCES
      ed25519.cpp                    # Ed25519 keygen/round-trip/sign-verify test cases, incl. all five of RFC 8032 section 7.1's known-answer vectors (empty, 1-, 2-, 64- and 1023-byte messages; signing is deterministic, so an exact byte match validates the whole pipeline at once)
      ed448.cpp                      # Ed448: same coverage as ed25519.cpp, incl. its own RFC 8032 TEST 1 known-answer vector
      x25519.cpp                     # X25519 keygen/round-trip/deriveSharedSecret test cases, incl. RFC 7748 5.2's Diffie-Hellman and iterated-scalar-multiplication known-answer vectors (independently re-derived via a standalone Python implementation before hardcoding, not just transcribed from a single fetch)
      b163.cpp, k163.cpp, b233.cpp, k233.cpp, b283.cpp, k283.cpp,
      b409.cpp, k409.cpp, b571.cpp, k571.cpp
                                     # the 10 binary/Koblitz curves, each: same coverage as p192.cpp
      gost3410.cpp                   # GOST R 34.10-2012 test cases: RFC 7091 section 7's (r, s) known answer, RFC 9215 appendix D's three test certificates end to end (hash + signature + both byte orders), sign/verify round trips on all nine parameter sets, and wrong-key/tampered-message/tampered-signature/swapped-half negatives
      mldsaring.cpp                  # MlDsaRing: the twiddle table against FIPS 204 Appendix B and re-derived from ZETA, the complete 8-layer NTT against a schoolbook negacyclic multiply, centered()/infinityNorm()
      mldsarounding.cpp              # MlDsaRounding: Power2Round/Decompose/HighBits/LowBits/MakeHint/UseHint, the inversion identity at the bucket boundaries, and Decompose's (q-1) band
      mldsacodec.cpp                 # MlDsaCodec: SimpleBitPack/BitPack and their inverses, HintBitPack/HintBitUnpack and each of its three rejection conditions
      mldsasampler.cpp               # MlDsaSampler: SampleInBall/RejNTTPoly/RejBoundedPoly and ExpandA/ExpandS/ExpandMask against pinned known answers, incl. ExpandA's transposed seed order
      mldsaparams.cpp                # MlDsaParams: every derived length static_asserted against FIPS 204 Table 2
      kat_mldsa.cpp                    # ML-DSA keyGen/sigGen against NIST ACVP: deterministic (rnd = 0) and hedged, internal and external interfaces, plus that the two interfaces disagree and that skDecode rejects an out-of-range s1
      kat_mldsaver.cpp                  # ML-DSA sigVer against NIST ACVP, including all four negative reasons (modified message, commitment, hint, z), a per-region bit-flip sweep, and cross-parameter-set refusal
      mldsa.cpp                          # CMlDsa as an IAsymmetric: the message-not-digest convention (sizeOfDigest() == 0), hedged signatures differing per call, publicKey() re-derivation, and malformed/foreign key refusal
    hashers/
      md4.cpp                    # MD4 test cases (RFC 1320 A.5 vectors + the documented NT hash of "password" + boundary/chunking tests)
      md5.cpp                    # MD5 test cases (RFC 1321 vectors + FIPS-style stress/chunking tests)
      sha1.cpp                     # SHA-1 test cases (FIPS 180-4 vectors)
      sha224.cpp                     # SHA-224 test cases (FIPS 180-4 vectors, cross-checked against openssl)
      sha256.cpp                     # SHA-256 test cases (FIPS 180-4 vectors)
      sha384.cpp                       # SHA-384 test cases (FIPS 180-4 vectors)
      sha512.cpp                         # SHA-512 test cases (FIPS 180-4 vectors)
      sha3.cpp                            # SHA3-256/SHA3-512 test cases (FIPS 202 published examples, rate-boundary lengths, million-'a' stress, chunk-invariance, and that SHA-3 differs from SHAKE at the same output length)
      shake128.cpp                        # SHAKE128 test cases (Python hashlib vectors + one NIST CSRC-published empty-message vector, cross-checked against hashlib)
      shake256.cpp                        # SHAKE256 test cases (known-answer vectors generated locally via Python's hashlib, incl. rate-block-boundary cases)
      shake_squeeze.cpp                   # SHAKE128/SHAKE256 squeeze() test cases: chunk-invariance across every chunk size from 1 byte up, including splits landing on, just before and just after each rate boundary -- the only place a cursor off-by-one would show
      blake2s.cpp                         # BLAKE2s test cases (RFC 7693 Appendix B, the 256-entry unkeyed reference KAT, every digest length 1-32, block-boundary lengths, chunk-invariance)
      streebog.cpp                         # Streebog-256/-512 test cases (RFC 6986's two example messages, the published empty-message digests, chunk-invariance, that the 256-bit digest is not a cut of the 512-bit one, and RFC 9385's HMAC SKEYSEED -- the only available vector whose hash input is an exact multiple of the 64-byte block)
      streebogcore.cpp                     # StreebogCore test cases: Pi' is a bijection, Tau satisfies the Tau(8w+t) == w+8t identity the fast table is built on, the combined LPS table agrees with the literal three-pass spec reading, and the mod-2^512 accumulators carry correctly
    kems/
      mlkemring.cpp                 # MlKemRing: the twiddle table re-derived from ZETA, forward-then-inverse NTT round trip, the NTT-domain multiply against a schoolbook negacyclic reference, and X^256 == -1 asserted directly
      mlkemcodec.cpp                 # MlKemCodec: ByteEncode/ByteDecode round trips at every width, and the compression rounding checked against the exact rational definition for every coefficient in [0, q)
      kat_mlkem.cpp                   # ML-KEM keyGen/encap/decap against NIST ACVP for all three parameter sets, including the modified-ciphertext records (implicit rejection is a defined output, so ACVP publishes its expected secret) and both key-check negative groups
      mlkem.cpp                        # MLKEM as an IKem: that repeated encapsulate() calls differ, that a tampered ciphertext returns ERET_OK with a different secret, and that a parameter set the standard never defined is refused by all eight entry points
    rng.cpp                       # CRng::fill() test cases
    hmac.cpp                      # CHmac test cases (RFC 4231's SHA-224/256/384/512 vectors and RFC 2202's SHA-1 ones, the over-long-key hashing rule, and that verify() accepts only the exact tag)
    blake2smac.cpp                # CBlake2sMac against all 256 keyed BLAKE2s reference KAT entries, chunking, key lifecycle, and separation from HMAC-BLAKE2s
    hkdf.cpp                       # CHkdf test cases (RFC 5869 Appendix A's SHA-256 A.1-A.3 and SHA-1 A.4-A.6, plus that an absent salt equals a HashLen zero salt)
    pbkdf2.cpp                      # CPbkdf2 test cases (RFC 6070's HMAC-SHA1 vectors, RFC 7914 s11's HMAC-SHA256 ones, the iterations-is-0 and output-length refusals; says why the 16777216-iteration case is left out)
    siphash.cpp                   # CSipHash test cases (all 64 of the SipHash reference's vectors_sip64 entries, chunking, key-reuse/restart semantics, error paths)
    syms/
      aes.cpp                      # AES test cases (NIST SP 800-38A CBC known-answer vectors incl. F.2's four-block one unpadded, round-trip, tamper, error paths)
      aria.cpp                     # ARIA test cases (RFC 5794 Appendix A vectors for all three key sizes, CBC/padding, invalid keys and IVs)
      des.cpp                       # DES test cases (the classic FIPS-46 vector)
      des3.cpp                       # TripleDES test cases (DES-composition cross-check)
      chacha20.cpp                    # ChaCha20 test cases (RFC 8439 Appendix A.1, chunked stream, independent scalar differential across SSE2/AVX2/AVX-512 boundaries)
    aeads/
      chacha20poly1305.cpp          # CPoly1305 + CChaCha20Poly1305 test cases (RFC 8439 2.5.2/2.6.2/2.8.2)
      xchacha20poly1305.cpp          # CXChaCha20Poly1305 test cases (draft-irtf-cfrg-xchacha A.3's vector, the HChaCha20 subkey against A.1, and that a 192-bit nonce whose last 8 bytes repeat does not repeat the keystream)
      aesgcm.cpp                     # CAesGcm test cases (the GCM spec's Appendix B 96-bit-IV cases 1-4/7-10/13-16, aliasing, tag truncation, tamper, error paths)
      ghash.cpp                       # Ghash test cases (field identities in GCM's bit order, multiply-by-x against the shift, chunking, portable-vs-PCLMULQDQ differential)
    eccurve.cpp                   # CEcCurve/SEcPoint test cases (group law, joint multiplication, SEC1 encoding, group-order check)
    ec2curve.cpp                  # CEc2Curve/SEc2Point test cases, for all 10 known curves (on-curve, negation, group law, joint multiplication, SEC1 encoding, group-order check)
    policy.cpp                    # CAlgorithmPolicy defaults and legacy-algorithm opt-in behavior
    safe_api.cpp                  # owning-output overloads and failure-state checks across public crypto APIs
  x509/
    cert.cpp                  # CCert::importDer() test cases (own self-signed RSA/EC/KeyUsage/private-key fixtures), extension<T>() lookup, CCertBuilder::build() (self-signed RSA/DSA/EC/EdDSA, every digestAlgo/rsaPss combination)
    crl.cpp                      # CCrlWriter::add()/remove()/build() + CCrlReader::decode()/find()/check() round-trip test cases (own self-signed CA fixtures)
    ocsp.cpp                      # COcspCertId/COcspEntry/COcspRequestBuilder/COcspResponse round-trip + signature-verification test cases
    csr.cpp                       # CCertRequest/CCertRequestBuilder (PKCS#10): five externally-produced fixtures (four `openssl req`, two hand-assembled from RFC 2986 and signed by `openssl dgst`), a byte-exact known answer for this library's own output, present-but-empty `attributes`, tamper rejection, and CCertBuilder::subjectFrom()
    exts/                         # one .cpp per extension type, each building -> encoding -> reparsing its own extension
      bc.cpp, ku.cpp, eku.cpp, san.cpp, ski.cpp, aki.cpp, cdp.cpp, aia.cpp, cp.cpp, nc.cpp
    verify.cpp                    # CCert::verifyBy()/tbsCertificate()/signature() and the CCrlReader equivalents: genuine signatures, wrong-issuer and tampered-byte rejection
    malformed.cpp                 # adversarial/negative x509: trailing bytes, malformed [3] extensions wrapper, inner/outer signature-algorithm mismatch, BIT STRING unused bits, pathLenConstraint range
    chain.cpp                     # CCertCollection test cases against a real three-level hierarchy issued in the test: lookups, findIssuerOf(), buildChain(), verifyLinks(), checkKeyPairing()
    validator.cpp                 # CPathValidator trust, time, constraints, usage, name constraints, depth, signature, and unavailable-feature results
    gost.cpp                      # RFC 9215 GOST certificate/CSR SubjectPublicKeyInfo and signature encodings
    kemspki.cpp                   # RFC 9935 ML-KEM SubjectPublicKeyInfo known answers and malformed-input rejection
    chain/                        # one .cpp per container format
      pem.cpp                       # CPemChainFormat test cases: round-trip, append-not-replace, malformed/truncated/encrypted containers, CRLF and inter-block text, plus certs/openssl-*.pem -- fixtures written by OpenSSL 3.4.0, not by this library
      pfx.cpp                       # CPfxFormat test cases: reads five PFX containers OpenSSL 3 wrote, round-trips its own, the MAC-covered tamper sweep, and the CCert PKCS#8 wrap/unwrap pair
      certs/                        # the PEM fixtures, and fixtures/ the PFX ones -- both written once by OpenSSL 3 and checked in, so the suite needs no openssl on PATH. Reading a file this library did not write is the only thing that separates an implementation of a format from a self-consistent one
    realcerts.cpp                # real commercial certificates on disk under certs/implemented/: github.com, amazon.com, sourceforge.net, a QuoVadis/DigiCert RSASSA-PSS intermediate, and the IdenTrust ML-DSA-87 pilot root whose self-signature verifies end to end
  dnssec/
    name.cpp                      # CDnsName test cases (wire form, case folding, label counting, malformed names, compression-pointer rejection)
    records.cpp                    # DNSKEY/DS/RRSIG test cases against published RFC 5702, 6605, 8080, and 9558 artifacts
    keys.cpp                        # CDnssecKeys tests including RFC 9558 GOST algorithm 23, fixed-width signature re-padding, and end-to-end conversion
third-party/
  CMakeLists.txt           # exposes vendored deps as CMake targets; add_subdirectory'd only when CERTPP_BUILD_TESTS=ON
  doctest/
    doctest.h                 # vendored single-header test framework (MIT)
CMakeLists.txt              # builds certpp (+ tests, if CERTPP_BUILD_TESTS=ON) as shared (default) or static
```
```

## Build model

← [Concepts](../CONCEPTS.md)

CMake builds one target, `certpp` (aliased `certpp::certpp`), either as a
shared library (default) or static library via `-DCERTPP_BUILD_SHARED=OFF`.
The `__COMPILES_LIBCERTPP__` definition is `PRIVATE` (only the library's own
translation units get dllexport), while `__SHARED_LIBCERTPP__` is `PUBLIC`
so consumers linking against the shared build automatically get
dllimport-annotated declarations. See [BUILDING.md](../BUILDING.md) for commands.

Hardware acceleration is split into four build options, matching
the unrelated instruction-set families it draws on -- disabling one never
affects the others:

- `CERTPP_DISABLE_HWACCEL_SIMD` (`OFF` by default) disables the extended-
  instruction paths independent of AES-NI and SHA-NI: ADX/BMI2 in `CBigNum`,
  PCLMULQDQ in `CGf2m` and `Ghash`, GFNI reflection in `Ghash`, the SSE2/AVX2/AVX-512F
  ChaCha20 keystream, BMI1 ANDN in Keccak, BMI2 RORX in SHA-384/SHA-512, and
  AVX512-IFMA in Poly1305. Each affected component keeps a portable path;
  runtime CPUID checks select optional instructions, while SSE2 is baseline
  on x86-64.
- `CERTPP_DISABLE_HWACCEL_AVX512` (`OFF` by default) disables only the
  sixteen-block ChaCha20 AVX-512F path and the eight-block Poly1305
  AVX512-IFMA path. AVX2/SSE2 and the other SIMD families remain available.
- `CERTPP_DISABLE_HWACCEL_SHA` (`OFF` by default) forces `SHA1::transform()`/
  `SHA256::transform()` (`src/crypto/hashers/sha1.cpp`,
  `src/crypto/hashers/sha256.cpp`) to always use their portable compression
  loop instead of the x86 SHA Extensions (SHA1RNDS4/SHA1NEXTE/SHA1MSG1/
  SHA1MSG2 and SHA256RNDS2/SHA256MSG1/SHA256MSG2 respectively), gated behind
  a runtime CPUID check (`hasSha()`, CPUID leaf 7 sub-leaf 0, EBX bit 29) the
  same way the other optional paths gate on their own CPUID bits. `MD5` is
  unaffected. SHA-384/SHA-512 and SHA-3/SHAKE have BMI-based accelerated
  paths governed by `CERTPP_DISABLE_HWACCEL_SIMD`, not this SHA-extension
  switch.
- `CERTPP_DISABLE_HWACCEL_AES` (`OFF` by default) forces `AesCore`
  (`src/crypto/syms/aescore.cpp`) to use portable rounds instead of AES-NI for
  single blocks/CBC and VAES for parallel GCM counters. AES-NI uses its own
  runtime CPUID check (`hasAesNi()`, leaf 1, ECX bit 25). The VAES checks decode
  AVX2/AVX-512F and VAES directly from CPUID and verify the corresponding OS-enabled
  XMM/YMM/ZMM state in XCR0; they do not depend on compiler-specific CPU-feature strings.
  `DES`/`TripleDES` have no accelerated path and are
  unaffected; `ChaCha20` uses SSE2/AVX2/AVX-512F rather than an AES extension
  and so answers to `CERTPP_DISABLE_HWACCEL_SIMD` instead -- see the
  `crypto/syms/aes.hpp` bullet above for the Equivalent Inverse Cipher
  construction the decrypt side uses.

All four settings' accelerated and portable paths are expected to produce
byte-identical results and are verified against the full test suite before
any change to either path is considered done; a separate build directory
(e.g. `build_noaccel/`) is a convenient way to keep an accelerated and a
portable-only configuration built at once without rebuilding the whole
library on every toggle, since these options -- like `CERTPP_RNG_FALLBACK`
above -- are `target_compile_definitions` switches that force a full
rebuild of `certpp` itself when changed.
