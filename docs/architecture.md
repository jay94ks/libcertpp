# Architecture

[한국어](architecture.ko.md)

## Overview

`libcertpp` is a C++17 library, still early-stage but past its initial
scaffolding: a `common` foundation, a `version` module, a `utils` module
(a DJB hash utility, `CHex` hex decoding, `CBase64` base64, `CBigNum` an
arbitrary-precision integer, `CGf2m` a binary-field (GF(2^m)) element, and
`CJson` JSON parsing/serialization),
an `io` layer (spans, a growable array, a resizable working byte buffer
(`CBuffer`), a fixed-size owning one (`COctet`), and a stream
abstraction), a `net` module (IPv4/IPv6/Unix-domain socket addresses and
`CSocket` operations, with native errors translated to `ERetCode`), an
`asn1` module (tag encode/decode, a TLV decoder/encoder,
sequential reader/writer wrappers, and `CDer`'s arbitrary-precision-
`INTEGER`/`SEQUENCE` DER helpers), a `crypto` module, an `x509` module, and a
`dnssec` module.

`crypto` has: an `IHasher` interface with from-scratch MD4/MD5/SHA-1/SHA-224/
SHA-256/SHA-384/SHA-512/SHA3-256/SHA3-512/SHAKE128/SHAKE256/BLAKE2s/
Streebog-256/Streebog-512 implementations; a CSPRNG utility
(`CRng`); an `IAsymmetric` interface with eight concrete implementations
(RSA -- PKCS#1 v1.5 and RSASSA-PSS sign/verify, PKCS#1 v1.5 encrypt/
decrypt; DSA; `CEcdsa`, ECDSA over any of NIST P-192/P-224/P-256/P-384/
P-521, secp256k1, or the 14 Brainpool curves (RFC 5639), plus ECDH key
agreement over the same curves (RFC 5903 / SP 800-56A); `CEcdsa2`, ECDSA
over the 10 NIST binary/Koblitz curves B-163/K-163 .. B-571/K-571;
`Ed25519`/`Ed448`, EdDSA (RFC 8032); `X25519`, Diffie-Hellman key
agreement (RFC 7748); and `CGost3410`, GOST R 34.10-2012 (RFC 7091) over
any of its nine parameter sets); an `ISymmetric` interface with four
concrete implementations (`AES`, `DES`, `TripleDES` -- all CBC,
PKCS#7-padded or unpadded -- and the `ChaCha20` stream cipher); and three
AEADs outside that interface, `CChaCha20Poly1305` (RFC 8439 2.8),
`CXChaCha20Poly1305` (draft-irtf-cfrg-xchacha) and `CAesGcm` (NIST SP
800-38D) -- all from scratch, no third-party dependency.

`x509` parses (and, for `CCert`, also builds/self-signs) DER-encoded
`Certificate` (`CCert`/`CCertBuilder`), `CertificateList`/CRL
(`CCrlReader`/`CCrlWriter`), and OCSP request/response (RFC 6960;
`COcspRequest`/`COcspRequestBuilder`, `COcspResponse`/
`COcspResponseBuilder`), plus ten concrete `IExtension` types under
`x509/exts/` (BasicConstraints, KeyUsage, ExtendedKeyUsage,
SubjectAlternativeName, SubjectKeyIdentifier, AuthorityKeyIdentifier,
CRLDistributionPoints, AuthorityInformationAccess, CertificatePolicies,
NameConstraints). Single-link signature verification exists for all three
(`CCert::verifyBy(issuer)`, `CCrlReader::verifyBy(issuer)`,
`COcspRequest`/`COcspResponse::verifySignature()`), but there is no chain
validation / path-building engine on top of it -- no name chaining, validity
windows, or BasicConstraints/KeyUsage/NameConstraints enforcement. See
"Where this will grow" below.

Certificates and their keys can be carried as a container: `x509/chain.hpp`'s
`CCertCollection` holds them with the PKCS#9 attributes that pair them and
orders them by issuer linkage (which, again, is not validation), and
`IChainFormat` reads and writes that collection as a file.
`x509/chain/pfx.hpp` implements PKCS#12/PFX over PBES2 and a `MacData` HMAC.

The public API surface is header-based under
[`include/certpp/`](../include/certpp/), re-exported through the umbrella
header [`include/certpp.hpp`](../include/certpp.hpp) — every public header
is included there, so consumers can `#include <certpp.hpp>` alone.
Implementation files live under [`src/`](../src/) and mirror the header
they implement (e.g. `include/certpp/version.hpp` <-> `src/version.cpp`).

```
include/
  certpp.hpp             # umbrella header, re-includes the public API
  certpp/
    common.hpp            # CERTPP_API export macro, fixed-width type aliases, ERetCode
    version.hpp            # SVersion struct, GetLibraryVersion() declaration
    time.hpp                # STimeSpan (duration); SDateTime: calendar-field time, now()/from()/toUtc()/toLocal()/toSeconds()/add()/diff()/...
    string.hpp               # TString<T>: owning, growable string buffer (template-only, no .cpp)
    name.hpp                  # CName: an X.509 distinguished-name (DN) component, ENameType
    utils/
      djb.hpp                  # CDjb: DJB hash (plain/case-folded), SDjbValue
      hex.hpp                   # CHex: hex-string-to-bytes decoder (optional "0x"/"0X" prefix), shared by CBigNum::fromHex()/CGf2m::fromHex()
      secure.hpp                 # CSecure: zeroization the compiler may not elide, plus constant-time equals()/equalsMask()/select() -- the operations whose running time must not depend on their inputs
      base64.hpp                 # CBase64: base64 codec, both a streaming push()/finish() transform and static one-shot encode()/decode(); EBase64Mode
      json.hpp                   # CJson: JSON value tree, parseJson()/parseBson(), toString()/toBson()
      bignum.hpp                 # CBigNum: arbitrary-precision non-negative integer (RSA/DSA/EC/Ed25519 math)
      montgomery.hpp              # CMontgomery: one odd modulus + its precomputed Montgomery constants; division-free mul/add/sub/dbl/neg/modExp for the EC field arithmetic
      gf2m.hpp                    # CGf2m: fixed-capacity GF(2^m) binary field element (polynomial basis); EGf2mKnownField + CGf2m::knownField()/knownFieldPtr() name the 5 field sizes the B-*/K-* binary curves share
    io/
      span.hpp              # TSpan<T> / TReadOnlySpan<T> (template-only, no .cpp); SByteSpan/SReadOnlyByteSpan aliases
      array.hpp               # TArray<T>: owning, growable array (template-only, no .cpp); EArrayType
      buffer.hpp                # CBuffer: owning, resizable raw byte buffer -- the working buffer COctet results are built in
      octet.hpp                 # COctet: owning, fixed-size byte buffer
      stream.hpp                  # IStream interface, IStreamPtr, ESeekMode/EStreamCapability
    asn1/
      tag.hpp                # CTag (ASN.1 tag encode/decode), ETagClass, EUniversalTags
      decoder.hpp             # CDecoder (TLV decode + per-type value decoders), EEncodingRule, EDecoderStatus
      encoder.hpp              # CEncoder (TLV encode + per-type value encoders, definite-length form)
      reader.hpp                # CReader: sequential CDecoder-over-an-IStream (or a span)
      writer.hpp                  # CWriter: sequential CEncoder-over-an-IStream
      der.hpp                      # CDer: arbitrary-precision INTEGER/SEQUENCE DER helpers (CBigNum-sized CEncoder/CDecoder extension)
    crypto/
      hasher.hpp               # IHasher interface: reset()/push()/finish(), byteWidth()
      hashers/                   # concrete IHasher implementations, one file each
        md4.hpp                    # MD4 (RFC 1320) -- broken; present only for NTLM/EAP-MSCHAPv2's NT hash
        md5.hpp                    # MD5 (RFC 1321)
        sha1.hpp                   # SHA-1 (FIPS 180-4)
        sha224.hpp                 # SHA-224 (FIPS 180-4) -- SHA-256's compression function, own IV, truncated output
        sha256.hpp                 # SHA-256 (FIPS 180-4)
        sha384.hpp                 # SHA-384 (FIPS 180-4)
        sha512.hpp                 # SHA-512 (FIPS 180-4)
        sha3_256.hpp                # SHA3-256 (FIPS 202): the Keccak sponge with a fixed 32-byte output and the 0x06 domain byte
        sha3_512.hpp                 # SHA3-512 (FIPS 202): same, 64-byte output, 72-byte rate
        shake128.hpp                # SHAKE128, the 128-bit-security sibling of SHAKE256 -- same shape, shares KeccakCore
        shake256.hpp                # SHAKE256, the Keccak/SHA-3-family XOF (FIPS 202); output length fixed per instance via the constructor, not the algorithm
        blake2s.hpp                 # BLAKE2s (RFC 7693), unkeyed; little-endian HAIFA construction, digest length 1-32 bound into the parameter block
        streebog256.hpp             # Streebog256: GOST R 34.11-2012 with a 256-bit hash code (RFC 6986) -- its own IV, not a cut of the 512-bit digest
        streebog512.hpp             # Streebog512: GOST R 34.11-2012 with a 512-bit hash code (RFC 6986)
      keys.hpp                   # SKeySize, SKeySizeSpec, IPublicKey/IPrivateKey interfaces, SKeyPair; EKems/IKemKeyBase/IKemPublicKey/IKemPrivateKey/SKemKeyPair (the parallel KEM key family)
      kem.hpp                     # IKem/IKemContext: KEM counterpart of asym.hpp -- encapsulate()/decapsulate() in place of sign/verify/encrypt/decrypt, because a KEM produces a ciphertext and a fresh secret together rather than encrypting a plaintext the caller chose
      kems/                        # concrete IKem implementations, one file each (mirrors asyms/)
        mlkem.hpp                     # CMlKem/SMlKemParams/SMlKemPoly/CMlKemSampler: ML-KEM (FIPS 203, post-quantum) over raw spans, K-PKE plus the FO transform with implicit rejection; and MLKEM, the same three parameter sets as an IKem
      rng.hpp                     # CRng: CSPRNG utility (OS API, std::random_device fallback)
      eccurve.hpp                  # CEcCurve/SEcPoint: short-Weierstrass point arithmetic (affine coordinates); EEcKnownCurves + CEcCurve::knownCurves() name the built-in P-192/P-224/P-256/P-384/P-521/secp256k1/Brainpool (RFC 5639, 14 curves) and GOST R 34.10-2012 (9 parameter sets, 2 of them cofactor-4) domain parameters
      ec2curve.hpp                 # CEc2Curve/SEc2Point: binary-curve point arithmetic over CGf2m (affine coordinates); EEc2KnownCurves + CEc2Curve::knownCurves() name the 10 built-in B-163/K-163 .. B-571/K-571 domain parameters
      asym.hpp                   # IAsymmetric (algorithm descriptor/factory) + IAsymmetricContext (bound-key sign/verify + deriveSharedSecret key agreement + encrypter/decrypter factory) + IAsymmetricTransformer (encrypt/decrypt session)
      asyms/                      # concrete IAsymmetric implementations, one file each (mirrors hashers/)
        rsa.hpp                     # RSA: PKCS#1 keygen, PKCS#1 v1.5 + RSASSA-PSS (RFC 8017) sign/verify, PKCS#1 v1.5 encrypt/decrypt
        dsa.hpp                      # DSA: FIPS 186-4 keygen (incl. domain params) + sign/verify only
        ecdsa.hpp                     # CEcdsa: ECDSA over any EEcKnownCurves value, keygen + sign/verify + ECDH IAsymmetricContext::deriveSharedSecret() (RFC 5903)
        ecdsa2.hpp                    # CEcdsa2: ECDSA over any EEc2KnownCurves value, keygen + sign/verify only
        ed25519.hpp                    # Ed25519: EdDSA over edwards25519 (RFC 8032), keygen + sign/verify only
        ed448.hpp                       # Ed448: EdDSA over edwards448/"Goldilocks" (RFC 8032), keygen + sign/verify only
        x25519.hpp                      # X25519: Diffie-Hellman key agreement over Curve25519 (RFC 7748), keygen + IAsymmetricContext::deriveSharedSecret() only
        gost3410.hpp                     # CGost3410: GOST R 34.10-2012 (RFC 7091) over any ECURVE_GOST* parameter set, keygen + sign/verify only -- not ECDSA with a different curve (different s/verification equation, GOST's own hash-to-integer rule, and RFC 9215's own key/signature byte orders)
        mldsa.hpp                         # CMlDsa: ML-DSA (FIPS 204, post-quantum) in all three parameter sets, keygen + sign/verify only; sign()/verify() take the MESSAGE, not a digest (sizeOfDigest() == 0), and implement FIPS 204's external interface with an empty context, which is what RFC 9881's id-ml-dsa-* OIDs mean
      transform.hpp                # ITransformer: generic streaming transform interface shared by IAsymmetricTransformer and ISymmetricTransformer
      sym.hpp                      # ISymmetric (algorithm descriptor/factory) + ISymmetricContext (bound-key encrypter/decrypter factory) + ISymmetricTransformer
      syms/                        # concrete ISymmetric implementations, one file each (mirrors asyms/)
        aes.hpp                        # AES: FIPS-197 keygen (128/192/256-bit) + CBC encrypt/decrypt, PKCS#7-padded or unpadded per ISymmetricContext::padding()
        des.hpp                         # DES: FIPS 46-3 keygen (64-bit) + CBC/PKCS#7 encrypt/decrypt -- legacy/interop only
        des3.hpp                         # TripleDES: two-/three-key EDE keygen + CBC/PKCS#7 encrypt/decrypt, built on DES's own block core
        chacha20.hpp                      # ChaCha20: RFC 8439 stream cipher, keygen + encrypt/decrypt (the same XOR operation either way)
      hmac.hpp                     # CHmac: HMAC (RFC 2104) over any IHasher, with a constant-time verify() -- comparing a tag with memcmp leaks the matching prefix length and so makes a forgery oracle
      blake2smac.hpp                # CBlake2sMac: BLAKE2s's own keyed mode (RFC 7693 2.6), which is NOT HMAC-BLAKE2s -- the key goes into the parameter block, not through HMAC's two-pass construction
      siphash.hpp                   # CSipHash: SipHash-2-4, a keyed PRF for short inputs -- RFC 9018's DNS server cookies, and hash-table keying. Not a general-purpose MAC
      poly1305.hpp                 # CPoly1305: RFC 8439 one-time MAC, streaming push()/finish() + a one-shot compute()
      hkdf.hpp                      # CHkdf: HKDF (RFC 5869) extract/expand/derive over any hash CHmac supports -- for input that already has full entropy, and deliberately cheap
      pbkdf2.hpp                     # CPbkdf2: PBKDF2 (RFC 8018 5.2) derive() -- for a password, and deliberately not cheap; NOT interchangeable with CHkdf
      aeads/                       # AEADs: one seal()/open() pair each, not part of the ISymmetric surface (which has nowhere to put AAD or a tag)
        chacha20poly1305.hpp           # CChaCha20Poly1305: RFC 8439 2.8, 256-bit key, 96-bit nonce, 128-bit tag
        xchacha20poly1305.hpp            # CXChaCha20Poly1305: draft-irtf-cfrg-xchacha, 256-bit key, 192-bit nonce -- long enough to choose at random, unlike the 96-bit one
        aesgcm.hpp                      # CAesGcm: NIST SP 800-38D, 128/192/256-bit key, 96-bit IV, 96..128-bit tag
    x509/
      ext.hpp                    # IExtension: concrete base for a decoded extension (oid()/value()), IExtensionPtr, IExtension::create() OID-dispatch factory
      generalname.hpp             # CGeneralName (GeneralName CHOICE, RFC 5280 4.2.1.6), EGeneralNameType; CGeneralSubtree (NameConstraints' GeneralSubtree)
      policy.hpp                   # CPolicyInformation (CertificatePolicies' PolicyInformation)
      access.hpp                    # CAccessDescription (AuthorityInformationAccess's AccessDescription); ECrlReasons, CDistributionPoint (CRLDistributionPoints' DistributionPoint)
      exts/                          # concrete IExtension implementations, one file each, named by the extension's common short name
        bc.hpp                         # CBasicConstraintsExtension
        ku.hpp                          # CKeyUsagesExtension, EKeyUsages
        eku.hpp                          # CEkuExtension
        san.hpp                           # CSanExtension
        ski.hpp                            # CSkiExtension
        aki.hpp                             # CAkiExtension
        cdp.hpp                              # CCdpExtension
        aia.hpp                               # CAiaExtension
        cp.hpp                                 # CPoliciesExtension
        nc.hpp                                  # CNameConstraintsExtension
      cert.hpp                        # CCert: parses a DER X.509 Certificate, EKeyUsages re-exported via exts/ku.hpp; CCertBuilder: builds + self-signs one
      crl.hpp                          # CCrlReader/CCrlWriter: parse/build a DER X.509 CertificateList (CRL); CCrlRevokationInfo: one revoked-certificate entry
      ocsp.hpp                          # COcspRequest/COcspRequestBuilder: parse/build an OCSPRequest; COcspResponse: parse+build an OCSPResponse; COcspCertId (CertID), COcspEntry (SingleResponse)
      csr.hpp                            # CCertRequest/CCertRequestBuilder: parse (verifying the self-signature) / build + self-sign a PKCS#10 CertificationRequest; SCertRequestAttribute: one Attribute, PKCS#9 extensionRequest decoded into extensions
      chain.hpp                          # SCertEntry/CCertCollection: certificates + optional keys + the PKCS#9 attributes that pair them, with issuer-linkage lookups and buildChain() (NOT path validation); IChainFormat: container-format interface, EChainFormats, builtIn()/detect()
      chain/                              # one IChainFormat implementation per container format, the same arrangement exts/ has for extension types
        pem.hpp                            # CPemChainFormat: concatenated RFC 7468 PEM blocks -- and the whole of this library's PEM handling (CCert::importPem()/exportPem() delegate to it). No password, no encryption
        pfx.hpp                             # CPfxFormat: PKCS#12/PFX (RFC 7292), PBES2/AES-256-CBC + PBKDF2 encryption, MacData HMAC integrity
    dnssec/
      name.hpp                       # CDnsName: presentation <-> canonical wire-format domain names (RFC 4034 6.2 case folding); compression pointers deliberately rejected
      records.hpp                     # EDnsAlgorithms/EDnsDigests (IANA numbers, pinned); SDnskey (RDATA + RFC 4034 App. B key tag), SDsRecord (RDATA + the 5.1.4 digest over owner name || DNSKEY RDATA), SRrsig (RDATA + toSignedPrefix())
      keys.hpp                         # CDnssecKeys: DNSKEY <-> IPublicKey and RRSIG signature <-> this library's encoding, per RFC 3110/5702 (RSA), 6605 (ECDSA) and 8080 (EdDSA)
src/
  common.cpp              # namespace scaffold (no out-of-line code yet)
  version.cpp              # SVersion + GetLibraryVersion() implementation
  time.cpp                 # SDateTime implementation (uses <ctime>'s gmtime_s/gmtime_r, localtime_s/localtime_r)
  string.cpp                # empty stub -- TString<T> is entirely templates, so there's nothing to put in it
  name.cpp                   # CName::reset()/compare()/equals()/toString()
  utils/
    djb.cpp                    # CDjb::compute()/computeAsUpper()/computeAsLower()
    hex.cpp                     # CHex::decode()
    json.cpp                    # JSON/BSON parsing and serialization, string escaping and BSON bounds checks
    base64.cpp                   # CBase64 streaming push()/finish() + the static one-shot encode()/decode()
    bignum.cpp                   # CBigNum: schoolbook add/sub/mul, Knuth-D divMod, modExp/modInverse/gcd, Miller-Rabin primality + prime generation via crypto::CRng
    montgomery.cpp                # CMontgomery: the -m^-1 mod 2^32 Newton iteration, R^2 mod m, and the CIOS Montgomery multiply over CBigNum's raw limbs
    secure.cpp                    # CSecure: the zeroization the optimizer is not allowed to delete, and the constant-time compare/select primitives -- volatile writes and mask arithmetic, with no branch on a secret anywhere in the file
    gf2m.cpp                      # CGf2m: XOR add, shift-and-XOR carry-less multiply + word-level polynomial reduction, binary extended-Euclid inverse; the 5 known fields' reduction polynomials, behind a construct-on-first-use accessor (see this module's doc comment for why)
  io/
    buffer.cpp                # CBuffer::store()/resize()
    octet.cpp                 # COctet::store()/clear()
    stream.cpp               # IStream::createMemory() factories
    memstream.hpp             # MemStream: private IStream impl, not part of the public API
    memstream.cpp              # MemStream implementation
  asn1/
    tag.cpp                   # CTag::decode()/encode()
    decoder.cpp                 # CDecoder::decodeLength()/readEncodedValue()
    encoder.cpp                  # CEncoder::encodeLength()/writeEncodedValue()
    reader.cpp                    # CReader implementation
    writer.cpp                     # CWriter implementation
    der.cpp                          # CDer implementation, built on CEncoder/CDecoder
  crypto/
    hasher.cpp                # empty stub -- IHasher is a pure-virtual interface, nothing out-of-line
    hashers/
      md4.cpp                     # MD4 transform (3 rounds of 16) + reset()/push()/finish()
      md5.cpp                     # MD5 transform + reset()/push()/finish()
      sha1.cpp                    # SHA-1 transform + reset()/push()/finish()
      sha2_32core.hpp              # Sha2_32Core::transform(): private, shared SHA-224/SHA-256 compression function
      sha2_32core.cpp
      sha224.cpp                    # SHA-224: own context/IV/truncation, shared transform
      sha256.cpp                     # SHA-256: own context/IV, shared transform
      sha2_64core.hpp              # Sha2_64Core::transform(): private, shared SHA-384/SHA-512 compression function
      sha2_64core.cpp
      sha384.cpp                    # SHA-384: own context/IV/truncation, shared transform
      sha512.cpp                     # SHA-512: own context/IV, shared transform
      keccakcore.hpp                  # KeccakCore: private, shared Keccak-f[1600] permutation + sponge absorb, used by every SHA-3/SHAKE variant
      keccakcore.cpp
      sha3core.hpp                     # Sha3Core: private, shared SHA-3 buffering/padding (0x06 domain byte) over KeccakCore, used by sha3_256.cpp/sha3_512.cpp
      sha3core.cpp
      sha3_256.cpp                      # SHA3-256: drives Sha3Core at RATE=136
      sha3_512.cpp                       # SHA3-512: drives Sha3Core at RATE=72
      shake128.cpp                     # SHAKE128: drives KeccakCore at RATE=168
      shake256.cpp                    # SHAKE256: drives KeccakCore at RATE=136
      blake2score.hpp                  # Blake2sCore: private, the whole BLAKE2s state machine (parameter block, compression, buffering, finalization), shared by blake2s.cpp and blake2smac.cpp
      blake2score.cpp
      blake2s.cpp                       # BLAKE2s: drives Blake2sCore unkeyed, at the constructor's digest length
      streebogcore.hpp                 # StreebogCore: private, shared Streebog g_N round function (S/P/L collapsed into one 8x256 table derived from Pi and A at first use) + the mod-2^512 N/EPSILON accumulators, used by streebog256.cpp/streebog512.cpp; also the one place the RFC 6986 byte order is written down
      streebogcore.cpp
      streebog256.cpp                   # Streebog-256: own IV ((00000001)^64), own context/padding, emits MSB_256 of the final state
      streebog512.cpp                   # Streebog-512: own IV (0^512), own context/padding, emits the whole final state
    keys.cpp                  # SKeySizeSpec::compare() -- IPublicKey/IPrivateKey themselves are pure-virtual, SKeyPair a plain struct, nothing else out-of-line
    kem.cpp                    # IKem::builtIn(): dispatches EKems to a concrete kems/ implementation
    kems/                       # concrete IKem implementations, one file each
      mlkemring.hpp / .cpp          # MlKemRing: private, R_q = Z_q[X]/(X^256 + 1) with q = 3329; NTT/inverse NTT/base-case multiply, twiddles derived from ZETA rather than transcribed
      mlkemcodec.hpp / .cpp          # MlKemCodec: private, FIPS 203's ByteEncode/ByteDecode and Compress/Decompress, plus isCanonical12() -- ByteDecode_12 reduces mod q and so is not injective, which IS the encapsulation-key validity check
      mlkemsampler.cpp                # MlKemSampler: private, SampleNTT (the first consumer of SHAKE128::squeeze()) and the centered binomial sampler
      mlkem.cpp                        # CMlKem (K-PKE + the FO transform with implicit rejection, over raw spans) and MLKEM (the same three sets as an IKem); the only ML-KEM layer that draws from CRng
    rng.cpp                    # CRng::fill(): BCryptGenRandom on Windows / getrandom(2) on Linux (falls back to /dev/urandom) / /dev/urandom elsewhere on POSIX, falling back to std::random_device if unavailable
    transform.cpp               # empty stub -- ITransformer is a pure-virtual interface, nothing out-of-line
    sym.cpp                      # ISymmetric::builtIn() factory dispatch
    syms/
      symkey.hpp                     # SymRawKey: private, shared raw-byte ISymmetricKey (no validation beyond length)
      cbctransformer.hpp              # CbcTransformer: private, shared CBC-mode buffering+chaining+padding (PKCS#7 or none, per ESymPaddings), used by aes.cpp/des.cpp/des3.cpp
      cbctransformer.cpp
      aescore.hpp                      # AesCore: private, shared AES block cipher (own S-box/key schedule, AES-NI accelerated path behind CERTPP_DISABLE_HWACCEL_AES), used by aes.cpp/aeads/aesgcm.cpp
      aescore.cpp
      aes.cpp                          # AES: AesCore + CbcTransformer
      descore.hpp                      # DesCore: private, shared DES block cipher (key schedule + Feistel network), used by des.cpp/des3.cpp
      descore.cpp
      des.cpp                           # DES: DesCore + CbcTransformer
      des3.cpp                          # TripleDES: TripleDesCore (DES-EDE3 composition over DesCore) + CbcTransformer
      chacha20.cpp                      # ChaCha20: from-scratch quarter-round/block function + keystream XOR transformer
      chacha20core.hpp                   # ChaCha20Core: private, shared ChaCha20 block function, used by chacha20.cpp/aeads/chacha20poly1305.cpp
      chacha20core.cpp
    hmac.cpp                     # CHmac implementation: the ipad/opad two-pass construction over any IHasher, with verify() going through CSecure::equals()
    blake2smac.cpp                # CBlake2sMac implementation: drives Blake2sCore with the key in the parameter block and the key block absorbed first
    poly1305.cpp                 # CPoly1305 implementation (130-bit accumulator over 26-bit limbs)
    aeads/
      chacha20poly1305.cpp           # CChaCha20Poly1305: ChaCha20Core + CPoly1305, RFC 8439 2.8's framing
      ghash.hpp                       # Ghash: private GHASH + GCM's GF(2^128) multiply (bit-reflected; PCLMULQDQ path behind CERTPP_DISABLE_HWACCEL_SIMD), used only by aesgcm.cpp
      ghash.cpp
      xchacha20poly1305.cpp             # CXChaCha20Poly1305: HChaCha20 derives a subkey from the first 16 nonce bytes, then ChaCha20-Poly1305 over the remaining 8 -- which is why the 192-bit nonce costs nothing but a subkey derivation
      aesgcm.cpp                       # CAesGcm: AesCore (counter mode) + Ghash, SP 800-38D 7.1's framing
    eccurve.cpp                  # CEcCurve/SEcPoint implementation, plus CEcCurve::_knownCurves' definition (the P-192/P-224/P-256/P-384/P-521/secp256k1/Brainpool and GOST R 34.10-2012 domain parameters, in EEcKnownCurves order -- the GOST ones parsed out of RFC 4357/7091/7836/9215 and machine-checked on-curve/order-checked before hardcoding)
    ec2curve.cpp                 # CEc2Curve/SEc2Point implementation, plus CEc2Curve::_knownCurves' definition (the 10 B-*/K-* domain parameters, in EEc2KnownCurves order -- each independently verified on-curve and order-checked before hardcoding, see this module's doc comment)
    asym.cpp                   # IAsymmetric::builtIn(): dispatches EAsymmetrics to a concrete asyms/ implementation
    asyms/                       # concrete IAsymmetric implementations, one file each
      rsa.cpp                      # RSA implementation, plus the private RsaPublicKey/RsaPrivateKey/RsaContext/RsaTransformer classes
      dsa.cpp                      # DSA implementation, plus the private DsaPublicKey/DsaPrivateKey/DsaContext classes
      ecdsa.cpp                     # CEcdsa implementation (incl. EcContext::deriveSharedSecret(), prime-curve ECDH), plus the private EcPublicKey/EcPrivateKey/EcContext classes
      ecdsa2.cpp                    # CEcdsa2 implementation, plus the private Ec2PublicKey/Ec2PrivateKey/Ec2Context classes
      fe25519.hpp                    # Fe25519: private, GF(2^255 - 19) in ten signed limbs at radix 2^25.5 -- constant-time and division-free, shared by ed25519.cpp and x25519.cpp
      fe25519.cpp
      ed25519.cpp                    # Ed25519 implementation (edwards25519 point arithmetic over Fe25519, scalar arithmetic mod L over CBigNum, EdDSA logic), plus the private EdPublicKey/EdPrivateKey/EdContext classes
      ed448.cpp                       # Ed448 implementation (edwards448 field/point arithmetic, SHAKE256-based EdDSA logic), plus its own private EdPublicKey/EdPrivateKey/EdContext classes
      x25519.cpp                       # X25519 implementation (Montgomery-ladder Curve25519 scalar multiplication over Fe25519, RFC 7748), plus the private X25519PublicKey/X25519PrivateKey/X25519Context classes
      gost3410.cpp                      # CGost3410 implementation, plus the private GostPublicKey/GostPrivateKey/GostContext classes
      mldsa.cpp                          # CMlDsa implementation, plus the private MlDsaPublicKey/MlDsaPrivateKey/MlDsaContext classes; the only ML-DSA layer that draws from CRng
      mldsaring.hpp / .cpp                # MlDsaRing: private, R_q = Z_q[X]/(X^256 + 1) with q = 8380417, complete 8-layer NTT
      mldsarounding.hpp / .cpp             # MlDsaRounding: private, FIPS 204 7.4's Power2Round/Decompose/MakeHint/UseHint
      mldsacodec.hpp / .cpp                 # MlDsaCodec: private, FIPS 204 7.1-7.2's bit packing and hint encoding
      mldsasampler.hpp / .cpp                # MlDsaSampler: private, FIPS 204 7.3's rejection samplers and Expand* procedures
      mldsaparams.hpp                         # MlDsaParams: private, FIPS 204 Table 1's three parameter sets with every length derived
      mldsascheme.hpp / .cpp                   # MlDsaScheme: private, ML-DSA itself over raw spans -- the 7.2 encoders plus KeyGen/Sign/Verify in both the internal and external forms
  x509/
    ext.cpp                    # UnknownExtension (fallback IExtension) + IExtension::create()'s OID-dispatch table
    generalname.cpp             # CGeneralName::decode()/decodeList() (GeneralName CHOICE parsing)
    access.cpp                   # CDistributionPoint::decode()/encode()
    policy.cpp                    # CPolicyInformation::encode() -- the one out-of-line member policy.hpp declares
    crlreason.hpp                  # CrlReasonCodec: private, maps RFC 5280 5.3.1's CRLReason ENUMERATED values to/from ECrlReasons flag bits (deliberately not a 1:1 mapping)
    crlreason.cpp
    ocspcodec.hpp                   # OcspCodec: private, OCSP wire helpers shared by the request/response and their builders (nonce + basic-response OIDs, single-extension lists, GeneralizedTime)
    ocspcodec.cpp
    exts/                          # one .cpp per exts/ header, same abbreviated filenames
      bc.cpp, ku.cpp, eku.cpp, san.cpp, ski.cpp, aki.cpp, cdp.cpp, aia.cpp, cp.cpp, nc.cpp
    cert.cpp                        # CCert implementation: importDer()/importPem()/importFrom(), lazy publicKey()/privateKey(), extension<T>() callers; CCertBuilder::build()/subjectFrom(); the shared encode/decode/sign/verify statics crl.cpp/ocsp.cpp/csr.cpp reach through friendship
    crl.cpp                          # CCrlReader/CCrlWriter/CCrlRevokationInfo implementation, built on CCert's own private encodeName()/encodeTime()/readTime()/resolveSigAlgoForSigning() (friend access)
    ocsp.cpp                          # COcsp*/CCert friend-access implementation (RFC 6960); own file-local GeneralizedTime-only time encode/decode, distinct from CCert's own UTCTime|GeneralizedTime CHOICE helpers
    csr.cpp                            # CCertRequest/CCertRequestBuilder implementation (RFC 2986), built entirely on CCert's own encodeName()/encodeAlgorithmIdentifier()/encode+decodeSubjectPublicKeyInfo()/encodeExtensions()/parseExtensions()/signTbs()/verifySignedBlob() (friend access); own X.690 11.6 SET-OF ordering for the Attributes SET
    chain.cpp                          # SCertEntry/CCertCollection implementation (lookups, buildChain(), verifyLinks(), checkKeyPairing()) + IChainFormat::detect()/builtIn(), the one place that knows which container formats exist
    chain/                              # one .cpp per chain/ header
      pem.cpp                           # CPemChainFormat implementation: encapsulation-boundary scanning, labels, base64 framing, PKCS#9 "Bag Attributes", and the SEC1/PKCS#8/RFC 8410 private-key block encodings
      pfx.cpp                             # CPfxFormat implementation; file-local PBES2 parse/build, the RFC 7292 Appendix B KDF (MAC key only), and the UTF-8 <-> BMPString password/friendlyName conversions
  dnssec/
    name.cpp                    # CDnsName implementation; one shared walk() so a malformed name is rejected identically whichever operation hit it
    records.cpp                  # SDnskey/SDsRecord/SRrsig implementation; big-endian field helpers (unlike Poly1305/ChaCha20 next door, which are little-endian)
    keys.cpp                      # CDnssecKeys implementation; the RSA direction also swaps field order, since DNS writes exponent-then-modulus and this library's DER wants modulus-then-exponent
tests/
  time.cpp                  # SDateTime / STimeSpan test cases
  string.cpp                 # TString<T> test cases
  name.cpp                    # CName test cases
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
    hkdf.cpp                       # CHkdf test cases (RFC 5869 Appendix A's SHA-256 A.1-A.3 and SHA-1 A.4-A.6, plus that an absent salt equals a HashLen zero salt)
    pbkdf2.cpp                      # CPbkdf2 test cases (RFC 6070's HMAC-SHA1 vectors, RFC 7914 s11's HMAC-SHA256 ones, the iterations-is-0 and output-length refusals; says why the 16777216-iteration case is left out)
    siphash.cpp                   # CSipHash test cases (all 64 of the SipHash reference's vectors_sip64 entries, chunking, key-reuse/restart semantics, error paths)
    syms/
      aes.cpp                      # AES test cases (NIST SP 800-38A CBC known-answer vectors incl. F.2's four-block one unpadded, round-trip, tamper, error paths)
      des.cpp                       # DES test cases (the classic FIPS-46 vector)
      des3.cpp                       # TripleDES test cases (DES-composition cross-check)
      chacha20.cpp                    # ChaCha20 test cases (RFC 8439 Appendix A.1 block function, chunked keystream)
    aeads/
      chacha20poly1305.cpp          # CPoly1305 + CChaCha20Poly1305 test cases (RFC 8439 2.5.2/2.6.2/2.8.2)
      xchacha20poly1305.cpp          # CXChaCha20Poly1305 test cases (draft-irtf-cfrg-xchacha A.3's vector, the HChaCha20 subkey against A.1, and that a 192-bit nonce whose last 8 bytes repeat does not repeat the keystream)
      aesgcm.cpp                     # CAesGcm test cases (the GCM spec's Appendix B 96-bit-IV cases 1-4/7-10/13-16, aliasing, tag truncation, tamper, error paths)
      ghash.cpp                       # Ghash test cases (field identities in GCM's bit order, multiply-by-x against the shift, chunking, portable-vs-PCLMULQDQ differential)
    eccurve.cpp                   # CEcCurve/SEcPoint test cases (group law, SEC1 encoding, group-order check)
    ec2curve.cpp                  # CEc2Curve/SEc2Point test cases, for all 10 known curves (on-curve, negation, group law, SEC1 encoding, group-order check)
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
    chain/                        # one .cpp per container format
      pem.cpp                       # CPemChainFormat test cases: round-trip, append-not-replace, malformed/truncated/encrypted containers, CRLF and inter-block text, plus certs/openssl-*.pem -- fixtures written by OpenSSL 3.4.0, not by this library
      pfx.cpp                       # CPfxFormat test cases: reads five PFX containers OpenSSL 3 wrote, round-trips its own, the MAC-covered tamper sweep, and the CCert PKCS#8 wrap/unwrap pair
      certs/                        # the PEM fixtures, and fixtures/ the PFX ones -- both written once by OpenSSL 3 and checked in, so the suite needs no openssl on PATH. Reading a file this library did not write is the only thing that separates an implementation of a format from a self-consistent one
    realcerts.cpp                # real commercial certificates on disk under certs/implemented/: github.com, amazon.com, sourceforge.net, a QuoVadis/DigiCert RSASSA-PSS intermediate, and the IdenTrust ML-DSA-87 pilot root whose self-signature verifies end to end
  dnssec/
    name.cpp                      # CDnsName test cases (wire form, case folding, label counting, malformed names, compression-pointer rejection)
    records.cpp                    # DNSKEY/DS/RRSIG test cases against the published examples in RFC 5702, 6605 and 8080 -- every key tag and DS digest
    keys.cpp                        # CDnssecKeys test cases (DNSKEY round trips per algorithm, the fixed-width r|s re-padding, and a sign/verify end to end through a converted DNSKEY)
third-party/
  CMakeLists.txt           # exposes vendored deps as CMake targets; add_subdirectory'd only when CERTPP_BUILD_TESTS=ON
  doctest/
    doctest.h                 # vendored single-header test framework (MIT)
CMakeLists.txt              # builds certpp (+ tests, if CERTPP_BUILD_TESTS=ON) as shared (default) or static
```

## Module responsibilities

- **`common.hpp`** is the foundation every other header includes. It defines:
  - `CERTPP_API`, the dllexport/dllimport macro switched by
    `__COMPILES_LIBCERTPP__` (set only while building the library itself)
    and `__SHARED_LIBCERTPP__` (set when building/consuming certpp as a
    shared library). Non-MSVC compilers get an empty macro since ELF/Mach-O
    default visibility already exports symbols.
  - Fixed-width integer aliases (`uint8_t` .. `int64_t`, `float32_t`,
    `float64_t`, `size_t`, `ptrdiff_t`, `nullptr_t`) inside `namespace certpp`,
    so the rest of the library uses `certpp::uint32_t` etc. instead of reaching
    into the global namespace.
  - `ERetCode`, the shared status/error-code enum (`ERET_OK`, `ERET_INVAL`,
    `ERET_NOTIMPL`, ...) that fallible operations across the library return,
    instead of each module inventing its own status enum.
  - `using std::swap;`, brought into `namespace certpp` so a hand-written
    move assignment operator anywhere in the library can call unqualified
    `swap(a, b)` per member and have it resolve to `std::swap`. This is
    deliberately a using-declaration, not a custom `certpp::swap<T>`
    template of its own (an earlier version of this file had exactly that,
    with a body identical to `std::swap`) -- an unconstrained template
    named `swap` in `certpp` becomes an argument-dependent-lookup candidate
    for *any* type built out of a `certpp::` type, including ones this
    codebase never declares itself. Concretely, `CDistinguishedName` holds
    a `std::map<ENameType, CName>`; merely moving, assigning, or `.swap()`-ing
    that map makes MSVC-STL's own `<xtree>` code do an unqualified `swap()`
    on internal types (a tree-node pointer, or the comparator
    `std::less<ENameType>`) that are parameterized by a `certpp::` type --
    with a competing `certpp::swap<T>` in scope, that's a hard, unfixable
    ambiguity error (proven by testing several workarounds: relocating the
    swap call only moved which internal STL swap collided, and a per-type
    specific overload -- the trick that fixed `TSpan<T>`/`TReadOnlySpan<T>`
    once for an unrelated `std::sort` collision -- doesn't apply, since the
    colliding type is a private STL implementation detail with no
    declaration to add an overload next to). Replacing the custom template
    with a using-declaration makes `certpp::swap` and `std::swap` the same
    entity, so there's nothing to be ambiguous with, for any type, anywhere.
- **`version.hpp` / `version.cpp`** define `SVersion` (major/minor/patch) and
  `certpp::GetLibraryVersion()`. `HEADER_VERSION` in the header and
  `LIBRARY_VERSION` in the `.cpp` are meant to be compared by consumers to
  detect a header/binary mismatch.
- **`time.hpp` / `time.cpp`** define `STimeSpan` (a millisecond duration,
  entirely inline/`constexpr`: `absolute()`, the `total*()`/unit accessors,
  arithmetic and comparison operators) and `SDateTime`, decomposed
  calendar-field time (year/month/day/hour/minute/second/millisecond + an
  `isUtc` flag). `SDateTime` lives at the top level (not under `asn1/`)
  since it's a general-purpose value type — `asn1/decoder.hpp`'s
  `decodeUtcTime()`/`decodeGeneralizedTime()` and `asn1/encoder.hpp`'s
  `encodeUtcTime()`/`encodeGeneralizedTime()` use it, but so will non-ASN.1
  code (e.g. a certificate's validity period once X.509 parsing exists).
  `now()`/`from()`/`toUtc()`/`toLocal()`/`toSeconds()` all convert through
  `<ctime>`: `gmtime`/`localtime` (via `_s` on MSVC, `_r` elsewhere for
  thread safety) for the tm-from-time_t direction, and `mkgmtimeSafe()`
  (`_mkgmtime` on MSVC, `timegm` elsewhere) for the reverse — `std::mktime`
  is deliberately never used on a UTC-valued `tm`, since it only ever
  interprets its argument as local time. `add()`/`subtract()`/`diff()`
  and the `+`/`-`/`+=`/`-=` operators (`STimeSpan` or millisecond-based)
  round-trip through `toMilliseconds()`/`from()`.
- **`string.hpp`** defines `TString<T>` (default `T = char`), an owning,
  growable, null-terminated string buffer — `TSpan<T>`'s owning counterpart.
  Capacity grows in `CAP_INC` (64-element) increments via `reserve()`;
  `trimExcess()` shrinks back down (freeing entirely when the string is
  empty). Provides `append()`/`erase()`/`find()`/`findLast()`/`subString()`/
  `trim()`/`toLower()`/`toUpper()`/`reverse()`, and converts to/from a
  `TSpan<T>`/`TReadOnlySpan<T>` via `toSpan()`. Entirely templates, so it
  has no meaningful `.cpp` (the stub exists only for consistency).
- **`utils/djb.hpp` / `src/utils/djb.cpp`** define `CDjb`, a static-method-only
  DJB hash utility (`SDjbValue = uint32_t`): `compute()` hashes a byte span
  as-is, `computeAsUpper()`/`computeAsLower()` case-fold ASCII letters first
  (for case-insensitive hashing) -- each takes an optional starting `hash`
  so a caller can hash multiple spans as one logical value (`compute(a) `
  then `compute(that result, b)` equals `compute(a+b)` in one call). The
  case-folding functions widen each `char` through `uint8_t` before folding
  it into the hash, not directly to `SDjbValue` -- `char`'s signedness is
  implementation-defined, and a high-bit-set byte (e.g. an escaped
  non-ASCII byte from `CName`) would otherwise sign-extend on a
  signed-`char` platform (MSVC) and hash to a different value than
  `compute()` gives the identical byte on an unsigned-`char` one. Used by
  `CName` to give it a cheap equality pre-check ahead of a full `memcmp`.
- **`utils/hex.hpp` / `src/utils/hex.cpp`** define `CHex`, a single-method
  utility (`static bool decode(const char*, TArray<uint8_t>&)`) that parses
  a hex string (optionally `0x`/`0X`-prefixed) into raw bytes, rejecting
  malformed input. Factored out of what were previously near-duplicate
  hex-parsing helpers in `CBigNum`/`CGf2m` and several `crypto/asyms/`
  implementations; `CBigNum::fromHex()`/`CGf2m::fromHex()` are now thin
  wrappers over it.
- **`utils/secure.hpp` / `src/utils/secure.cpp`** define `CSecure`: the three
  operations on secret bytes that cannot be written the obvious way.
  `zero()` clears a buffer through a volatile function pointer to `memset`,
  so the call cannot be proven ineffective and therefore cannot be removed
  -- a plain `memset` over a local nothing reads again is dead code, and
  MSVC at `/O2` does delete it (checked by reading the generated assembly,
  not assumed). `equalsMask()` compares two spans reading every byte
  whatever the outcome, returning `0xFF`/`0x00` rather than a bool, because
  `std::memcmp` stops at the first mismatch and so leaks the matching
  prefix's length through its running time. `select()` copies one of two
  spans according to such a mask, so a caller can act on a comparison
  without branching on it. There is also a convenience `equals()` returning
  bool, for the cases where that one bit genuinely isn't sensitive.

  The first consumer, and the reason it exists, is ML-KEM's
  `decapsulate()`: the Fujisaki-Okamoto re-encryption check is exactly a
  comparison whose outcome must not be observable, and FIPS 203 separately
  requires the reject flag be destroyed before returning. `CSecure` does
  **not** subsume the inline mask arithmetic in RSA's EME-PKCS1-v1_5
  unpadding or `CbcTransformer`'s PKCS#7 check -- neither is "compare two
  buffers" or "choose between two buffers"; both interleave masking with a
  scan over the padding, so there is nothing here for them to call.

  `CBigNum::secureClear()` is the big-number counterpart, wiping the limb
  allocation (its whole capacity, so limbs above a trimmed length go too)
  and resetting the value to zero. It is opt-in rather than something
  `~CBigNum()` does, which was settled by measurement: clearing on every
  destruction cost 22% across the asymmetric suites and 32% on X25519
  alone, since a scalar multiplication creates a great many temporaries and
  nearly all of them hold public intermediates. Applying it only to named
  secrets costs nothing above the measurement noise. The limitation that
  buys is real and worth stating: temporaries created inside an expression,
  or inside `modExp()`/`modInverse()`, are freed uncleaned, so this narrows
  the window a secret sits in freed memory rather than closing it.

  The values it is applied to are the ones whose exposure is catastrophic
  rather than merely unwanted -- an ECDSA/DSA nonce `k` and the `d*r`/`x*r`
  product beside it (either yields the private key outright from a
  published signature), EdDSA's nonce and the expanded seed behind it,
  X25519's clamped scalar and shared secret, and RSA's CRT intermediates
  (`m1` is `m mod p`, so `gcd(m - m1, n)` is `p` exactly).
- **`utils/bignum.hpp` / `src/utils/bignum.cpp`** define `CBigNum`, an
  arbitrary-precision non-negative integer (little-endian 32-bit limbs,
  schoolbook algorithms throughout -- correctness and simplicity over
  performance, consistent with this library's early-stage priorities). It's
  the shared math type behind every `crypto/asyms/` implementation: `add`/
  `sub`/`mul`/`divMod`/`mod`/`mulMod`/`modSub`/`modNeg`/`shl`/`shr` for basic
  and modular arithmetic, `modExp`/`modInverse`/`gcd` for RSA/DSA/EC-style
  modular arithmetic, and `isProbablePrime` (Miller-Rabin, preceded by
  small-prime trial division)/`generatePrime` (via `crypto::CRng`) for
  RSA/DSA key generation. `fromHex`/`fromLittleEndian`/`toLittleEndian`/
  `fromBigEndianTruncated` round out construction/serialization (the hex
  parsing itself lives in the standalone `CHex` utility, see below);
  `condSwap` is a conditional swap for branch-based scalar-multiplication
  ladders (e.g. `crypto/asyms/x25519.cpp`'s Montgomery ladder). Lives under
  `utils/` rather than `crypto/`, since the type itself is generic math, not
  tied to any one algorithm (or even to `crypto/` specifically) -- only its
  callers are cryptographic.

  **`add`/`sub`/`mul`/`mod`/`mulMod`/`modSub`/`modNeg`/`shl`/`shr` mutate
  `*this` in place and return `CBigNum&` (a reference to `*this`), purely to
  allow chaining (`a.mulMod(b, m).add(c)`) -- they are NOT a
  functional/copy-returning API, unlike a first instinct from their names
  might suggest. A caller that still needs the pre-call value of the
  receiver must copy it explicitly first (`CBigNum saved(original);
  saved.add(x);`), including when the receiver is itself passed back in as
  the `other`/`modulus` argument to a *different* variable's call a few
  lines later (the classic bug this shape invites: mutating a curve's own
  domain parameter, a function's by-reference out-parameter, or a value
  still needed on a later loop iteration, because it happened to be the
  left-hand operand of an otherwise-innocuous-looking expression). Calling
  one of these on a fresh temporary or an rvalue chain (`CBigNum(1).shl(8)`,
  or `CBigNum::modExp(...).mulMod(x, m)`) is always safe, since nothing else
  can be holding a reference to a temporary. `divMod` is the one exception:
  it stays a `const` query reporting both results via out-parameters, since
  it never had a "return the changed value" shape to begin with. Static
  factories (`fromBigEndian`, `fromHex`, ...) and serializers (`toBigEndian`,
  `toLittleEndian`) are unaffected -- they don't operate on an existing
  instance's value, so there's nothing to alias.

  `divMod()` is Knuth's Algorithm D (TAOCP vol. 2, 4.3.1) in base 2^32: it
  normalizes the divisor so its top limb has its high bit set, then produces
  one quotient limb at a time from an estimate over the top two limbs of the
  running remainder, correcting the estimate down and -- rarely -- adding the
  divisor back when it was still one too high. The earlier implementation was
  a bit-serial restoring division: one shift, compare and conditional
  subtract across the whole divisor *per bit of the dividend*. Since every
  `modExp()` performs thousands of reductions, this one routine was the
  dominant cost in RSA, DSA and ECDSA alike -- replacing it took the full
  test suite from 1243s to 140s, with the asymmetric algorithms individually
  7-14x faster.

  Algorithm D's correctness hinges on two things that ordinary use never
  exercises, so both are tested deliberately in `tests/utils/divmod.cpp`:
  the estimate-correction loop, and the add-back branch, which fires on the
  order of once per 2^31 quotient limbs and is *impossible* for a two-limb
  divisor (the estimate is exact there, because the two-limb test then
  examines the whole divisor). Random testing reaches the branch zero times,
  so its inputs were constructed -- exercised exhaustively in a 4-bit-limb
  model of the same algorithm first, then scaled into the top nibble of each
  32-bit limb, which preserves every ratio the estimate depends on. The
  whole routine is also differentially fuzzed against a deliberately naive
  bit-serial reference written using nothing but `CBigNum`'s public
  operations, which is the algorithm this one replaced.

  `mul()` additionally has a hardware-accelerated path (x86-64 only, and
  only when `CERTPP_DISABLE_HWACCEL_SIMD` isn't set): `mulAccelerated()`
  reinterprets pairs of the native 32-bit limbs as 64-bit digits and uses
  MULX (BMI2)/ADCX (ADX) instead of the portable loop's 32-bit schoolbook
  multiply-accumulate, gated behind a runtime CPUID check (`hasAdxBmi2()`)
  since both extensions are optional even on x86-64. Given how much of this
  library depends on `mul()` being correct, this path is verified by a
  dedicated fuzz-style cross-check (`tests/utils/bignum.cpp`, against an
  independent reference multiply built only from `add()`/`shl()`/
  `testBit()`) across many random operand pairs, in addition to running
  this library's whole test suite under both `CERTPP_DISABLE_HWACCEL_SIMD`
  settings. That cross-check earned its keep immediately: an early version
  tried to fold a 64x64 multiply's high word and an addition's carry-out
  into one running "carry" value added straight into the next column,
  which is unsound whenever the three-way sum (the running carry, the
  existing accumulator digit, and the new digit's low word) needs a
  carry-out of 2 -- something a single `_addcarry_u64` chain can't
  represent (it can only ever produce 0 or 1). The fix restructures each
  row into the classic two-step "long multiplication" shape -- first
  compute the whole row `ai * b[]` on its own (safe: every step there only
  ever combines two 64-bit values plus an implicit carry-in), *then* add
  that row into the running total via an ordinary multi-precision add
  (equally safe, same reason) -- rather than trying to fuse both steps
  into a single pass.
- **`utils/montgomery.hpp` / `src/utils/montgomery.cpp`** define
  `CMontgomery`: one **odd** modulus together with the constants that let
  modular arithmetic against it run with no big-number division at all --
  Montgomery's `n' = -m^-1 mod 2^32` and `R^2 mod m`, where
  `R = 2^(32*limbs(m))`. It exists because `CBigNum::mulMod()` has nowhere to
  cache anything: it is necessarily `mul()` then `mod()`, and `mod()` is a full
  Knuth-D long division, so every single modular multiply inside a scalar
  multiplication paid for one. `CMontgomery` hoists that cost out of the loop
  — two divisions once, at construction, against the thousands the loop would
  otherwise perform.

  It is **additive, not a replacement**: `CBigNum::mod()`/`mulMod()` are
  unchanged and still the only option for an even modulus, which Montgomery
  reduction cannot handle (it needs `gcd(R, m) == 1` with `R` a power of two).
  A `CMontgomery` built from an even or zero modulus reports `isValid() ==
  false` and turns every operation into a no-op rather than computing
  something plausible-looking.

  Two domains are in play. *Ordinary* form is the plain residue `a`;
  *Montgomery* form is `a*R mod m`. `toMont()`/`fromMont()` convert,
  `one()` is the Montgomery form of 1 (what a projective `Z = 1` must be
  initialized to), and `mul()` multiplies two Montgomery-form values into a
  third. `add()`/`sub()`/`dbl()`/`neg()` are valid in *either* domain, since
  `a -> a*R` is linear — and they matter as much as `mul()` does, because the
  code they replaced spelled addition as `.add(x)` followed by `.mod(p)`, i.e.
  a long division to reduce a sum that was at most `2p`. `mulMod()` is the
  ordinary-form drop-in for `CBigNum::mulMod()` for a caller that does not want
  to think about domains, and `modExp()` is square-and-multiply in the domain.

  The multiply itself is CIOS (Coarsely Integrated Operand Scanning): the
  schoolbook multiply and the reduction are interleaved per limb of the second
  operand, so the accumulator never exceeds `limbs(m)+2` words and lives in an
  on-stack buffer (sized for 80 limbs, well past P-521's 17, so no curve
  operation allocates). It reaches `CBigNum`'s raw limb array through
  `friend class CMontgomery` rather than new public limb accessors — the
  representation stays `CBigNum`'s own business, and avoiding the per-operation
  copying is the entire point of the class.

  Its final step is the conditional subtraction that brings a result in
  `[m, 2m)` back below `m`. Skipping that is the classic Montgomery bug and it
  only shows on about half of all inputs, never on a hand-picked small case, so
  the class is tested the way `CBigNum::divMod()` is: differentially, against
  the `CBigNum` operation each method is the fast path for, over every modulus
  the library actually ships (the 29 `CEcCurve` parameter sets' `p` and `n`,
  plus edwards448's `p` and `L`), random odd moduli from 1 to 32 limbs,
  exhaustively over `[0, 2m+2]^2` for single-limb moduli, the hand-picked
  `0`/`1`/`m-1`/`m`/`m+1`/`m^2-1`/`m^2+m` operand classes per modulus, and
  200-step chained sequences that would expose an error that only accumulates
  (`tests/utils/montgomery.cpp`, ~915k assertions). Dropping the conditional
  subtraction, perturbing `n'`, or omitting one `fromMont()` each fail it.
- **`utils/gf2m.hpp` / `src/utils/gf2m.cpp`** define `CGf2m`, a binary
  field GF(2^m) element (polynomial basis) -- the field arithmetic
  `CEc2Curve`'s binary curves need, and which `CBigNum` cannot provide
  (`CBigNum` is arbitrary-precision integer arithmetic mod a prime; GF(2^m)
  addition is XOR with no carry, multiplication is carry-less and reduced
  by a fixed irreducible polynomial, not integer division). Fixed-capacity
  (`uint64_t[9]`, 576 bits, covering every field this library defines up to
  GF(2^571)) rather than arbitrary-precision like `CBigNum`, since a field
  element's width never grows past its field's fixed `m`. `add()` is XOR;
  `mul()` is schoolbook shift-and-XOR carry-less multiply followed by
  reduction against the field's trinomial/pentanomial reduction
  polynomial -- or, on x86/x86-64 with `CERTPP_DISABLE_HWACCEL_SIMD` unset and a
  runtime CPUID check confirming PCLMULQDQ support, a fixed 9x9 grid of
  hardware carry-less multiplies (`_mm_clmulepi64_si128`) building the same
  pre-reduction wide product instead, with the reduction step
  itself unchanged either way. That reduction (`reduceWide()`) is word-level,
  not bit-serial: `x^m == x^terms[0] + ... + 1` displaces *every* excess bit
  by the same amount, so the whole excess folds at once -- take
  `hi = wide >> m`, clear from bit `m` up, then XOR `hi` back in at offset 0
  and at each term offset, repeating until nothing remains at or above `m`
  (exactly twice for all five fields here). The earlier bit-serial version
  walked one bit at a time from `2m-2` down to `m`, toggling `1+termCount`
  bits per set bit, which measured at 95-98% of a multiplication's cost and
  so left the PCLMULQDQ product buying almost nothing; `square()` is implemented as `mul(self)` rather than a
  dedicated bit-spread fast path -- correct and much simpler, the same
  performance/simplicity trade-off `CBigNum`/`CEcCurve` already make;
  `inverse()` is the binary extended Euclidean algorithm over `GF(2)[x]`.
  `fromHex()` parses a hex string (via `CHex`, see below); `toInteger()`
  reinterprets this element's polynomial-basis bits as a `CBigNum` (FIPS
  186-4 Appendix C.2), bridging into `CBigNum` arithmetic where `CEcdsa2`
  needs it (e.g. reducing a binary-curve point's x-coordinate mod the
  subgroup order `n`, which is a `CBigNum` even on a binary curve).

  Like `CBigNum` above, `add`/`mul`/`square`/`inverse` mutate `*this` in
  place and return `CGf2m&` for chaining only -- the same "copy first if you
  still need the original" rule applies (see `CBigNum`'s note on this).
  `EGf2mKnownField` names the 5 field sizes (163/233/283/409/571) this
  library's binary curves use -- a "B" and "K" curve of the same size share
  the identical field, only their curve coefficients differ, so the field
  is a `CGf2m`-owned, non-owning `const SGf2mField*` pointing at one of 5
  program-lifetime singletons (via `knownField()`/`knownFieldPtr()`),
  mirroring `CEcCurve`'s known-curves lookup. Those singletons live behind
  a construct-on-first-use function-local `static` rather than a plain
  `CGf2m::_knownFields` class-static array: `CEc2Curve::_knownCurves`
  (`ec2curve.cpp`, a different translation unit) reads them while *it*
  is being statically constructed, and the standard doesn't guarantee
  which translation unit's static objects finish initializing first --
  this bit the initial implementation immediately (every `CEc2Curve`
  coefficient/point silently ended up as a zero-valued, null-field `CGf2m`,
  because the shared field singletons hadn't been populated yet when they
  were read, and `CGf2m::fromBigEndian()`'s bounds check against the
  not-yet-real `field.m` failed every single bit, leaving its `out`
  parameter untouched at its all-null default -- caught by a `SIGSEGV` the
  first time arithmetic dereferenced that null field pointer). The
  function-local `static` sidesteps the ordering question entirely: it's
  guaranteed initialized on first use, regardless of which translation
  unit's static initializer calls it first. The reduction polynomials
  themselves (FIPS 186-4 Appendix D / SEC 2's standard trinomials/
  pentanomials) were independently confirmed irreducible of the correct
  degree via a standalone check (Python's `sympy`) before hardcoding.
- **`name.hpp` / `src/name.cpp`** define `CName`, one component of an X.509
  distinguished name (e.g. a single `CN=...` or `OU=...`), and `ENameType`:
  the six basic X.520 types (`ENAME_CN`/`ENAME_OU`/`ENAME_O`/`ENAME_L`/
  `ENAME_ST`/`ENAME_C`), then `ENAME_OI` (`organizationIdentifier`, 2.5.4.97
  -- ETSI EN 319 412, routine on EU-regulated certificates), `ENAME_SERIAL`,
  `ENAME_TITLE`, `ENAME_GN`, `ENAME_SURNAME`, `ENAME_PSEUDONYM`, `ENAME_DNQ`
  and `ENAME_DC`, all bounded by `ENAME_MAX`. These values cross the
  shared-library ABI boundary, so a new type is *appended* immediately before
  `ENAME_MAX` and never inserted -- inserting one silently shifts every
  enumerator after it for a caller compiled against the older header. The
  same `ENAME_MAX` sizes `TYPE_KEYS`/`TYPE_LABELS`/`TYPE_OIDS`, and a C++
  array with fewer initializers than its declared size compiles without a
  word, leaving the tail default-constructed; `tests/name.cpp` therefore
  walks every enumerator from `ENAME_NONE + 1` to `ENAME_MAX` and requires an
  entry in each of the three. Content is expected to be ASCII; `reset()` (private --
  called only from the `CName(ENameType, const char*, size_t limit)`
  constructor) escapes any byte > 127 with a leading `\` when storing it,
  tracked by a `FLAG_ESCAPED` bit packed into the same `uint16_t` as
  `ENameType` (masked off again by `type()`); `toString(out, escaped)`
  reverses the escaping back to the original bytes by default
  (`escaped=false`), or returns the raw internal (still-escaped) form when
  `escaped=true` -- overloaded for `CString`/`CWideString`, plus a
  `toString<U>(escaped)` convenience template returning a fresh
  `TString<U>`. `CName::keyOf()`/`labelOf()` (static) and `key()`/`label()`
  (member) map a type to its DN attribute key (`"CN"`, `"OU"`, ...) and
  human-readable label (`"Common Name"`, ...) via the
  `TYPE_KEYS`/`TYPE_LABELS` tables; `attributeOid()`/`attributeTypeOf()`
  (static) map a type to/from its DN attribute OID arcs (e.g. `ENAME_CN`
  <-> `{2, 5, 4, 3}`) via the `TYPE_OIDS` table, used by the `asn1` module
  to encode/decode a `CDistinguishedName`'s components (see below). That
  table is an `SAttributeOid { count, arcs[MAX_OID_ARCS] }` per type rather
  than a flat `[4]` row, because `ENAME_DC`'s OID
  (`0.9.2342.19200300.100.1.25`, RFC 4519) is the one recognized attribute
  outside the 2.5.4 `attributeType` arc and is 10 arcs long. `typeOf()`
  compares `strlen(key) + 1` bytes, so the table key's own NUL takes part:
  comparing only `strlen(key)` made the lookup a *prefix* match, and
  `"organizationIdentifier"` resolved to `ENAME_O`.
  `compare()` orders by `type()` first, then by content; `equals()`/
  `operator==` pre-checks `type()` + a precomputed `CDjb::computeAsLower()`
  hash (exposed via `hash()`) + length before an exact `memcmp`, so most
  inequalities short-circuit without touching the data at all. The copy
  constructor/assignment deep-copy `_data`/`_len`/`_hash`/`_type` verbatim
  (inlined directly rather than through `reset()`, and duplicated across the
  two rather than factored into a shared private helper, since it's only a
  few lines each) -- calling `reset()` with `other._data` here would be
  wrong, since `other._data` may already contain escape markers from a
  previous `reset()`, and `reset()`'s escaping logic can't tell that apart
  from raw input, so it would prepend a *new* backslash ahead of every
  already-escaped byte instead of just copying it as-is (a real bug this
  project hit once a `CName` with non-ASCII content got copied through a
  `CDistinguishedName`'s `std::map`, compounding with each further copy).
  Move construction/assignment swap state with the incoming value
  (unqualified `swap()` per member, which resolves to `std::swap` -- see
  `common.hpp`'s note below) rather than clearing `this` and taking
  ownership first, this project's standard move-assignment convention --
  `COctet` and `TString<T>` follow the same pattern.
- **`name.hpp` / `src/name.cpp`** also define `CDistinguishedName`, an
  ordered collection of `CName` components (`std::map<ENameType, CName>`,
  at most one component per type). `trySet()`/`tryGet()`/`has()`/`keys()`
  manage the map; `compare()` walks component types present in *either* DN
  in ascending `ENameType` order, comparing each pair the two have in
  common first (via `CName::compare()`), then breaking any remaining tie by
  which DN has an extra component the other lacks (a lower-ordinal extra
  component sorts that DN later). `toString(out, escaped)` renders
  `"key1=value1, key2=value2"` in the map's (ascending-type) iteration
  order. `tryParse(out, s)` (static, overloaded for `CString`/`CWideString`)
  parses that same `"key1=value1, key2=value2"` shape back into a fresh DN:
  it splits on top-level `,`, then each component on its first `=`, trims
  whitespace from both sides, resolves the key via `CName::typeOf()`
  (case-insensitive), and `trySet()`s the result with `overwrite=true` (so a
  repeated key keeps the last occurrence); any malformed component (no `=`,
  an empty/unrecognized key) fails the whole parse and leaves `out` empty.
  The wide overload converts each trimmed key/value through
  `TString<T>::convertTo<char>()` before doing the narrow lookup/`CName`
  construction, since `CName` only ever stores narrow (possibly-escaped)
  bytes. `out` is always reset to empty up front, before even the
  null/empty-input check, so every failure path -- not just the ones
  reached after that point -- leaves it empty.
- **`io/span.hpp`** defines `TSpan<T>` (mutable) and `TReadOnlySpan<T>`
  (read-only, implicitly constructible from a `TSpan<T>`) — non-owning
  views over contiguous memory, used throughout the library instead of a
  raw pointer+length pair. `SByteSpan`/`SReadOnlyByteSpan` alias the
  `uint8_t` instantiations (see
  [coding-conventions.md](coding-conventions.md#types) for the `T`- vs
  `S`-prefix rule this follows). Entirely templates, so it has no `.cpp`.
- **`io/array.hpp`** defines `TArray<T>`, an owning, growable array --
  `TSpan<T>`'s owning counterpart for arbitrary element types (`TString<T>`
  fills the same role specifically for character types). `EArrayType`
  tracks two orthogonal things in one `uint8_t`: a mutually-exclusive
  STATIC/DYNAMIC sub-type (`EARRAY_TYPE_MASK`, whether the array owns its
  heap allocation or -- via the static `wrap()` -- merely aliases a
  caller-supplied buffer it must never `delete[]`) and an independent
  `EARRAY_FIXED` flag (rejecting `reserve()`/`trimExcess()`/any
  `resize()`/`add()`/`insert()` that would need to grow past the current
  capacity). A non-fixed STATIC array transforms into DYNAMIC the first
  time it actually needs to grow -- whether that growth is requested
  directly via `reserve()` or indirectly via `resize()`/`add()`/`insert()`,
  since they all funnel through `reserve()` to make room; at that point it
  allocates its own buffer and stops aliasing the wrapped one, without
  freeing it, since it was never owned. `markFixed()` ORs `EARRAY_FIXED`
  into whichever sub-type is already set, a no-op on a still-`EARRAY_NONE` (freshly
  default-constructed, no elements ever added) array. Every mutating method
  (`add()`, `insert()`, `remove()`, `pop()`, `resize()`, `reserve()`,
  `trimExcess()`, `clear()`) manages element lifetimes manually via
  placement `new`/explicit `~T()` calls rather than assuming `T` is
  trivially constructible/destructible, the same manual-lifetime approach
  `COctet` and `TString<T>` take for their own element types. Entirely
  templates, so it has no `.cpp` -- like `TSpan<T>`.

  Three real bugs surfaced by writing `tests/io/array.cpp` against a
  lifetime-tracking element type (which flags a constructor/`operator=`
  call whose operand's lifetime had already ended, e.g. via a stale magic
  byte a destructor writes on its way out): `reserve()` only ever
  transitioned `EARRAY_STATIC` to `EARRAY_DYNAMIC`, and only when `_data`
  was already non-null -- so a plain default-constructed `TArray<T>()`
  (`EARRAY_NONE`) stayed stuck reporting `EARRAY_NONE` forever even after
  `add()`ing real elements, which made `empty()`/`operator bool()` (both of
  which treat `EARRAY_NONE` as empty regardless of size) permanently wrong
  for the single most common way to use this class; `insert()` shifted
  elements by move-constructing sources into place and destroying them,
  then plain-assigned (not placement-constructed) the new value into the
  vacated slot -- but that slot's object lifetime had already ended (its
  destructor ran as part of the shift, or -- for a pure append -- it was
  still the live default object `resize()` had just constructed there,
  which the fix must destroy before reusing), so the assignment (or, for
  the pure-append case, the following shift's placement-`new`) ran against
  either dead or still-live memory; and `markFixed()` masked `_type` with
  `~EARRAY_TYPE_MASK` before OR-ing in `EARRAY_FIXED`, wiping out the
  STATIC/DYNAMIC sub-type bits it should have left untouched (`EARRAY_FIXED`
  is a disjoint bit needing no such mask, unlike `reserve()`/`trimExcess()`'s
  legitimate "replace the sub-type" pattern the code had evidently been
  copied from). A fourth, unrelated bug -- an inverted `resize()`
  short-circuit (`!(_type & EARRAY_FIXED) && !reserve(size)` instead of
  `(_type & EARRAY_FIXED) || !reserve(size)`) that skipped the capacity
  check entirely for a fixed array needing to grow, letting `add()`/
  `resize()` placement-`new` past the end of `_cap` -- was caught by the
  same test suite once the other three were fixed and it could run
  cleanly.
- **`io/buffer.hpp` / `src/io/buffer.cpp`** define `CBuffer`, an owning,
  resizable raw byte buffer: `resize()`, `store()`, `toPtr()` for the raw
  pointer, and `toSpan()` to hand it on. It is the *working* buffer of the
  three byte containers here, and the distinction between them is
  load-bearing enough that
  [`coding-conventions.md`](coding-conventions.md)'s "Buffer handling"
  section legislates it: `CBuffer` is what a result is assembled in
  (resize once, `memcpy`/`memset` into it, read it back), `COctet` is what a
  finished fixed-length result is kept in, and `TArray<T>` is for sequences
  of genuinely distinct elements rather than bytes. Nearly every `encode()`/
  `build()` in the library accumulates into a `CBuffer` and converts to a
  `COctet` at the end. Two sharp edges worth knowing: `resize()` preserves
  existing content but does **not** zero the bytes it adds (unlike
  `TArray<uint8_t>`), and it returns `bool` -- a caller that ignores it and
  then writes through `toPtr()` is writing out of bounds on an allocation
  failure.
- **`utils/base64.hpp` / `src/utils/base64.cpp`** define `CBase64`, which is
  both halves of a base64 codec in one class: an incremental transform
  (`push()`/`finish()`, with an `EBase64Mode` fixing the direction --
  `EB64M_ENCODE`, `EB64M_ENCODE_BR` for PEM-style line breaking at
  `LINE_LENGTH`, `EB64M_DECODE` -- and internal `MAX_BUFFER` chunking), and
  static one-shot `encode()`/`decode()` for a whole buffer at once. The
  decoder is deliberately lenient about `=` padding and whitespace, which is
  what makes it usable on PEM blocks as they actually appear in the wild;
  `CCert::importPem()`/`exportPem()` are its main consumers. Note
  `io/base64.hpp` is **not** this: it is an empty placeholder header that
  declares nothing and that `certpp.hpp` deliberately does not include.
- **`utils/json.hpp` / `src/utils/json.cpp`** define `CJson`, a JSON value
  tree for null, booleans, numbers, strings, arrays and objects. `parseJson()`
  accepts exactly one complete JSON value; `toString()` escapes strings and
  object keys, preserves finite `double` round trips, and emits `null` for
  non-finite numbers or values beyond its depth limit. `toBson()` and
  `parseBson()` encode/decode BSON documents, including nested objects and
  arrays, booleans, strings, nulls, doubles and BSON integers (converted to
  `double`); unsupported BSON types are rejected. BSON scalar roots cannot be
  encoded. JSON is included by `certpp.hpp` unless `CERTPP_WITHOUT_JSON` is
  enabled; that option also omits `json.hpp` from installation and skips
  `tests/utils/json.cpp`.
- **`io/octet.hpp` / `src/io/octet.cpp`** define `COctet`, an owning,
  fixed-size byte buffer (not resizable/growable, unlike `TString<T>`) --
  `store()` replaces its content (copying and taking ownership; a null
  pointer or zero size is rejected and leaves prior content untouched, so a
  failed `store()` can't corrupt an existing instance), `clear()` releases
  it, and `toSpan()`/`toPtr()` give read-only access. Copy construction/
  assignment deep-copy. Move *construction* transfers ownership and leaves
  the source empty; move *assignment* swaps instead, so the source ends up
  holding whatever the target had -- the project-wide convention described
  under `io/array.hpp` below, which keeps a self-move safe and leaves the
  old buffer to be freed by the source's own destructor.
- **`io/stream.hpp` / `src/io/stream.cpp`** define `IStream`, the
  read/write/seek stream interface (capability-queried via
  `capabilities()`/`EStreamCapability`, optional operations like
  `trimExcess()`/`length(newLen)`/`flush()` default to `ERET_NOTIMPL` rather
  than being pure virtual), plus the `IStream::createMemory(...)` factory
  functions. The `.cpp` only implements the factories; the concrete
  in-memory implementation is `MemStream`, a private class under
  `src/io/` (`memstream.hpp`/`.cpp`) that is not exposed through
  `include/certpp/` (`MemStream::write()` returned 0 on every successful
  write instead of the byte count -- a real bug, since that return value is
  the only way `IStream::write()`'s contract lets a caller detect a short or
  failed write; fixed when `CWriter` started depending on it) — see
  [coding-conventions.md](coding-conventions.md#internal-implementation-headers)
  for why it lives there and how its header guard/include differ from a
  public header.
- **`net/sockaddr.hpp` / `src/net/sockaddr.cpp`** define `SSocketAddress`
  for IPv4, IPv6, and Unix-domain addresses, including numeric/hostname
  resolution. **`net/socket.hpp` / `src/net/socket.cpp`** define the owning
  `CSocket` wrapper for stream/datagram sockets; native system errors are
  translated to `ERetCode`. The module does not provide TLS or certificate
  path validation.
- **`asn1/tag.hpp` / `src/asn1/tag.cpp`** define `CTag`, an ASN.1 tag
  (class + constructed flag + tag number), with `decode()`/`encode()`
  to/from a `TReadOnlySpan<uint8_t>`/`TSpan<uint8_t>`, plus `ETagClass` and
  `EUniversalTags` for the standard tag classes/universal tag numbers.
- **`asn1/decoder.hpp` / `src/asn1/decoder.cpp`** define `CDecoder`, static
  methods for decoding ASN.1 data (`EEncodingRule` selects BER/CER/DER;
  `EDecoderStatus` reports why a decode failed), split into two layers:
  - **TLV framing** (tag-agnostic): `readEncodedValue()` reads a full
    tag-length-value, handling both definite-length values and BER/CER
    indefinite-length values (resolved by scanning nested values for the
    end-of-contents marker, bounded by a `MAX_NESTING_DEPTH` guard so a
    maliciously deep indefinite-length nesting can't exhaust the stack).
    `readNextElement()` layers a cursor on top of it to iterate a
    SEQUENCE/SET's members.
  - **Content decoding** (tag-independent, so these work whether the
    caller's tag was the plain universal one or an IMPLICIT/context-specific
    one): `decodeBoolean()`, `decodeInteger()`, `decodeEnumerated()`,
    `decodeNull()`, `decodeOctetString()`, `decodeBitString()` +
    `testNamedBit()` (NamedBitList, e.g. X.509 KeyUsage), `decodeOid()` +
    `countOidArcs()`/`decodeOidString<TChar>()` (the latter formats the arcs
    as dotted-decimal text, e.g. "1.2.840.113549.1.1.1", into a
    `TString<TChar>` -- purely ASCII digits/`.`, so it's locale-independent
    for both `TChar`s, unlike `decodeString<TChar>()`),
    `decodeText()`/`decodeString<TChar>()` (validates
    UTF8String/PrintableString/IA5String/NumericString charsets; other
    string tags pass through -- `decodeString<TChar>()` additionally
    transcodes into a `TString<TChar>` via `TUtf8Encoding<TChar>`), and
    `decodeUtcTime()`/`decodeGeneralizedTime()` (into an `SDateTime`), and
    `decodeDistinguishedName()` (into a `CDistinguishedName`, from a
    SEQUENCE's content octets -- see below for the exact structure expected).
    These take just the value's content octets (an outer `readEncodedValue()`
    call's `outArea`), not the tag+length header. `decodeOctetString()` and
    `decodeBitString()` each have a `COctet&` overload alongside their
    `SReadOnlyByteSpan&` one, copying the content into an owning `COctet`
    instead of aliasing the source buffer.

  `decodeDistinguishedName()` parses an X.501 Name/RDNSequence: each content
  element must be a SET (RelativeDistinguishedName) containing exactly one
  AttributeTypeAndValue (SEQUENCE { type OBJECT IDENTIFIER, value ANY }) --
  a multi-valued RDN is rejected outright, since `CDistinguishedName` only
  ever holds one `CName` per `ENameType`, so keeping just the first value
  and silently dropping the rest would be the wrong failure mode. `type`
  must resolve via `CName::attributeTypeOf()` -- an attribute type it can't
  name fails the whole `Name`, which is why one `organizationIdentifier`
  used to make a real EU-regulated certificate unimportable, and why
  `ENameType` had to grow rather than the decoder learn to skip (dropping an
  unnamed attribute would make two different DNs compare equal, and DN
  equality is what a future chain builder matches issuer to subject on);
  `value` must be a PrintableString, UTF8String or IA5String (the three kinds
  `CEncoder::encodeDistinguishedName()` ever writes -- see below), decoded via
  `decodeString<wchar_t>()` and converted to narrow via
  `TString<wchar_t>::convertTo<char>()` before constructing the `CName`
  (mirroring `CDistinguishedName::tryParse(CWideString)`'s same conversion
  path). Always applies DER's rules regardless of the enclosing document's
  rule set, since X.501 Names are encoded with DER in practice even inside
  a BER/CER document -- so, unlike `readEncodedValue()`, it doesn't take an
  `EEncodingRule` parameter.

  `decoder.hpp` also hosts `EEncodingRule`/`checkEncodingRule` and the
  CER-segment-limit check (`CER_MAX_SEGMENT`/`exceedsCerSegmentLimit`),
  since both the decoder and `CEncoder` need them.
- **`asn1/encoder.hpp` / `src/asn1/encoder.cpp`** define `CEncoder`, the
  write-side counterpart, mirroring `CDecoder`'s two layers:
  - **TLV framing**: `writeEncodedValue()` writes a tag-length-value using
    definite-length form (valid under all three rule sets; BER/CER's
    optional indefinite-length form is never produced), and
    `encodedValueSize()` sizes a destination buffer up front.
    `writeSequenceOf()`/`writeSetOf()` build a SEQUENCE/SET's content by
    concatenating already-encoded children; `writeSetOf()` additionally
    reorders them into CER/DER's canonical ascending order first (valid
    under BER too, so it's always applied).
  - **Content encoding**: `encodeBoolean()`, `encodeInteger()`,
    `encodeEnumerated()`, `encodeNull()`, `encodeOctetString()`,
    `encodeBitString()` + `encodeNamedBitList()` (trims trailing zero bits
    per X.690 11.2.2), `encodeOid()` + `encodedOidSize()`,
    `encodeOidString<TChar>()` + `encodedOidStringSize<TChar>()` (the
    inverse of `decodeOidString<TChar>()`: parses a dotted-decimal
    `TString<TChar>` via the private `parseOidArcs<TChar>()` helper, then
    encodes exactly like `encodeOid()`),
    `encodeText()`/`encodeString<TChar>()` (the inverse of
    `decodeText()`/`decodeString<TChar>()`, validating via `decodeText()`
    after transcoding a `TString<TChar>` to UTF-8) + `encodedStringSize<TChar>()`,
    `encodeUtcTime()`/`encodeGeneralizedTime()` (+
    `encodedGeneralizedTimeSize()`, since its length varies with whether
    there's a fractional-seconds part), and `encodeDistinguishedName()` (+
    `encodedDistinguishedNameSize()`; see below). `encodeOctetString()` and
    `encodeBitString()` each have a `const COctet&` overload too, a thin
    wrapper over the `SReadOnlyByteSpan` one via `COctet::toSpan()`. These
    always emit DER-canonical value encoding (minimal-length integers,
    `0xFF`/`0x00` booleans, ...) — a free choice for a writer, and canonical
    form is valid BER/CER too, so
    none of them take an `EEncodingRule` parameter.

  `encodeDistinguishedName()` is the inverse of `decodeDistinguishedName()`:
  one RDN (SET) per component, in the `CDistinguishedName`'s ascending
  `ENameType` order (`std::map`'s own iteration order), each containing
  exactly one AttributeTypeAndValue -- `type` from `CName::attributeOid()`,
  `value` from the component's *unescaped* text
  (`CName::toString<wchar_t>(false)`) encoded via `encodeString<wchar_t>()`
  (genuine, locale-independent UTF-8), tried first as a PrintableString and,
  only if that charset check fails, as a UTF8String instead. `ENAME_DC` is
  the one exception: RFC 4519 2.4 gives `domainComponent` IA5String as its
  syntax with no alternative, so it is written that way and fails outright
  rather than falling back. The private
  `buildAttributeTypeAndValue()`/`buildDistinguishedNameContent()` helpers
  build the full nested TLV bytes into a scratch `TArray<uint8_t>`
  bottom-up (OID TLV + value TLV -> AttributeTypeAndValue SEQUENCE TLV ->
  RDN SET TLV -> concatenated RDNSequence content); `encodedDistinguishedNameSize()`
  and `encodeDistinguishedName()` both call the same private helper (so they
  can never disagree on what gets encoded) and just differ in whether the
  result is measured or copied into the caller's destination. An empty
  (no-component) `CDistinguishedName` encodes successfully to zero content
  octets (an empty SEQUENCE) -- as with `encodedStringSize()`, a `0` return
  from the size-only helper is ambiguous between "empty" and "unencodable";
  call `encodeDistinguishedName()` directly and check its return value to
  tell them apart. Like the decoder side, always applies DER's rules and
  takes no `EEncodingRule` parameter.
- **`asn1/reader.hpp` / `src/asn1/reader.cpp`** define `CReader`, which pairs
  `CDecoder`'s content-level `decode*()` methods with stream/cursor
  management, so a caller doesn't hand-roll `readNextElement()` +
  `decode*()` for every field. Constructed from an `IStream`, it reads from
  it lazily: `growBuffer()` pulls one more chunk into an owned `COctet` only
  when a parse attempt actually runs out of buffered data, rather than
  reading the whole stream up front, so data written to the stream after
  construction (but before it's needed) is still visible. `CDecoder` still
  needs a contiguous span per attempt (and BER/CER indefinite-length parsing
  requires scanning ahead), so growth itself isn't avoidable, just its
  timing; constructed from a span directly (e.g. a parent element's already
  fully-buffered content), there's no stream to grow from, so it simply
  aliases the span. Since `growBuffer()` reallocates `COctet` (which frees
  the old allocation), a plain saved `SReadOnlyByteSpan` cursor snapshot can
  go stale mid-call -- every method that needs to roll back the cursor on
  failure goes through the private `withRollback()` helper, which tracks a
  `_generation` counter bumped on each reallocation and reconstructs the
  correct rollback target (the saved span if nothing grew, or the whole
  current buffer if it did, since `growBuffer()` always rebuilds it from
  exactly the saved span's unconsumed bytes plus newly-read ones) instead of
  trusting a potentially-dangling saved pointer. Because of this owned,
  on-demand-reallocated buffer, `CReader` is move-only (copying would leave
  the copy's cursor pointing into the source's buffer). Every typed
  `readBoolean()`/`readInteger()`/
  `readEnumerated()`/`readNull()`/`readOctetString()`/`readBitString()`
  (`SReadOnlyByteSpan` and `COctet` overloads)/`readOid()`/
  `readOidString<TChar>()`/`readText()`/`readString<TChar>()`/
  `readUtcTime()`/`readGeneralizedTime()` reads the next element expecting
  a specific plain UNIVERSAL, *primitive* tag (rejecting a constructed
  encoding too, since none of `CDecoder`'s content-level decoders
  reassemble constructed/segmented BER/CER strings) -- on any mismatch or
  decode failure, the cursor is left exactly where it was, so a caller can
  try a different read or treat an OPTIONAL/DEFAULT field as absent.
  `readDistinguishedName()` follows the same tag-mismatch-leaves-cursor-alone
  contract, but expects a *constructed* SEQUENCE (like `readSequence()`) and
  fully decodes it via `CDecoder::decodeDistinguishedName()` rather than
  returning a nested `CReader`, since a `CDistinguishedName` is a complete
  value in its own right, not something a caller iterates member-by-member.
  `readSequence()`/`readSet()`/`readConstructed()` return a nested `CReader`
  over a constructed value's content, for descending into SEQUENCE/SET (or,
  for `readConstructed()`, any other constructed tag, e.g. a
  context-specific `[n]` EXPLICIT wrapper). The low-level
  `readNextElement()` underlies all of these and is the escape hatch for
  IMPLICIT-tagged or CHOICE content the typed methods can't recognize by
  their plain universal tag.
- **`asn1/writer.hpp` / `src/asn1/writer.cpp`** define `CWriter`, the
  write-side counterpart: each typed `writeBoolean()`/`writeInteger()`/...
  method encodes its content into a scratch buffer via the matching
  `CEncoder::encode*()`, then writes the full tag-length-value to the
  stream via `writeElement()` (`CEncoder::writeEncodedValue()` under the
  hood), verifying the stream reports writing every byte. `writeSequence()`/
  `writeSet()` mirror `CEncoder::writeSequenceOf()`/`writeSetOf()` exactly
  (an array of already-encoded children) rather than introducing a new
  nested-builder API; build each child with `CEncoder` (or a nested
  `CWriter` over its own memory stream) first, exactly as the existing
  `CEncoder`-only tests already do. `writeDistinguishedName()` follows the
  same scratch-buffer-then-`writeElement()` pattern as the other typed
  writes, sizing the buffer via `CEncoder::encodedDistinguishedNameSize()`
  and filling it via `CEncoder::encodeDistinguishedName()`, then writing it
  under the SEQUENCE tag. Unlike `CReader`, `CWriter` only holds
  an `IStreamPtr` + `EEncodingRule`, so it's freely copyable.
- **`crypto/hasher.hpp`** defines `IHasher`, the interface every hash
  algorithm implements: `reset()` (back to the algorithm's initial state),
  `push(buf)` (feeds more input, streaming -- any chunking of the same total
  input produces the same digest), and `finish(out)` (writes the digest into
  a caller-supplied `SByteSpan`, failing if `out` is shorter than
  `byteWidth()`). `byteWidth()` (the digest length in bytes: 16/20/28/32/48/
  64 for MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 respectively) is set once
  via the constructor and exposed read-only, rather than being virtual, since
  it never varies per-instance for a concrete hasher. Unlike `IStream`, none
  of `IHasher`'s methods default to `ERET_NOTIMPL` -- every concrete hasher
  implements all three, so all three are pure virtual.
- **`crypto/hashers/md4.hpp`/`md5.hpp`/`sha1.hpp`/`sha224.hpp`/`sha256.hpp`/`sha384.hpp`/`sha512.hpp`**
  (and their matching `src/crypto/hashers/*.cpp`) implement `MD4`, `MD5`, `SHA1`,
  `SHA224`, `SHA256`, `SHA384`, and `SHA512` from scratch (no third-party
  dependency) -- each a concrete `IHasher`, living under the `hashers/` subdirectory
  (plural) as opposed to `crypto/hasher.hpp` (singular) which defines the
  interface itself; `crypto/asym.hpp`/`asyms/` follow the exact same
  singular-interface/plural-implementations split for asymmetric
  algorithms --
  cryptographic hash functions widely referenced by X.509 tooling (message
  digests, certificate fingerprints, `AuthorityKeyIdentifier`/
  `SubjectKeyIdentifier` computation, and legacy signature algorithms), so
  named plainly after the algorithm (`MD5`, not `CMD5`) rather than
  `C`-prefixed, matching how `asn1`'s enumerators use the standard's own
  abbreviations instead of inventing new names. MD4, MD5 and SHA-1 are
  cryptographically broken and only useful for interoperating with legacy
  certificates/fingerprints that still reference them, never for anything
  new -- MD4 most of all, which is here purely because NTLM and
  EAP-MSCHAPv2 define the NT hash as MD4 of the UTF-16LE password, with no
  alternative available to a client that must speak them. Each holds a
  private `Context` struct (running state words + an
  unprocessed-input buffer + a total-length counter) sized for its own block
  size (64 bytes for MD4/MD5/SHA-1/SHA-224/SHA-256, 128 for SHA-384/SHA-512);
  `push()` tops up a partial block from any previous call, runs the
  compression function over as many full blocks as it can consume directly
  from the caller's span, then buffers whatever's left over (less than one
  block). `finish()` runs the padding + compression on a *local copy* of the
  context (by constructing a scratch instance and overwriting its
  `Context`) rather than mutating `_ctx` in place, so it can be called more
  than once and always returns the same digest without disturbing the live
  object -- calling `push()` again afterward simply keeps extending the
  original (unfinalized) state, as if `finish()` had never been called.
  MD4 and MD5 pack message words and their 64-bit length field little-endian
  (the one place they differ from the SHA family, which is big-endian
  throughout). MD4 is MD5's direct ancestor and shares its padding and
  buffering exactly, but runs 3 rounds of 16 steps rather than 4, adds one
  constant per round (none, then `sqrt(2) * 2^30`, then `sqrt(3) * 2^30`)
  rather than one per step, uses a majority function where MD5's round 2
  uses a selection, and -- the part no formula produces -- takes its round-2
  and round-3 message-word order from fixed permutations spelled out in RFC
  1320 3.4 rather than from MD5's arithmetic `(5i + 1) % 16` family.
  SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 all pad the same way (a
  `0x80` byte, zero bytes up to the block-size-specific boundary, then the
  bit length) but with algorithm-specific block/word sizes and round counts.
  SHA-224/SHA-256 are identical except for their initial hash values and
  SHA-224's truncated (28-byte, first 7 of 8 state words) output, and
  SHA-384/SHA-512 are the same relationship one word size up (48-byte, first
  6 of 8 state words); each pair shares the one genuinely error-prone piece
  -- the round-by-round compression function -- via `Sha2_32Core::transform()`/
  `Sha2_64Core::transform()` in the private (not part of the public API)
  `src/crypto/hashers/sha2_32core.hpp`/`.cpp` and `sha2_64core.hpp`/`.cpp`
  respectively; everything else (`Context` layout, `reset()`/`push()`/
  `finish()`, padding) is duplicated between `sha224.cpp`/`sha256.cpp` (and
  separately `sha384.cpp`/`sha512.cpp`) rather than factored into a shared
  base class, since that boilerplate is short and mechanical -- only the
  part that's actually complex enough to risk skew between two copies (the
  compression function) is shared. The 128-bit SHA-384/SHA-512 length
  field's high 64 bits are always written as zero -- correct for any
  realistic input, since the low 64 bits alone can count up to 2^61 bytes
  before overflowing.

  `SHA1::transform()`/`Sha2_32Core::transform()` additionally have a
  hardware-accelerated path (x86-64 only, and only when
  `CERTPP_DISABLE_HWACCEL_SHA` isn't set): `transformAccelerated()` runs the
  same compression function via the x86 SHA Extensions (SHA1RNDS4/
  SHA1NEXTE/SHA1MSG1/SHA1MSG2 for SHA-1; SHA256RNDS2/SHA256MSG1/SHA256MSG2
  for SHA-224/SHA-256, since they share one compression function) instead of
  the portable round-by-round loop (`transformPortable()`), gated behind a
  runtime CPUID check (`hasSha()`, leaf 7 sub-leaf 0, EBX bit 29) since the
  extensions are optional even on x86-64 -- the same shape as
  `CBigNum::mul()`'s `hasAdxBmi2()`/`CGf2m::mul()`'s `hasPclmul()` gates
  above. Both are the well-known Intel-published intrinsics sequence (see
  "Intel SHA Extensions", also mirrored across OpenSSL/BoringSSL/the Linux
  kernel) rather than independently derived, given how easy a
  single-instruction transcription slip is to get subtly wrong in this kind
  of code; verified against this library's existing FIPS 180-4/RFC 3174 test
  vectors (including each algorithm's million-`'a'` multi-block stress
  vector, which exercises `transform()` across thousands of blocks), which
  on a SHA-NI-capable CPU exercise the accelerated path automatically rather
  than needing a dedicated forced-path test. MD5/SHA-384/SHA-512/SHA3-256/SHA3-512/SHAKE128/SHAKE256
  have no equivalent -- there is no mainstream x86 hardware extension for
  MD5 or Keccak, and no widely-deployed x86 SHA-512 extension the way there
  is for SHA-1/SHA-224/SHA-256, so `Sha2_64Core::transform()`/`SHAKE256`'s
  Keccak-f permutation stay portable-only.
- **`crypto/hashers/shake256.hpp` / `src/crypto/hashers/shake256.cpp`**
  implement `SHAKE256`, the 256-bit-security extendable-output function
  from the Keccak/SHA-3 family (FIPS 202) -- from scratch, like every other
  hasher. Structurally different from the MD5/SHA family: instead of a
  fixed-size compression function over a running hash state, it's a sponge
  construction (absorb input into a 1600-bit state via the Keccak-f[1600]
  permutation in 136-byte "rate" blocks, then squeeze output the same way)
  around a genuine XOF, whose output length isn't fixed by the algorithm at
  all -- so unlike every fixed-digest hasher here, `byteWidth()` is set by
  the *caller*, via the constructor argument (`SHAKE256(114)` for Ed448's
  usage, `SHAKE256()` defaulting to 32 otherwise), rather than being an
  intrinsic property of the algorithm. Verified against known-answer
  vectors generated locally via Python's `hashlib` (a mature, independent
  implementation) rather than hand-transcribed from a spec document,
  including inputs exactly at/one-below/one-above the 136-byte rate
  boundary specifically to catch off-by-one padding bugs -- which is
  exactly how an initial transposition bug in the rotation-offset table
  (rows and columns swapped from FIPS 202's own layout) was caught
  immediately, before it ever reached `Ed448`. Needed by `Ed448` (RFC
  8032), which uses `SHAKE256(x, 114)` everywhere `Ed25519` uses SHA-512.

  The Keccak-f[1600] permutation and sponge-absorption logic (`theta`/
  `rho`/`pi`/`chi`/`iota`, 24 rounds, plus the multi-rate `0x1F`/`0x80`
  domain-separated padding) are rate-independent -- i.e. identical for any
  SHAKE variant regardless of its 1600-bit-minus-2*security-level rate --
  so they live in a shared private `KeccakCore` class
  (`src/crypto/hashers/keccakcore.hpp`/`.cpp`, `STATE_BYTES=200`,
  `permute()`/`absorbBlock()`), not duplicated per algorithm. `SHAKE256`
  (RATE=136, 512-bit capacity) and `SHAKE128` (`crypto/hashers/
  shake128.hpp`/`src/crypto/hashers/shake128.cpp`, RATE=168, 256-bit
  capacity) both just drive `KeccakCore` at their own rate; `EHashers`
  gained `EHASH_SHAKE128` alongside the existing `EHASH_SHAKE256`.
  `SHAKE128` is verified the same way as `SHAKE256` -- Python `hashlib`-
  generated vectors (including rate-boundary cases at 167/168/169-byte
  inputs) plus one NIST-published vector (CSRC's `SHAKE128_Msg0.pdf`
  empty-message example, cross-checked against `hashlib.shake_128` to rule
  out a transcription error from the PDF). Not currently used by any
  signature/cipher algorithm in this library (unlike `SHAKE256`/Ed448) --
  added ahead of need, as the first step of the ML-KEM/ML-DSA groundwork
  described in [`docs/pqc-review.md`](pqc-review.md), since both FIPS
  203/204 use SHAKE128 for matrix/vector expansion.

  Both XOFs additionally expose `squeeze(const SByteSpan&)` alongside
  `finish()`: successive calls return successive chunks of the output stream,
  advancing the sponge, so output length is independent of `byteWidth()`.
  `finish()` is the fixed-length, repeatable view (it squeezes from a copy and
  leaves the cursor alone); `squeeze()` is the streaming one. They are
  alternatives rather than something to interleave. This exists because FIPS
  203's `SampleNTT` and FIPS 204's challenge/mask expansion rejection-sample
  from a SHAKE stream until enough candidates are accepted -- with no length
  knowable in advance. `MlKemSampler::sampleNtt()` consumes 453-498 bytes
  depending on the seed, which is the concrete demonstration.
- **`crypto/hashers/sha3_256.hpp`/`sha3_512.hpp` /
  `src/crypto/hashers/sha3_256.cpp`/`sha3_512.cpp`** implement SHA3-256 and
  SHA3-512 (FIPS 202 6.1). Despite the name these are not SHA-2 variants:
  SHA-3 is the same sponge as the SHAKE XOFs above, so it reuses the same
  `KeccakCore` permutation, and the buffering/padding common to both digests
  lives in a shared private `Sha3Core`
  (`src/crypto/hashers/sha3core.hpp`/`.cpp`) -- the same arrangement
  `Sha2_32Core` has between SHA-224 and SHA-256, as free functions over raw
  arrays so each public header can declare its own context without depending
  on anything under `src/`.
  SHA-3 differs from SHAKE in exactly two respects: the rate is
  `200 - 2*digestWidth` (136 bytes for SHA3-256, 72 for SHA3-512, the capacity
  being twice the output length), and the domain-separation byte is `0x06`
  rather than SHAKE's `0x1F`. That single byte is the whole difference between
  a SHA-3 digest and a SHAKE output of the same length over an identical
  sponge, which is why `tests/crypto/hashers/sha3.cpp` asserts the two
  actually differ rather than only checking digests against vectors.
  `finish()` follows the SHA-2 convention rather than the XOFs': it is a query
  that leaves the sponge untouched, so it repeats and absorption can continue
  afterwards. These were added because ML-KEM needs them as FIPS 203's `H` and
  `G` -- a prerequisite `docs/pqc-review.md`'s plan had missed, since the
  library had SHAKE but no fixed-output SHA-3 at all -- but they are ordinary
  `EHashers` members (`EHASH_SHA3_256`/`EHASH_SHA3_512`) usable anywhere.
- **`crypto/keys.hpp` / `src/crypto/keys.cpp`** define `SKeySize`/
  `SKeySizeSpec` (a `{minSize, maxSize, step}` range an `IAsymmetric`
  validates its `keySizes()` against); `IKeyBase` (`keySize()`,
  `serialize(COctet&)`, `compare()` -- common to any key, symmetric or
  asymmetric); `IPublicKey`/`IPrivateKey` (extend `IKeyBase` for the
  asymmetric case, `IStream`-style `Ptr` aliases, never constructed
  directly -- only produced by `IAsymmetric`; `IPrivateKey` adds
  `publicKey()` to derive its public half); and `SKeyPair`, a plain struct
  pairing the two (not an interface -- a key pair has no behavior beyond
  its halves). The same header also defines a third, parallel key family
  for KEMs (see `crypto/kem.hpp` below): `EKems`, `IKemKeyBase`,
  `IKemPublicKey`/`IKemPrivateKey`, and `SKemKeyPair` -- mirroring
  `EAsymmetrics`/`IAsymmetricKeyBase`/`IPublicKey`/`IPrivateKey`/`SKeyPair`
  exactly, kept as a separate family (the same reasoning `ESymmetrics`
  already uses) because a KEM key isn't a signature or DH key even though
  it's still asymmetric.
- **`crypto/kem.hpp` / `src/crypto/kem.cpp`** define `IKem`/`IKemContext`,
  the key-encapsulation counterpart of `asym.hpp`'s
  `IAsymmetric`/`IAsymmetricContext`. `IKem::builtIn()` dispatches `EKems`'
  three members -- `EKEM_MLKEM512`/`EKEM_MLKEM768`/`EKEM_MLKEM1024` -- to
  `MLKEM` (`crypto/kems/mlkem.hpp`, below). The interface was designed and
  committed ahead of any lattice-crypto implementation as the first step of
  the ML-KEM work in [`docs/pqc-review.md`](pqc-review.md), which is why it
  mirrors `IAsymmetric` as closely as it does. It deliberately isn't just `IAsymmetric` reused:
  a KEM's core operation produces an algorithm-chosen shared secret
  *together with* the ciphertext that encapsulates it, unlike
  `createEncrypter()`'s "encrypt this caller-supplied plaintext" shape, so
  forcing it onto `IAsymmetric` would mean a `transform()` call whose
  input is ignored -- a worse fit than a small sibling interface. `IKem`
  mirrors `IAsymmetric`'s shape as closely as that one difference allows:
  `builtIn(EKems)`, `keySizes()`, `generateKeyPair()`, `checkPrivateKey()`,
  `createPublicKey()`/`createPrivateKey()` (span and `COctet` overloads),
  and `createContext()`. `IKemContext` follows `IAsymmetricContext`'s
  "acts on whichever bound key, not a parameter passed in" convention:
  `encapsulate(SByteSpan& ciphertext, SByteSpan& sharedSecret)` operates on
  the bound *public* key (the peer's, bound via the two-key `keyPair(pub,
  nullptr)` overload -- the caller is encapsulating *to* that peer);
  `decapsulate(SReadOnlyByteSpan ciphertext, SByteSpan& sharedSecret)`
  operates on the bound *private* key. `sizeOfCiphertext()`/
  `sizeOfSharedSecret()` follow the existing getter-public/setter-protected
  split `sizeOfSign()`/`sizeOfDigest()` use.
- **`crypto/kems/mlkem.hpp` / `src/crypto/kems/mlkem.cpp`** implement ML-KEM
  (FIPS 203) and the K-PKE scheme underneath it, over raw byte spans. This is
  the algorithm itself, with no opinion about key objects or contexts, so it
  can be driven straight from a test vector; the `IKem`/`IKemContext` shape
  above is what most callers should prefer once it is wired up, and sits on
  top of this. The header publishes four types:
  - `SMlKemPoly`, one element of R_q = Z_q[X]/(X^256+1) as 256 `int16_t`
    coefficients, carrying `COEFFICIENTS`/`MODULUS`/`ROOT_OF_UNITY`. The same
    layout also holds NTT-domain values, which are 128 degree-1 blocks rather
    than a polynomial; FIPS 203 doesn't distinguish the two in its data types
    either, so which one an instance holds is the caller's to track.
  - `SMlKemParams`, one of FIPS 203 Table 2's three parameter sets as
    `{k, eta1, eta2, du, dv}` plus `mlKem512()`/`mlKem768()`/`mlKem1024()`.
    Only those five figures are stored; `ekBytes()`/`dkBytes()`/
    `dkPkeBytes()`/`ciphertextBytes()`/`sharedSecretBytes()`/`seedBytes()`
    all derive from them, and `tests/crypto/kems/kat_mlkem.cpp` pins the derived
    results against the published table with `static_assert`. A mistyped key
    length is exactly the error that stays internally consistent -- an
    implementation using the wrong `ek` length throughout still round-trips
    with itself -- so the sizes are made impossible to write down wrongly.
    `isValid()` reports whether the set is one of the three, and `equals()`
    compares two; every `CMlKem` entry point calls `isValid()` first and
    refuses otherwise. That is a memory-safety requirement rather than
    pedantry: `SMlKemParams` is public, so a caller can hand over a
    hand-built set, while the implementation sizes its fixed-capacity buffers
    from `MAX_K` and `maxCiphertextBytes()`.
  - `CMlKemSampler`, FIPS 203's two samplers: `sampleNtt()` (Algorithm 7,
    rejection-sampling a uniform NTT-domain polynomial from a SHAKE128
    stream) and `samplePolyCbd()` (Algorithm 8, turning PRF output into the
    small-coefficient noise Module-LWE needs). `sampleNtt()` appends its two
    index bytes in the order given, because FIPS 203's matrix expansion calls
    it as `SampleNTT(rho || j || i)` -- transposed relative to the natural
    loop order, which the standard's own margin note flags.
  - `CMlKem`, the scheme: `generateKeyPair()`/`encapsulate()`/
    `decapsulate()` (Algorithms 16-18), `checkEncapsulationKey()`/
    `checkDecapsulationKey()` (the FIPS 203 6.2 input checks), and
    `kpkeKeyGen()`/`kpkeEncrypt()`/`kpkeDecrypt()` (Algorithms 13-15).
    `encapsulate()` takes the 32-byte message explicitly rather than drawing
    it, so it is reproducible from a vector -- which means a caller outside
    the tests must pass fresh CSPRNG output, since reusing a message reuses
    the shared secret.

  The subtlety is all in `decapsulate()`. ML-KEM is the Fujisaki-Okamoto
  transform over K-PKE, which is what lifts an IND-CPA scheme to IND-CCA2:
  it re-encrypts what it decrypted and compares against the ciphertext it was
  given, and on a mismatch returns `J(z || ciphertext)` -- a secret derived
  from the private key's own rejection seed -- rather than an error. A
  malformed ciphertext therefore yields a well-formed but unrelated shared
  secret, and the caller cannot tell the two cases apart. Reporting failure
  there, or skipping the re-encryption, would hand back exactly the
  decryption oracle the transform exists to deny. That is why `decapsulate()`
  has no failure mode for a bad ciphertext at all, only for a
  structurally wrong-sized one.

  "Cannot tell the two cases apart" has to hold for timing too, so the
  comparison is `CSecure::equalsMask` and the choice between the two secrets
  is `CSecure::select` -- a `std::memcmp` would leak how long a prefix of
  the re-encryption matched, and a ternary on the verdict would leak the one
  bit that verdict is. The function has a single exit so that
  `CSecure::zero` cannot be skipped by an error path, which is FIPS 203's
  requirement that the reject flag be destroyed before returning.

  Validated against NIST's ACVP vectors for all three parameter sets,
  including the `modified ciphertext` cases that exercise that rejection path
  and the `encapsulationKeyCheck`/`decapsulationKeyCheck` negative cases --
  see `tests/crypto/kems/kat_mlkem.cpp`. FIPS 203 publishes no worked examples, so
  those vectors are the only external oracle available.

  The same header then declares **`MLKEM`**,
  `IKem`'s only implementation, serving all three ML-KEM parameter sets from
  one class with the set as constructor state -- the arrangement `CEcdsa` has
  across its curves. It implements nothing cryptographic itself: `CMlKem`
  above is the algorithm, and this is the key objects, the size bookkeeping
  `IKemContext` exposes, and the CSPRNG draws around it.

  `keySizes()` accepts exactly one size per instance, and that size is the
  parameter set's own number (512, 768 or 1024) rather than a modulus width
  or a claimed security strength. ML-KEM has no size that scales -- the sets
  differ in the module rank `k` and four other parameters, and those three
  numbers are names. Passing the name keeps `generateKeyPair()` usable the
  way every other algorithm in the library is, without inventing a figure
  that looks like it means something it doesn't.

  Keys serialize as FIPS 203's own encodings and nothing more: a public key
  is the encapsulation key, a private key the decapsulation key. Since a
  decapsulation key embeds its own encapsulation key at offset
  `dkPkeBytes()`, `IKemPrivateKey::publicKey()` reads it out rather than
  recomputing it, and `checkPrivateKey()` verifies the two agree (plus the
  embedded `H(ek)`, plus that the `ek` is canonical) rather than assuming
  so. `createPublicKey()`/`createPrivateKey()` apply the same checks, since
  a key reaching them came from outside. The SubjectPublicKeyInfo wrapping a
  certificate needs is Phase 6 of [`docs/pqc-review.md`](pqc-review.md), not
  here.

  This is also the only layer in the ML-KEM implementation that draws
  randomness. `CMlKem::generateKeyPair()`/`encapsulate()` take their seeds
  and message as parameters so they can be driven from a test vector;
  `IKemContext::encapsulate()` has no such parameter, so `MLKEM` fills them
  from `CRng` -- which also means there is no known-answer test to be had at
  this layer, and `tests/crypto/kems/mlkem.cpp` covers what the wrapper adds
  rather than the algorithm (asserting, among other things, that repeated
  `encapsulate()` calls against one key differ, since a shared secret that
  was a function of the key alone would be reused every session).
- **`src/crypto/kems/mlkemring.hpp`/`.cpp`, `src/crypto/kems/mlkemcodec.hpp`/
  `.cpp`** hold the arithmetic and wire encoding `CMlKem` is built from:
  `MlKemRing` (NTT, inverse NTT, base-case multiply over R_q, plus a
  schoolbook negacyclic multiply that exists only to check the others) and
  `MlKemCodec` (ByteEncode/ByteDecode, Compress/Decompress, `isCanonical12`).
  Both stay private to `src/` -- plain `PascalCase`, no `CERTPP_API` -- since
  nothing outside the ML-KEM implementation has a reason to reach them, and
  `SMlKemPoly` is the one type they share with the public header. Because
  they aren't exported, a test under `tests/crypto/kems/` compiles them into
  its own executable; see [`docs/build.md`](build.md).
- **`src/crypto/asyms/mldsaring.hpp`/`.cpp`** define `MlDsaRing`, arithmetic in
  ML-DSA's ring R_q = Z_q[X]/(X^256 + 1) with q = 8380417 (FIPS 204 4) --
  the first piece of ML-DSA, and also private to `src/`. It is deliberately
  a separate unit from `MlKemRing` rather than a parameterization of it,
  because three differences go deeper than the constants:
  - q = 2^23 - 2^13 + 1, so a coefficient needs 23 bits and `int32_t`
    storage, and a product of two coefficients reaches about 7.0e13 --
    which overflows `int32_t` by four orders of magnitude, so every
    intermediate runs in `int64_t`. In ML-KEM's ring the same product fits
    in `int32_t` with room to spare; carrying that habit across would be a
    silent-wraparound bug. It bites the twiddle-table builder too, where
    `ZETA * acc` reaches about 1.5e10.
  - `ZETA = 1753` has order exactly **512**, not 256, so X^256 + 1 splits
    all the way into 256 linear factors and the NTT is **complete**: eight
    layers, 256 independent evaluation points. ML-KEM's transform stops one
    layer short, leaving 128 degree-1 blocks that need a base-case multiply
    and a second twiddle table. So `multiplyNtt()` here is plain pointwise
    multiplication, and there is no `gammas()` at all.
  - The index permutation is `bitRev8`, over eight bits, against ML-KEM's
    `bitRev7`.

  Beyond the transform it provides `centered()` -- FIPS 204's `mod±`,
  the representative in (-q/2, q/2] -- and `infinityNorm()`, which ML-DSA's
  signing loop rejects on, so it belongs to the ring rather than to a
  caller. Nothing is kept in Montgomery form; FIPS 204 Appendix A warns that
  implementations usually store the zetas array that way, which makes a
  representation mismatch there exactly the self-consistent-but-wrong
  failure mode this library has been bitten by before, so
  `tests/crypto/asyms/mldsaring.cpp` checks the table against Appendix B's
  printed values as well as against its defining property.
- **`src/crypto/asyms/mldsarounding.hpp`/`.cpp`** define `MlDsaRounding`,
  FIPS 204 7.4's rounding and hint machinery: `power2Round`, `decompose`,
  `highBits`/`lowBits`, `makeHint` and `useHint`, scalar and per-polynomial.
  Also private to `src/`.

  The hint mechanism is why this exists. A signature carries one bit per
  coefficient rather than w1 itself, and the verifier reconstructs
  `HighBits(w - c*s2 + c*t0)` from its own approximation plus those bits --
  which works only if `useHint()` inverts `makeHint()` exactly, and only
  while the perturbation stays within gamma2, a bound the signing loop is
  responsible for enforcing. The test checks that identity over random pairs
  and, separately, at the bucket boundaries and across the carve-out band,
  where random sampling would essentially never land.

  Two traps are documented in the header rather than left to be
  rediscovered:
  - **`decompose()`'s `(q-1)` carve-out is a band, not a point.** Algorithm
    36 branches on `r+ - r0 == q - 1`, which reads like "the single value
    r == q-1" and is not: the condition holds across the whole top band of
    width gamma2 -- 95232 values (1.14% of q) at gamma2 = (q-1)/88, 261888
    (3.1%) at (q-1)/32. The obvious simplification to a point comparison is
    wrong for 95231 inputs in the first case, and only an external vector
    would catch it.
  - **`mod±` here is not `MlDsaRing::centered()`.** That reduces modulo q,
    which is odd, so its split sits at (q-1)/2; these reduce modulo 2^d and
    2*gamma2, both even, where the range is (-m/2, m/2] and m/2 itself stays
    positive. Same definition, different modulus, different edge -- hence a
    separate `modPm()`.
- **`src/crypto/asyms/mldsacodec.hpp`/`.cpp`** define `MlDsaCodec`, FIPS 204
  7.1-7.2's bit packing and hint encoding -- the wire format ML-DSA's keys and
  signatures are built from. `simpleBitPack`/`simpleBitUnpack` handle
  coefficients in [0, b]; `bitPack`/`bitUnpack` handle [-a, b] by encoding
  `b - w_i`, so a signed range fits an unsigned field. Bits run little-endian
  within each byte, as in ML-KEM.

  **Decoding does not imply the range**, and FIPS 204 says so itself under
  Algorithm 17: for some (a, b) there are byte strings that decode outside the
  nominal range, which matters for untrusted input. It turns on whether the
  range exactly fills its bit width, and for ML-DSA's uses it splits cleanly --
  `t1`, `t0` and `z` are safe; `s1`/`s2` are not (at eta = 2 three bits decode
  down to -5, at eta = 4 four bits reach -11), so `skDecode` has to
  range-check; and `w1` is unsafe at b = 43 but is only ever encoded, never
  received. `inRange()` exists for the cases that need it. This is the same
  shape of hazard as ML-KEM's `ByteDecode_12`.

  `hintBitUnpack()` is the sharpest decode trap in the standard, and rejects
  on three *distinct* conditions: a cumulative index that moves backwards or
  past omega; positions not strictly increasing **within one polynomial**; and
  any non-zero leftover byte. Each one is what makes the encoding injective,
  and implementing fewer than all three accepts malleable signatures -- which
  is what ACVP's 36 "modified signature - hint" cases test. The
  within-one-polynomial scope matters in both directions: positions
  legitimately *decrease* across a polynomial boundary, so checking
  monotonicity over the whole array instead rejects valid signatures. A
  rejected decode leaves the caller's polynomials untouched rather than
  half-written.
- **`src/crypto/asyms/mldsasampler.hpp`/`.cpp`** define `MlDsaSampler`, FIPS
  204 7.3's pseudorandom sampling: `sampleInBall`, `rejNttPoly`,
  `rejBoundedPoly` and the `expandA`/`expandS`/`expandMask` procedures over
  them. All three samplers consume a seed-dependent amount of stream, so they
  read through `squeeze()` rather than `finish()` -- which is why incremental
  squeezing was a hard prerequisite rather than a convenience.

  Two things here are easy to get wrong and invisible without an external
  vector. The XOFs are not interchangeable: `rejNttPoly`/`expandA` use
  SHAKE128 (the standard's `G`), everything else SHAKE256 (`H`). And
  **`expandA`'s seed is transposed** -- `rho || s || r` for entry `A[r][s]`,
  the column byte before the row byte, exactly as ML-KEM's
  `SampleNTT(rho || j || i)` is. Both produce a scheme that is perfectly
  self-consistent and interoperates with nothing.
- **`src/crypto/asyms/mldsaparams.hpp`** defines `MlDsaParams`, FIPS 204
  Table 1's three parameter sets with every length derived from them rather
  than written out, and `static_assert`ed against Table 2 by
  `tests/crypto/asyms/mldsaparams.cpp`. Two of its values do not behave the way
  a reader expects: **eta is not monotone** across the sets (2, 4, 2 for
  ML-DSA-44/65/87), and **gamma1 is shared** by ML-DSA-65 and -87, so neither
  can be used to tell a set apart.
- **`src/crypto/asyms/mldsascheme.hpp`/`.cpp`** define `MlDsaScheme`, ML-DSA
  itself over raw byte spans: FIPS 204 7.2's key and signature encoders
  (`pkEncode`/`pkDecode`, `skEncode`/`skDecode`, `sigEncode`/`sigDecode`,
  `w1Encode`), and KeyGen/Sign/Verify in both the internal
  (Algorithms 6-8) and external (Algorithms 2-3) forms. It takes xi and rnd as
  parameters rather than drawing them, which is what lets it be driven straight
  from a test vector.

  It stays private to `src/`, unlike ML-KEM's `CMlKem`, because every entry
  point is parameterized by `MlDsaParams` -- exporting the signatures would
  mean either moving that already-tested private header into the public API or
  duplicating it, and the surface a caller actually needs is
  `IAsymmetric`-shaped anyway.

  **There are two message conventions and they are not interchangeable.** The
  internal interface signs `M'` verbatim. The external one prepends
  `IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx` first, and that is
  what RFC 9881's `id-ml-dsa-*` OIDs mean -- so an X.509 signature covers
  `0x00 || 0x00 || tbsCertificate`, not the TBS bytes alone. Signing the raw
  message instead round-trips perfectly against itself and rejects every
  genuine certificate; `tests/crypto/asyms/kat_mldsa.cpp` asserts the two
  interfaces disagree, each rejecting the other's signature, so the distinction
  cannot quietly collapse.

  `sign()`/`verify()` compute mu themselves and hand it to the internal form as
  its `externalMu`, rather than concatenating the prefix and the message into
  one buffer. The results are bit-identical, because mu is `H(tr || M')` and
  `H` absorbs its parts in order, but the message is never copied -- which
  matters when it is a document rather than a 3 KiB TBSCertificate. `tr` sits
  at a fixed offset in the private key, so reading it costs nothing. The same
  `externalMu` parameter covers ACVP's `externalMu: true` groups.

  `skDecode` **range-checks s1/s2**, which is not optional: `2*eta + 1` is 5 or
  9, neither a power of two, so the field encodes values the range does not
  contain (down to -5 at eta = 2, -11 at eta = 4). FIPS 204 Algorithm 25
  rejects such a key, and so does every entry point that decodes one -- a
  private key from storage or from a peer is untrusted input, and signing with
  an out-of-range s1 lands outside the scheme's security argument while still
  verifying against the matching public key.

  Signing is a **rejection loop with aborts**: each iteration draws a fresh
  masking vector and discards the whole attempt if any of four bounds fails, so
  the iteration count depends on the key and the message. There is no
  constant-time story to tell, and FIPS 204 offers none; see
  [`docs/pqc-review.md`](pqc-review.md). The working set is heap-allocated
  (`TArray<Poly>`) rather than on the stack because ML-DSA-87's is large --
  A-hat alone is 8x7 polynomials, 56 KiB, with a dozen more vectors alongside
  it.

  Only the pure variant is implemented. HashML-DSA has its own separate
  `id-hash-ml-dsa-*` OIDs, appears in no certificate this library is meant to
  read, and would drag in a hash-OID table for no present caller.
- **`crypto/asyms/mldsa.hpp` / `src/crypto/asyms/mldsa.cpp`** define `CMlDsa`,
  ML-DSA as an `IAsymmetric`, one instance per parameter set -- the same
  arrangement `CEcdsa` has across its curves, reached as
  `IAsymmetric::builtIn(EASYM_MLDSA44 | EASYM_MLDSA65 | EASYM_MLDSA87)`.
  Sign/verify only; `createEncrypter()`/`createDecrypter()` and
  `deriveSharedSecret()` all report `ERET_NOTSUP`.

  **`sign()`/`verify()`'s `digest` parameter is the message, not a hash of
  it.** ML-DSA has no externally supplied digest -- it hashes the message
  internally, twice with different domain separation, and signs a lattice
  commitment rather than a fixed-width digest. Passing a pre-computed SHA-256
  value would produce a valid ML-DSA signature *over that 32-byte string*, one
  no other implementation would generate or check. Ed25519/Ed448 read the
  parameter the same way for the same reason, and `CDnssecKeys::hasherOf()`
  states the same fact from the other side. The signal to a caller is
  `sizeOfDigest()`, which stays 0 for a bound ML-DSA key: zero means "there is
  no digest to compute, pass the message". The parameter keeps its interface
  name, since renaming it per implementation would obscure the override
  relationship rather than clarify it.

  `keySizes()` accepts the parameter set's own number (44, 65 or 87) rather
  than a modulus width or a security strength, exactly as `MLKEM` does with
  512/768/1024 -- ML-DSA has no size that can be scaled, and those numbers are
  names. Keys serialize as FIPS 204's own encodings and nothing more, which is
  also exactly what a `SubjectPublicKeyInfo` BIT STRING carries for these OIDs
  (RFC 9881 puts the raw public key there, no inner `OCTET STRING`, with
  `parameters` absent), so `CCert` needs no reshaping step the way DSA's split
  `Dss-Parms` does. A private key does not embed its public key, so
  `IPrivateKey::publicKey()` re-derives it from the key's own rho/s1/s2 and
  checks the result against the stored `tr` (which is `H(pk)`) -- the one
  internal-consistency test an ML-DSA private key admits.

  This is also where randomness enters, and the only place it does. Signing is
  **hedged**: a fresh 32-byte rnd per signature, FIPS 204's recommended
  default, so two signatures over the same message differ and a known-answer
  test has to go through `MlDsaScheme` with rnd = 0 instead. That is not a test
  contrivance -- deterministic signing is the standard's own variant, and it is
  what ACVP's `deterministic: true` groups use.

  Validated against NIST's ACVP vectors for all three parameter sets:
  `tests/crypto/asyms/kat_mldsa.cpp` (keyGen and sigGen, deterministic and
  hedged, internal and external), `tests/crypto/asyms/kat_mldsaver.cpp`
  (sigVer, including all four negative reasons -- modified message, commitment,
  hint and z), and `tests/crypto/asyms/mldsa.cpp` for the wrapper. The
  acceptance test is `tests/x509/realcerts.cpp`, where the real IdenTrust
  ML-DSA-87 pilot root verifies its own signature.
- **`crypto/hmac.hpp` / `src/crypto/hmac.cpp`** define `CHmac`, RFC 2104 over
  any fixed-output hasher here, with `IHasher`'s streaming shape plus a
  one-shot `compute()` and a constant-time `verify()`. Not an `IHasher`: HMAC
  is keyed, and `IHasher::create()` has nowhere to put a key. Re-keying an
  instance reuses the underlying hasher, so HKDF's expand loop does not
  allocate per block. The RFC 2104 block sizes live here rather than on
  `IHasher` (which exposes only `byteWidth()`), because putting them on the
  interface would mean changing its constructor and all of its implementations;
  the trade is that a hasher added later is unsupported until
  `blockBytesOf()` is extended, which fails loudly at `reset()` rather than
  computing a wrong tag. SHAKE is refused -- RFC 2104 is defined over a
  fixed-output hash. BLAKE2s's entry there is 64 bytes, the same block SHA-256
  uses; HMAC over BLAKE2s is well defined and distinct from BLAKE2's own keyed
  mode (`CBlake2sMac`).
- **`crypto/hashers/blake2s.hpp` / `src/crypto/hashers/blake2s.cpp`** define
  `BLAKE2s`, RFC 7693, as `EHASH_BLAKE2S`. Added for WireGuard's handshake
  (its `HASH()`, `MAC()` and HKDF all use it) but an ordinary member of the
  `EHashers` family. It is little-endian throughout where the SHA-2 family is
  big-endian, and a HAIFA rather than Merkle-Damgard construction: no
  length-padding block, the byte counter and a finalization flag go straight
  into the last compression, so a block is held back until a later byte proves
  it is not the last. The digest length (1-32) is bound into the parameter
  block, which makes `BLAKE2s(16)` a different function from the leading 16
  bytes of `BLAKE2s(32)` -- the constructor folds an out-of-range length onto
  32 rather than producing an instance the parameter block cannot describe.
  The state machine lives in `src/crypto/hashers/blake2score.hpp`
  (`Blake2sCore`) and is shared with `CBlake2sMac`, following `Sha3Core`'s
  pattern of free-standing operations over raw arrays so each public class
  declares its own context in its own header.
- **`crypto/blake2smac.hpp` / `src/crypto/blake2smac.cpp`** define
  `CBlake2sMac`, BLAKE2's *native* keyed mode (RFC 7693 2.9/3.3), which is
  what WireGuard's `MAC()` is. The key is one zero-padded first block and its
  length is in the parameter block; there is no ipad/opad and no second pass.
  This is **not** HMAC-BLAKE2s, which is `CHmac` with `EHASH_BLAKE2S` and is
  what WireGuard's HKDF uses -- the two produce different tags from the same
  inputs, so confusing them fails interoperability silently. It is a separate
  class rather than a keyed `reset()` on `BLAKE2s` because `IHasher::reset()`
  takes no arguments: a keyed hasher would either lose its key on a
  polymorphic reset or masquerade as a plain hash behind an `IHasherPtr`, the
  same reasoning that keeps `CPoly1305` out of the hasher hierarchy. Unlike
  `CPoly1305` the key is reusable across messages, and `finish()` is a
  repeatable query.
- **`crypto/hkdf.hpp` / `src/crypto/hkdf.cpp`** define `CHkdf`, RFC 5869's
  extract-then-expand KDF, as `extract()`/`expand()`/`derive()`. A concrete
  utility rather than one implementation of an `IKdf` family, following
  `CRng`'s precedent: HKDF's two-step shape does not generalize to a
  password-based KDF without an interface that fits neither well. `CPbkdf2`
  has since arrived and the interface still has not, because the prediction
  held -- the two share only "a static `derive()` taking spans", which is a
  shape and not an abstraction.
- **`crypto/pbkdf2.hpp` / `src/crypto/pbkdf2.cpp`** define `CPbkdf2`, RFC 8018
  section 5.2's iterated password-based KDF, as a single `derive()` plus
  `maxDeriveBytes()`. It sits beside `CHkdf` rather than inside the one caller
  that needed it (`CPfxFormat`) because a password KDF is a general-purpose
  primitive, and the two are emphatically **not** interchangeable: HKDF is
  built to be cheap because its input already has full entropy, and that is
  exactly what makes it useless over a password. The implementation notes worth
  carrying: `T(i)` is the XOR of *every* `U(j)`, not the last one (dropping the
  XOR costs the same to compute and matches nothing, which is why RFC 6070's
  vectors are the only cheap way to catch it); only `U(1)` sees the salt;
  `INT(i)` is four big-endian bytes from 1, which only shows up once the output
  runs past one digest; an iteration count of 0 is `ERET_BADREQ` rather than
  "no stretching", since a zeroed count parsed out of a container must not
  become a free derivation; and the output is bounded at `(2^32 - 1) * hLen`
  because past that the counter wraps and the keystream repeats.
  `tests/crypto/pbkdf2.cpp` checks it against RFC 6070's HMAC-SHA1 vectors and
  RFC 7914 section 11's HMAC-SHA256 ones, and explains why the 16777216-
  iteration case is left out.
- **`crypto/poly1305.hpp` / `src/crypto/poly1305.cpp`** define `CPoly1305`,
  RFC 8439 2.5's one-time authenticator. `finish()` *consumes* the state
  rather than being a repeatable query like `IHasher::finish()`, because
  Poly1305 is one-time by construction -- two messages under one key let an
  attacker solve for `r` and forge at will -- so leaving the instance usable
  would invite the misuse that breaks it. It deliberately shares no interface
  with `CHmac`: HMAC is keyed and reusable, this is neither, and letting them
  be swapped would make that difference invisible at the call site.
  `padToBlock()` is a named operation because RFC 8439 2.8's `pad16` closes a
  partial block rather than extending the message, which pushing zeros cannot
  express.
- **`crypto/siphash.hpp` / `src/crypto/siphash.cpp`** define `CSipHash`,
  SipHash-2-4 (Aumasson and Bernstein), the keyed 128-bit-key/64-bit-output
  PRF RFC 9018 2.2 specifies for DNS server cookies. It takes `CPoly1305`'s
  shape -- `reset(key)`/`push()`/`finish(out)` plus a one-shot `compute()` --
  but deliberately *not* its lifecycle: SipHash is a reusable PRF, so
  `reset()` may be called any number of times, there is a no-argument
  `reset()` that restarts a message under the key already installed, and
  `finish()` is a repeatable query (finalizing a copy of the state, as
  `IHasher::finish()` does) rather than consuming the key. That difference is
  the security model of each primitive showing through, and the doc comment on
  each class says so, since the two classes otherwise look interchangeable.
  It is not an `IHasher` either: `IHasher` is unkeyed with 16-byte-and-up
  digests, this is keyed with an 8-byte output, and 64 bits is far too short
  to resist a collision search -- putting it behind `IHasher` would invite
  exactly the use it cannot support. The padding is the subtle part: there is
  always a final block, even for an empty or block-aligned message, and it
  carries the message length mod 256 in its top byte instead of any `0x80`
  marker or bit count, so an implementation that merely zero-pads the short
  block is self-consistent and gives any message and its zero-extension the
  same output -- the empty message and a single `0x00` byte being the
  smallest such pair, which is what the test for it uses.
- **`crypto/aeads/chacha20poly1305.hpp` /
  `src/crypto/aeads/chacha20poly1305.cpp`** define `CChaCha20Poly1305`, RFC
  8439 2.8. One instance is a keyed context -- construct per key, call
  `seal()`/`open()` per record with only the nonce changing -- and neither
  operation allocates. `out` may alias `in`, which is what lets a receiver
  decrypt a record where it already sits.

  `open()` verifies the tag *before* writing any plaintext. The tag covers the
  ciphertext, so it can be checked while the input is intact -- and because
  `out` may alias `in`, a decrypt-then-verify order would overwrite the
  caller's only copy of the ciphertext with unauthenticated plaintext before
  noticing the forgery. The comparison goes through `CSecure::equalsMask`, not
  `memcmp`.
- **`crypto/aeads/xchacha20poly1305.hpp` /
  `src/crypto/aeads/xchacha20poly1305.cpp`** define `CXChaCha20Poly1305`,
  draft-irtf-cfrg-xchacha's extended-nonce variant -- the one WireGuard and
  libsodium use. It is a thin wrapper rather than a second AEAD:
  `subkey = HChaCha20(key, nonce[0:16])`, then `CChaCha20Poly1305` under that
  subkey with the 96-bit nonce `00000000 || nonce[16:24]`. The API and every
  contract (in-place operation, no per-call allocation, constant-time
  verify-before-write) are `CChaCha20Poly1305`'s, inherited by delegation
  rather than restated.

  The 192-bit nonce is the whole point: 96 bits is too short to pick at
  random, since a birthday collision becomes likely after roughly 2^48 records
  under one key, so RFC 8439 effectively requires a counter -- and a counter
  requires state that survives restarts and is not shared between senders. At
  192 bits random nonces are safe for any realistic record count, so a key can
  be used by parties that cannot coordinate a counter at all. The cost is one
  extra ChaCha20 permutation per record.

  Nothing can be cached across calls, because the subkey depends on the nonce.
  The per-record subkey and inner nonce therefore live in a stack struct
  (`Inner` in the `.cpp`) that keys a stack `CChaCha20Poly1305` and zeroes the
  subkey in its destructor, which keeps the no-allocation contract without a
  `mutable` member or a non-const `seal()`.
- **`crypto/aeads/aesgcm.hpp` / `src/crypto/aeads/aesgcm.cpp`** define
  `CAesGcm`, NIST SP 800-38D, with AES-128/192/256 and a 96-bit IV. It matches
  `CChaCha20Poly1305`'s shape deliberately -- a keyed context, `seal()`/`open()`
  per record, no per-call allocation, `out` may alias `in`, and `open()` verifies
  before writing a plaintext byte -- because the same consumer (IKEv2) picks one
  or the other by negotiation and should not have to restructure around the
  choice. The differences are the ones the algorithms force: the tag may be
  truncated (SP 800-38D 5.2.1.2 permits 128/120/112/104 or 96 bits, which is
  every byte length from `MIN_TAG_BYTES` to `TAG_BYTES`, and nothing shorter),
  and the key may be any of three lengths rather than one.

  **Only a 96-bit IV is accepted.** SP 800-38D allows any length, but anything
  else derives the initial counter block by running the IV through GHASH instead
  of using it directly -- a second code path with its own ways to be subtly
  wrong, and no caller needs it: IKEv2 (RFC 4106/5282), TLS and SSH all use
  exactly 96 bits, which is also what SP 800-38D 8.2 recommends.

  `deriveSubkey()` exposes `H = E_K(0^128)` for the same reason
  `CChaCha20Poly1305::deriveOneTimeKey()` exists: the GCM specification
  publishes `H` per test case, and it is the one intermediate value that
  separates "the key schedule is wrong" from "the hash is wrong".
- **`src/crypto/aeads/ghash.hpp`/`.cpp`** define `Ghash`, GHASH (SP 800-38D 6.4)
  and GCM's `GF(2^128)` multiplication. It is **not** built on `CGf2m`, whose
  PCLMULQDQ-accelerated multiply would otherwise look like the obvious reuse,
  for three independent reasons:

  - GCM's field is **bit-reflected**: the most significant bit of a block's
    first byte is the `x^0` coefficient (SP 800-38D 6.3), the opposite of the
    polynomial-basis convention `CGf2m` and the rest of the library use. Handing
    `CGf2m` the bytes as they arrive yields a product that is self-consistent in
    every algebraic respect and is not GHASH -- the classic way to get this
    wrong, and one only a published vector catches.
  - `H` is **secret**, so the multiply must be constant-time; `CGf2m` documents
    that it has none, which is the right trade for ECDSA's public curve
    arithmetic and the wrong one for a MAC key.
  - `CGf2m` is sized for other fields: 9 limbs and a generic pentanomial
    reduction over an 18-limb product, where GHASH is two 64-bit words with one
    fixed modulus, once per 16 bytes of message.

  The portable multiply is SP 800-38D's own Algorithm 1 with every branch
  replaced by a mask, and no table -- the key-dependent indices of the usual
  windowed GHASH are what leak `H` through the cache. The accelerated path
  (PCLMULQDQ, behind `CERTPP_DISABLE_HWACCEL_SIMD` and a runtime CPUID check,
  exactly as `CGf2m`'s is) does **not** multiply in the reflected convention:
  it converts both operands into the ordinary one with a dozen SSE2
  instructions, where the reduction is the textbook `x^128 = x^7 + x^2 + x + 1`,
  rather than carrying the shift-by-one-plus-mirrored-constants trick whose
  correctness cannot be eyeballed.

  Published vectors cannot tell the two paths apart -- whichever one this CPU
  takes is the only one they ever reach -- so `tests/crypto/aeads/ghash.cpp`
  compares them directly over thousands of random and structured operands, and
  checks the field identities that pin the bit order down (the multiplicative
  identity is the block `80 00 ... 00`, not `00 ... 00 01`). `Ghash` has no
  public header and no `CERTPP_API`, so that test compiles `ghash.cpp` into
  itself via `CERTPP_TEST_PRIVATE_SOURCES`.
- **`src/crypto/syms/aescore.hpp`/`.cpp`** define `AesCore`, AES's key schedule
  and single-block encrypt/decrypt (with the AES-NI path behind
  `CERTPP_DISABLE_HWACCEL_AES`), extracted from `aes.cpp` so GCM can share it --
  the arrangement `DesCore` and `ChaCha20Core` already have. GCM is not a mode
  `ISymmetricContext` can express: it needs the raw forward block function at
  arbitrary counter blocks *and* at the all-zero block (for `H`), and never uses
  the inverse cipher at all.
- **`src/crypto/syms/chacha20core.hpp`/`.cpp`** define `ChaCha20Core`, the
  block function, extracted from the stream cipher so the AEAD can share it --
  the arrangement `DesCore` and `KeccakCore` already have. The AEAD needs it at
  two counters `ISymmetric` cannot express: 0 for the Poly1305 key derivation,
  and 1 onward for the payload.
  `xorStream()` carries the four-block SSE2 keystream path (`xorStream4()`,
  behind `CERTPP_DISABLE_HWACCEL_SIMD`): each of the sixteen state words
  becomes an `__m128i` holding that word for four consecutive counters, so one
  pass of the twenty rounds produces 256 bytes, followed by a 4x4 transpose per
  group of four words to get back to block-major byte order. Blocks are
  independent by construction, so nothing has to be serialized. Unlike
  `CBigNum`'s ADX/BMI2 and `CGf2m`'s PCLMULQDQ paths there is **no runtime
  CPUID check**, because SSE2 is part of the x86-64 ABI -- the gate is the
  architecture and the build option alone. Whole four-block groups go through
  it and the remainder falls through to the scalar loop, which also serves
  every non-x86-64 target. Measured at 1.93x the scalar keystream rate, taking
  a 64 KiB `seal()` from 331 to roughly 560 MiB/s.
  RFC 8439's own vectors cannot check any of this -- the largest is 114 bytes,
  so every one of them is served entirely by the scalar loop -- which is why
  `tests/crypto/syms/chacha20.cpp` carries a second, independent
  implementation of RFC 8439 2.3 and sweeps every length from 0 to 600 plus
  1 KiB/4 KiB/16 KiB/64 KiB against it. Deliberately breaking the per-lane
  counter feed-forward leaves all seven RFC-vector cases passing and fails
  only those two.

  `hchacha20()` lives here for the same reason the block function does -- it is
  the same twenty rounds -- and differs from `block()` in two ways that are
  each self-consistent if got wrong: the 128-bit nonce fills words 12 through
  15 (there is no counter), and there is **no feed-forward**, so the rounds'
  output is emitted as-is, words 0-3 followed by words 12-15. Reusing
  `block()` for it would produce a subkey that round-trips against itself and
  matches no other implementation, which is why it is a separate function
  rather than a flag on the existing one.
- **`crypto/rng.hpp` / `src/crypto/rng.cpp`** define `CRng`, a CSPRNG utility.
  `fill(const SByteSpan&) -> ERetCode` is backed directly by the operating
  system's CSPRNG -- `BCryptGenRandom` (Windows CNG, linked via
  `bcrypt.lib`) on Windows, the `getrandom(2)` syscall (Linux 3.17+,
  looping past `EINTR`/short reads, with a `/dev/urandom` fallback for
  ENOSYS/an outright syscall failure) on Linux, or `/dev/urandom` directly
  on other POSIX platforms -- rather than any third-party library, falling
  back to `std::random_device` only if the OS API fails
  *and* the `CERTPP_RNG_FALLBACK` CMake option (`OFF` by default -- a
  stopgap for an environment that genuinely lacks an OS-level CSPRNG, not
  something to leave on by default, since `std::random_device` isn't
  guaranteed cryptographically secure on every standard library) is
  enabled; leaving it disabled compiles the fallback path out entirely and
  `fill()` returns `ERET_NOTSUP` instead. `fillNonZero(const SByteSpan&)`
  fills a buffer with random *nonzero* bytes via rejection sampling over
  `fill()`, for padding schemes that forbid zero bytes (RSAES-PKCS1-v1_5).
  Needed by key generation (`IAsymmetric::generateKeyPair()`) and
  encryption padding once any `asyms/` implementation exists.
- **`crypto/asym.hpp`** defines `IAsymmetric`, `IAsymmetricContext`, and
  `IAsymmetricTransformer`. `IAsymmetric` holds no key material: `keySizes()`
  describes what the algorithm accepts, `generateKeyPair(keySize, out)`/
  `createPublicKey()`/`createPrivateKey()` produce/parse keys, and
  `createContext()` (`IStream::createMemory()`'s factory pattern as an
  instance method) returns a key-less `IAsymmetricContext`.

  `generateKeyPair()` reports its result via `ERetCode` (an out-parameter
  `SKeyPair& out`, not a return value) rather than the empty-`SKeyPair`-on-
  failure convention an earlier version used, so a caller can distinguish
  *why* generation failed -- in particular, `ERET_AGAIN` specifically means
  the freshly generated key failed `checkPrivateKey()`'s validation (see
  below) and the caller should simply call `generateKeyPair()` again, as
  opposed to a structural failure (`ERET_KEY_SIZE` for an unsupported
  `keySize`, `ERET_UNKNOWN` for an RNG/arithmetic failure) that retrying
  won't fix. Every concrete implementation validates its own freshly built
  key via `checkPrivateKey()` before returning it, rather than looping
  internally on a validation failure -- looping is the caller's decision,
  not something hidden inside `generateKeyPair()`. Importantly,
  `checkPrivateKey()`'s own diagnostic code is never forwarded directly --
  `generateKeyPair()` always translates any non-`ERET_OK` result into
  `ERET_AGAIN`, since a fresh candidate's *specific* rejection reason isn't
  actionable for a caller who's just going to try again, and conflating the
  two would make `ERET_AGAIN` ambiguous for a caller validating a
  deserialized key directly (see `checkPrivateKey()` below) where retrying
  isn't a coherent response at all.

  `checkPrivateKey(key)` validates a private key's structure -- both a
  freshly generated one (called internally by `generateKeyPair()`, as
  above) and one parsed from untrusted storage via `createPrivateKey()`
  (called directly). Since retrying isn't coherent for the latter case, it
  reports *why* validation failed instead of `ERET_AGAIN`: `ERET_KEY_FORMAT`
  if `key` wasn't created by this algorithm instance (wrong concrete type),
  `ERET_KEY_ERROR` if `key` is internally inconsistent (e.g. its linked
  public key is missing or of the wrong type), or `ERET_KEY_PARAM` if a
  structural check on its own parameters/derived values fails. The same
  three-way distinction (missing vs. wrong type vs. bad value) is applied
  throughout `sign()`/`verify()`/`deriveSharedSecret()` too: each first
  checks whether the context's bound key is present at all (`ERET_KEY_EMPTY`
  if not), then whether it's this algorithm's own concrete key type
  (`ERET_KEY_FORMAT` if not) -- distinguishing "nothing bound" from "the
  wrong algorithm's key pair was bound to this context"
  (`IAsymmetricContext::keyPair()` itself doesn't type-check what it's
  given).

  For the elliptic-curve algorithms (`CEcdsa`/
  `CEcdsa2`/`Ed25519`/`Ed448`), this means the classic four checks on the
  key's derived public point Q (point-at-infinity, field range, curve
  equation, correct-order subgroup: `n*Q` must reduce to the identity) plus
  (for `CEcdsa`/`CEcdsa2` only -- see below) the private scalar's own range
  `d in [1, n-1]` -- and a fifth check every algorithm here applies
  regardless of curve family: that Q is *this key's own* point, not merely
  *some* well-formed one. `CEcdsa`/`CEcdsa2` recompute `d*G`
  (`scalarMulBase()`) and compare against Q directly; `Ed25519`/`Ed448`
  re-derive the scalar `s` from the stored seed (the same
  `deriveFromSeed()` signing itself uses) and compare `s*B` against Q;
  `RSA`/`DSA` (see below) and `X25519` apply the same idea to their own
  shape instead -- without this, a private scalar could be paired with an
  unrelated but independently well-formed public key/point and still pass
  every other check. `X25519` (a Montgomery curve, u-coordinate only, cofactor
  8, twist-secure by design) uses RFC 7748-appropriate analogues instead:
  field range, reject an all-zero derived public key (RFC 7748 6.1's own
  rule, applied to key generation rather than the ECDH output), and reject
  a low-order/twist-torsion public key -- detected by computing `8*u`
  directly (reduces to the identity iff `u` has order dividing the
  cofactor) rather than checking against a hardcoded constant list; there is
  deliberately no curve-equation check, since X25519 accepts u-coordinates
  from either the curve or its quadratic twist by design. `Ed25519`/`Ed448`
  skip the scalar-range check `CEcdsa`/`CEcdsa2` have: RFC 8032 5.1.5/5.2.5's
  clamped scalar is deliberately *not* meant to be less than the group
  order (clamping fixes it into a fixed high bit range instead), unlike
  ECDSA's `d`. `RSA`/`DSA` (not elliptic-curve algorithms) implement their
  own analogous structural checks instead of the four EC-point checks: RSA
  validates `p`/`q` are distinct probable primes, `n == p*q`, `e` is
  coprime to `phi(n)`, `d` is `e`'s modular inverse mod `phi(n)`, and the
  CRT parameters (`dp`/`dq`/`qInv`) are consistent with `d`/`p`/`q`; DSA
  validates `p`/`q` are probable primes, `q` divides `p-1`, `g` has order
  `q`, `x` is in `[1, q-1]`, and `y == g^x mod p` -- both also dynamic-cast
  their own `IPrivateKey::publicKey()` first (`ERET_KEY_ERROR` if that
  fails) and check its stored fields (`n`/`e` for RSA; `p`/`q`/`g`/`y` for
  DSA) match the private key's own, the same "Q is *this key's* point, not
  just *some* point" idea the EC/EdDSA algorithms apply via `d*G`/`s*B`
  above. `X25519`'s `checkPrivateKey()` does the analogous thing by
  re-deriving `u` from the stored raw scalar and comparing its little-endian
  encoding against the linked public key's stored bytes.

  `IAsymmetricContext`
  holds a bound key pair (`keyPair()`, cleared via `reset()`; both notify
  the `protected` `onReset()` hook so a derived class can invalidate
  anything it derives from the key) and acts on it directly: `sign()`/
  `verify()` return `ERetCode` (not `bool`, so "doesn't match" is
  distinguishable from `ERET_NOTSUP`/an error) and default to `ERET_NOTSUP`,
  `IStream`'s not-every-implementation-supports-this pattern.
  `deriveSharedSecret(peerPublicKey, out)` follows the same optional-
  capability idiom, for Diffie-Hellman-style key agreement (`X25519`, and
  `CEcdsa` for prime-curve ECDH): it combines the context's own bound
  private key with an explicitly passed peer public key, unlike every other
  method here, which acts only on the bound key(s) -- the minimal addition
  needed to fit a two-party operation into an interface otherwise built
  around a single bound key pair.

  Prime-curve ECDH lives on `CEcdsa`'s context rather than a separate
  `CEcdh` because an ECDH key pair over a prime curve *is* an ECDSA key pair
  -- RFC 5480's `id-ecPublicKey` `SubjectPublicKeyInfo`, with the same curve
  OID, serves both -- so a separate algorithm would have meant a second
  `EAsymmetrics` enumerator describing one encoded key, and `IKeyBase::
  algorithm()` exists precisely to pick that OID. It also matches `RSA`,
  whose one context already carries sign/verify alongside
  `createEncrypter()`/`createDecrypter()`. One generated key pair therefore
  binds to one context and does both. The shared secret is the
  x-coordinate of `d*Q` alone, left-padded to `CEcCurve::fieldByteLen()`
  (RFC 5903 section 7 -- not the full point, not a hash of it); callers run
  it through `CHkdf`. The peer point is re-validated against the *bound
  key's own* curve (not infinity; `0 <= x, y < p`; on the curve) rather than
  trusted from whatever curve the peer's key object carries, which is what
  stops an invalid-curve attack; there is deliberately no small-subgroup
  check, since every `CEcCurve` prime curve has cofactor 1, the opposite of
  `X25519`'s cofactor 8. **It is not constant-time** -- see
  `CEcCurve::scalarMul()`'s own note and the doc comment on
  `EcContext::deriveSharedSecret()`.

  `sign()`/`deriveSharedSecret()`'s `out` parameter is a fixed, caller-
  allocated `SByteSpan&` (not a growable `TArray<uint8_t>&`): the caller
  queries `sizeOfSign()` first, allocates a buffer at least that large, and
  passes it in; the implementation writes into `out.data` and narrows
  `out` to the actual bytes produced (`out = SByteSpan(out.data,
  actualLen)`) before returning, or returns `ERET_NOSPC` up front without
  writing anything if the caller's buffer was too small. `sizeOfSign()`/
  `sizeOfDigest()` (getters public, setters `protected` -- the same
  split-access pattern `IAsymmetric::keySizes()` already uses) are computed
  in each concrete context's `onReset()` from whichever key is bound
  (private key first, then public, so a verify-only context still reports
  a meaningful `sizeOfSign()`): `sizeOfSign()` is the maximum signature
  size (exact for RSA/Ed25519/Ed448's fixed-format signatures; a safe
  upper bound for DSA/ECDSA/ECDSA2's DER-encoded ones, which are
  frequently 1-2 bytes shorter in practice -- see those modules' own
  bullets for the exact DER-size formula), 0 where `sign()` isn't
  supported at all (`X25519`). `sizeOfDigest()` is the largest digest
  length an algorithm's math actually consumes (the field/subgroup byte
  length for DSA/ECDSA/ECDSA2, since a longer digest is truncated to
  exactly that many bits regardless) -- 0 for RSA (which accepts one of
  six discrete, unrelated lengths depending on hash algorithm, not a
  single "maximum") and for Ed25519/Ed448/X25519 (no digest concept at
  all: EdDSA's `sign()` "digest" parameter is the raw message).

  `createEncrypter()`/`createDecrypter()` are pure virtual instead, since
  asymmetric encryption only ever handles one block at a time -- they hand
  back an `IAsymmetricTransformer` (bound to the same key) for the caller to
  drive via `transform()` (repeatedly, one chunk at a time) then
  `transformFinal()`, rather than a single arbitrary-length call.
  `transform()`/`transformFinal()` take the same fixed `SReadOnlyByteSpan`/
  `SByteSpan&` shape as `sign()`; `IAsymmetricTransformer::blockSize()`
  (getter public, setter `protected`) reports the natural block size for
  the transformer's operation -- for `RsaTransformer`, the RSA modulus
  byte length (the ciphertext block size; PKCS#1v1.5's plaintext block is
  up to 11 bytes smaller, not tracked as a second field).
- **`crypto/asyms/rsa.hpp` / `src/crypto/asyms/rsa.cpp`** define `RSA`
  (RFC 8017), the first concrete `IAsymmetric`. Keys serialize as PKCS#1
  DER (`RSAPublicKey`/`RSAPrivateKey`, two-prime form only) via `CDer`.
  `sign()`/`verify()` implement EMSA-PKCS1-v1_5: since `IAsymmetricContext`
  isn't told which hash produced the digest it's given, the DigestInfo's
  hash `AlgorithmIdentifier` is inferred from the digest's byte length (16/
  20/28/32/48/64, covering MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 --
  every hasher this library ships except the variable-length SHAKE256 and
  MD4). MD4 is the one collision in that mapping, since it is also 16 bytes
  wide: a 16-byte digest is read as MD5, because `md5WithRSAEncryption` is a
  real (if obsolete) X.509 signature algorithm and `md4WithRSAEncryption` is
  effectively never seen. MD4 exists here for NTLM/EAP-MSCHAPv2's NT hash,
  not for signing, so that is the right way round -- but it is the reason
  digest-length sniffing cannot absorb another 16-byte hash, and a caller
  that genuinely needs MD4-with-RSA has to be given a named-algorithm path
  instead. `signPss()`/`verifyPss()`
  (declared on `IAsymmetricContext` itself, defaulting to `ERET_NOTSUP`
  there since only RSA overrides them) implement RSASSA-PSS (RFC 8017 9.1)
  instead: EMSA-PSS-ENCODE/-VERIFY plus an MGF1 mask built from a caller-
  named `EHashers`, rather than digest-length sniffing -- PSS's own
  `AlgorithmIdentifier` carries its hash/MGF/salt-length explicitly, so
  there's no ambiguity to resolve the way plain `sign()`/`verify()` have to.
  `createEncrypter()`/`createDecrypter()` implement RSAES-PKCS1-v1_5,
  using `CRng::fillNonZero()` for its padding. The private `RsaPublicKey`/
  `RsaPrivateKey`/`RsaContext`/`RsaTransformer` classes back the public
  `IPublicKey`/`IPrivateKey`/`IAsymmetricContext`/`IAsymmetricTransformer`
  interfaces respectively, same pattern as `MemStream` backing `IStream`.

  Every private-key operation (`sign()`, `signPss()`, `decryptBlock()`)
  goes through `RsaContext::privateExp()`, which uses CRT (Garner's
  formula) instead of a single full-modulus `modExp(x, d, n)`: it computes
  `m1 = x^dp mod p`, `m2 = x^dq mod q` (each a modular exponentiation over
  a modulus roughly half the bit length of `n`, so each is individually
  about 4x cheaper than the full-width version, and the two are
  independent of each other), then combines them via `h = qInv*(m1 - m2)
  mod p; m = m2 + h*q`. This only runs when all of `p`/`q`/`dp`/`dq`/`qInv`
  are present on the key (true for anything this library's own
  `generateKeyPair()` produces, but not guaranteed for a key imported via
  `createPrivateKey()` with only `n`/`d` populated) -- `privateExp()` falls
  back to plain `modExp(x, d, n)` whenever any CRT parameter is missing.
  Even when CRT parameters are present, the result is never returned
  directly: `privateExp()` always re-encrypts it (`modExp(m, e, n) ==
  x?`) before handing it back, falling back to plain `modExp` on any
  mismatch. This check is simultaneously the standard Lenstra/Bellcore
  fault-attack countermeasure (a single bit-flip during the CRT
  computation, whether from a hardware fault or a corrupted/inconsistent
  key, produces a faulty signature that -- for RSA specifically --
  leaks a factor of `n` via `gcd(x - m^e, n)`, so skipping the check isn't
  an option) and a safety net making CRT correct to use even on an
  imported key whose CRT parameters were never independently validated via
  `checkPrivateKey()`.

  `decryptBlock()`'s EME-PKCS1-v1_5 unpadding (RFC 8017 7.2.2) scans the
  decrypted block for its `0x00`/`0x02` lead bytes and `0x00` separator in
  constant time: the separator search always runs the full `keyBytes - 2`
  iterations (never stopping at the first `0x00`), and every check -- lead
  bytes, separator found, minimum 8-byte padding length -- is folded into
  one bitmask via bitwise AND/OR rather than a chain of early-return
  branches, the same discipline `CbcTransformer`'s PKCS#7 check already
  applies (see its own doc comment below). The original version's
  data-dependent-length scan plus early-return branches on the lead
  bytes/separator position had the textbook Bleichenbacher-oracle shape:
  every failure path already returned the same `ERET_BADREQ`, but the
  *time taken* to reach it still leaked which check failed and where.
- **`crypto/asyms/dsa.hpp` / `src/crypto/asyms/dsa.cpp`** define `DSA`
  (FIPS 186-4), sign/verify only -- DSA has no encryption operation, so its
  `DsaContext::createEncrypter()`/`createDecrypter()` unconditionally
  return `ERET_NOTSUP`. `keySizes()` accepts exactly the three FIPS 186-4
  (L, N) pairs (1024/160, 2048/256, 3072/256), selected by L alone;
  `generateKeyPair()` generates fresh domain parameters (p, q, g) itself
  (FIPS 186-4 A.1.1.2's probable-primes construction, minus the seed/
  counter bookkeeping needed to later re-verify a parameter set's
  provenance) rather than requiring them supplied separately, since this
  library has no separate domain-parameter type to share them through.
  Private keys serialize as the traditional (OpenSSL-compatible)
  `DSAPrivateKey` DER layout; public keys as this library's own
  `SEQUENCE { p, q, g, y }` (there's no equally simple traditional
  single-blob public-key format -- OpenSSL's splits the domain parameters
  into a `SubjectPublicKeyInfo` `AlgorithmIdentifier`, which this library
  doesn't model yet). Signatures serialize as the standard
  `Dss-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 3279).

  `sign()`'s `g^k mod p` term is computed via `DsaPrivateKey::
  fixedBaseModExpG()`, a left-to-right windowed exponentiation over a
  lazily-built, per-instance-cached table of `g^0..g^15 mod p` -- the same
  "16-entry window" shape `CEcCurve::scalarMulBase()` already uses for
  fixed-base EC signing (see that module's own doc comment), adapted from
  point addition/doubling to modular multiplication/squaring. This turns
  the exponentiation into `bitLength/4` squarings plus exactly one window
  multiplication per 4 bits, instead of a plain `modExp()`'s
  square-and-multiply averaging `bitLength/2` multiplications; since the
  table is keyed only on this key's fixed `(g, p)`, not on the per-signature
  nonce `k`, it's built once and amortizes across every `sign()` call (and
  retry attempt) this key ever makes.
- **`crypto/eccurve.hpp` / `src/crypto/eccurve.cpp`** define `CEcCurve`/
  `SEcPoint`, a short-Weierstrass elliptic curve (`y^2 = x^3 + a*x + b mod
  p`) in affine coordinates. Public rather than a `src/`-only implementation
  detail, for the same reason as `CBigNum`: the group arithmetic isn't tied
  to any one algorithm. `add()`/`doublePoint()` implement the group law
  directly in affine form (one modular inversion per call each) -- still
  the simplest path for a single one-off group operation, and what
  `isOnCurve()`/`encodePoint()`/`decodePoint()` and this library's known-
  curve self-checks build on. `scalarMul()` (an arbitrary point times an
  arbitrary scalar) and `scalarMulBase()` (`g` times a scalar, e.g. every
  sign()/verify() call's `k*g`/`u1*g` term) instead work internally in
  Jacobian coordinates (`ECPointJac`, `eccurve.cpp`'s anonymous namespace --
  `X/Z^2, Y/Z^3`, `Z == 0` for infinity): a branch-free R0/R1 ladder
  (`condSwapJac()` swaps which register holds which value based on the
  scalar's bit, rather than branching on whether to add at all) that pays
  for exactly one modular inversion at the very end
  (`toAffineFromJac()`), not one per bit, and holds its coordinates in
  **Montgomery form** (`CMontgomery`, see `utils/montgomery.hpp` above) so
  that the thousands of field multiplications a scalar multiplication performs
  cost limb-wise multiply-accumulate passes rather than a long division each.
  The per-modulus context is built at the top of `scalarMul()`/
  `scalarMulBase()` and passed down, rather than cached on the `CEcCurve`
  instance: `p`/`a`/`b` are public mutable fields, so a cached context would
  need invalidating whenever a caller wrote to one, and its two divisions are
  unmeasurable next to the scalar multiplication they precede.
  `toJacobian()`/`toAffineFromJac()` are the conversion boundary in both
  directions, so no Montgomery-form value escapes those five functions; the
  affine `add()`/`doublePoint()`/`isOnCurve()` deliberately stay on
  `CBigNum`'s general path, since a single group operation is dominated by its
  one modular inversion and there is nothing to amortize a context over.
  `scalarMulBase()` additionally
  uses a lazily-built, per-instance-cached table of small multiples of `g`
  (`_baseTable`, a 4-bit window, 16 entries) to cut the number of additions
  from one per bit to one per 4 bits. `doublePointJac()`/`addJac()`
  (Bernstein/Lange `dbl-2007-bl`/`add-2007-bl`, general `a`) and the
  Lopez-Dahab equivalents in `ec2curve.cpp` are written to mutate a
  `CBigNum`/`CGf2m` operand in place whenever that operand's current value
  is never read again afterward, rather than copying it into a fresh
  variable first (each such spot has a comment naming which read is that
  operand's last) -- same in-place-over-copy discipline `CBigNum`/`CGf2m`'s
  own methods follow (see their own doc comments above), just carried
  through to these free functions' local variables too. Like `CBigNum`,
  this still has no constant-time hardening (the ladder swaps aren't
  constant-time either) -- correctness/auditability over full side-channel
  resistance remains this library's stance.
  `EEcKnownCurves` (`ECURVE_P192`/`ECURVE_P224`/`ECURVE_P256`/`ECURVE_P384`/
  `ECURVE_P521`/`ECURVE_SECP256K1`, plus 14 `ECURVE_BPOOLxxxR1`/
  `ECURVE_BPOOLxxxT1` values for the Brainpool curves) names this library's
  built-in curves; `CEcCurve::knownCurves(which, out)` looks one up from the
  private `_knownCurves` array, defined in `eccurve.cpp` with each curve's
  standard domain parameters (FIPS 186-4 for the NIST curves, SEC 2 for
  secp256k1, RFC 5639 for Brainpool -- the R1 curves' `a`/`b` are random;
  each T1 curve is R1's isomorphic "twisted" counterpart with `a = -3 mod
  p`, sharing the same `p`/`n`) in `EEcKnownCurves` order (independently
  verified against a second source before hardcoding, given how silently a
  single wrong hex digit would produce an insecure, non-standard curve that
  still passes this library's own self-consistency tests -- this actually
  happened twice during development, both times caught immediately by
  `verify()` failing; every curve added since is instead checked
  programmatically -- curve-equation and bit-length self-consistency, plus
  a second-source cross-check -- before being hardcoded, precisely to catch
  that class of mistake before it ships).
- **`crypto/asyms/ecdsa.hpp` / `src/crypto/asyms/ecdsa.cpp`** define
  `CEcdsa`, ECDSA (FIPS 186-4) over any `EEcKnownCurves` value, selected via
  its constructor (`CEcdsa(ECURVE_P256)`, etc.) -- one class rather than a
  separate concrete class per curve, since the only difference between them
  is which domain parameters `keySizes()`/`generateKeyPair()`/sign/verify
  use. `CEcdsa` looks its `CEcCurve` up once (via `knownCurves()`) and keeps
  its own copy as a plain value member: the private `EcPublicKey`/
  `EcPrivateKey` classes likewise each keep their own `CEcCurve` copy rather
  than a pointer/reference back to `CEcdsa`'s, since a generated key can
  outlive the `IAsymmetric` instance it came from (e.g.
  `IAsymmetric::builtIn(EASYM_P256)->generateKeyPair(256)` as a one-liner)
  -- an early version stored a raw `const CEcCurve*` there instead, which
  dangled and crashed in exactly that pattern. Private keys serialize as
  this library's own
  `SEQUENCE { version INTEGER (0), d INTEGER, publicKey OCTET STRING }`
  (no `SubjectPublicKeyInfo`/curve-OID modeling yet); public keys as a bare
  SEC1 uncompressed point. Signatures serialize as the standard
  `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 3279/SEC 1).
  `keySizes()` accepts exactly one size, the chosen curve's fixed field
  width (160/192/224/256/320/384/512/521 bits, depending on curve).
- **`crypto/ec2curve.hpp` / `src/crypto/ec2curve.cpp`** define `CEc2Curve`/
  `SEc2Point`, a binary curve (`y^2 + x*y = x^3 + a*x^2 + b` over GF(2^m))
  in affine coordinates -- `CEcCurve`'s binary-field counterpart, same
  reasoning for being public and affine/non-constant-time, but an entirely
  different group law (no formula is shared with `CEcCurve`) built on
  `CGf2m` instead of `CBigNum` for the field arithmetic. `add()`/
  `doublePoint()` stay affine (one field inversion each); `scalarMul()`/
  `scalarMulBase()` work internally in Lopez-Dahab coordinates
  (`EC2PointLD`: `X/Z, Y/Z^2`, `Z == 0` for infinity) via the same
  branch-free-ladder/cached-fixed-base-table/mutate-in-place-when-safe
  approach as `CEcCurve`'s Jacobian path (see its own doc comment above) --
  `doublePointLD()`/`addLD()`'s formulas were derived from this file's own
  affine ones and independently cross-checked against them (2000+ random
  trials plus edge cases, and an end-to-end ladder run) via a standalone
  Python GF(2^163) implementation before being hardcoded here, per this
  module's established constant-verification discipline (see `_knownCurves`
  below). `field` is a
  non-owning `const SGf2mField*` rather than an owned value, mirroring
  `CGf2m`'s own field pointer, since it's always one of `CGf2m`'s 5 shared
  static singletons (a "B" and "K" curve of the same size use the same
  field) -- see `CGf2m`'s doc comment for why this differs from `CEcCurve`
  owning its `CBigNum` values directly. `EEc2KnownCurves` (`ECURVE2_B163`/
  `ECURVE2_K163` .. `ECURVE2_B571`/`ECURVE2_K571`) names the 10 built-in
  curves; `CEc2Curve::knownCurves()` looks one up from the private
  `_knownCurves` array, defined in `ec2curve.cpp` with each curve's
  standard domain parameters (FIPS 186-4 Appendix D / SEC 2, cross-checked
  against a second source) in `EEc2KnownCurves` order. Every base
  point/order was independently verified two ways before being hardcoded --
  confirmed on-curve (`isOnCurve()`) *and* confirmed to have exactly the
  stated order (`scalarMul(g, n)` reduces to the point at infinity) -- the
  same two-property check this library used for Ed448's algebraically-
  derived base point, and much stronger than either property alone.
  Point encoding is SEC1 uncompressed (`0x04 || X || Y`) only; compressed-
  point decompression (which needs a GF(2^m) quadratic solve `CGf2m`
  doesn't implement) is deferred, since ECDSA sign/verify doesn't need it.
- **`crypto/asyms/ecdsa2.hpp` / `src/crypto/asyms/ecdsa2.cpp`** define
  `CEcdsa2`, ECDSA over any `EEc2KnownCurves` value -- `CEcdsa`'s binary-
  curve counterpart, same constructor-selects-curve shape and same
  by-value curve ownership in its private `Ec2PublicKey`/`Ec2PrivateKey`
  classes (for the identical dangling-pointer reason `CEcdsa`'s own doc
  comment explains). The ECDSA math itself (`r`/`s` reduced mod the
  subgroup order `n`) is unchanged from `CEcdsa`'s, since `n` stays a
  `CBigNum` regardless of curve family; only the signed point's
  x-coordinate needs converting from a GF(2^m) element to an integer
  first, via the field-element-to-integer rule FIPS 186-4 Appendix C.2
  defines for binary curves (a field element's `m`-bit polynomial-basis
  representation, reinterpreted directly as an unsigned integer -- the
  same bytes `CGf2m::toBigEndian()`/`CBigNum::fromBigEndian()` already
  agree on). `keySizes()` accepts exactly one size, the chosen curve's
  field degree `m` (163/233/283/409/571 bits). Serialization formats are
  identical in shape to `CEcdsa`'s.
- **`crypto/asyms/ed25519.hpp` / `src/crypto/asyms/ed25519.cpp`** define
  `Ed25519` (EdDSA over edwards25519, RFC 8032). Its field/point arithmetic
  is dedicated to this one curve rather than routed through `CEcCurve`
  (which only models short-Weierstrass curves; edwards25519 is a twisted
  Edwards curve, with a different, unconditionally-complete addition
  law -- one formula handles both point addition and doubling, unlike
  `CEcCurve::add()`/`doublePoint()`).

  **Two moduli, two types.** Ed25519 works modulo the field prime `p =
  2^255 - 19` for point coordinates and modulo the group order `L = 2^252 +
  0x14DEF9DEA2F79CD65812631A5CF5D3ED` for scalars, and the two are kept
  apart by the type system rather than by discipline. Coordinates are
  `Fe25519` (`src/crypto/asyms/fe25519.hpp`, shared with `X25519`), which
  implements `p` and nothing else; scalars -- the clamped private scalar,
  signing's nonce `r`, the reduced hash `k`, a signature's `S` -- are
  `CBigNum` reduced mod `groupOrder()`. `EdPoint`/`EdPointProj` hold nothing
  but `Fe25519`, and `Fe25519` has no conversion to or from `CBigNum`
  (its only external representation is 32 bytes), so a scalar cannot reach
  field arithmetic or a coordinate reach mod-`L` arithmetic without code
  that does not compile. The distinction matters because reducing a scalar
  mod `p` produces a signature that verifies against itself and against
  nothing else in the world -- a failure no self-consistency test can see,
  which is why all five of RFC 8032 section 7.1's byte-exact vectors are
  checked.

  Every curve constant (the equation parameter `d = -121665/121666 mod p`,
  the base point) is *derived* at first use from small integers rather
  than hardcoded as a 255-bit literal, except the group order's addend
  (`0x14DEF9DEA2F79CD65812631A5CF5D3ED`, independently confirmed against a
  second source), which has no simpler closed form -- deriving instead of
  transcribing sidesteps the exact class of mistake the NIST curve
  constants above hit twice. `sign()`/`verify()`'s "digest" parameter is
  unusually the *raw message*, not a hash: pure EdDSA hashes its input
  internally, so there is no caller-supplied digest to accept, unlike
  every other algorithm in this library. Keys and signatures serialize as
  RFC 8032's own raw byte encodings (32/32/64 bytes), with no DER
  structure, since that's what the format already is. Verified against
  all five of RFC 8032 section 7.1's known-answer vectors (the empty
  message, 1, 2, 64 and 1023 bytes) -- EdDSA signing is deterministic
  (no per-signature randomness), so an exact signature byte match
  validates the whole pipeline (arithmetic, derived constants, clamping,
  and the signing algorithm itself) far more strongly than a
  self-consistency round-trip alone could.

  `pointAdd()` (affine) stays the reference implementation for the
  single-operation case; `scalarMul()` (an arbitrary point) and
  `scalarMulBase()` (the base point `B` specifically, e.g. every sign()/
  verify() call's `B*r`/`B*s` term) work internally in extended projective
  coordinates (`EdPointProj`: Hisil/Wong/Carter/Dawson's `X/Z, Y/Z, T=XY/Z`,
  "Twisted Edwards Curves Revisited") via the same branch-free-R0/R1-ladder
  shape `CEcCurve::scalarMul()` uses (`crypto/eccurve.hpp`'s doc comment),
  simpler here since `pointAddProj()` is unconditionally complete (handles
  `P+P` and the identity with no special-casing, so the ladder needs no
  separate doubling step) and pays for exactly one modular inversion at the
  very end instead of one per bit. `scalarMulBase()` additionally uses a
  lazily-built, process-lifetime-cached table of small multiples of `B`
  (`baseTable()`, a 4-bit window) -- unlike `CEcCurve`'s per-`CEcCurve`-
  instance table, this file's base point is a single, fixed, file-scope
  constant, so one process-wide table suffices. Both read the scalar over a
  fixed 256 bits rather than over `CBigNum::bitLength()`, so the number of
  iterations does not depend on how large a secret scalar happens to be;
  `CBigNum::testBit()` reads false past the top limb, and a leading zero bit
  adds the identity and leaves the ladder invariant intact.
- **`crypto/asyms/ed448.hpp` / `src/crypto/asyms/ed448.cpp`** define
  `Ed448` (EdDSA over edwards448/"Ed448-Goldilocks", RFC 8032) --
  structurally `Ed25519`'s twin, with its own field/point arithmetic (a
  different prime, and untwisted rather than twisted Edwards addition, so
  not shared code) and its own private `EdPublicKey`/`EdPrivateKey`/
  `EdContext` classes, but every hash SHAKE256 (114-byte output) rather
  than SHA-512, each prefixed with RFC 8032 5.2's `dom4(F, C)` string
  (fixed here at `F = 0`, empty `C`: `"SigEd448" || 0x00 || 0x00` --
  context strings aren't supported). Its base point is the one constant
  that resisted every attempt to transcribe it directly: repeated fetches
  of "authoritative" sources for its x/y coordinates each produced a
  *different*, self-inconsistent-with-the-real-curve value (one even had
  the wrong bit length outright). It was ultimately derived instead --
  `B = [s^-1 mod L] * A`, where `A` is RFC 8032 TEST 1's known-correct
  public key point and `s` its arithmetically-derived clamped scalar --
  and independently confirmed by regenerating that exact public key from
  it and by checking it has order exactly `L` (both extremely
  discriminating properties, especially the latter: edwards448's cofactor
  of 4 means most curve points don't have order `L` at all).
  Keys/signatures serialize as RFC 8032's raw byte encodings (57/57/114
  bytes). Verified against RFC 8032's own TEST 1 vector, for the same
  reason as `Ed25519`.

  `scalarMul()`/`scalarMulBase()` use the same extended-projective-
  coordinates/branch-free-ladder/fixed-base-table approach as `Ed25519`
  (see its own doc comment above), but edwards448 is *untwisted* (`a = 1`,
  vs. edwards25519's `a = -1`), so `pointAddProj()` here uses the general
  `a`-parametrized addition law rather than `Ed25519`'s `a = -1`-specialized
  one -- derived directly from the affine addition law (see this function's
  own comment in `ed448.cpp`) rather than transcribed from a reference,
  since the well-known named formula for this shape is specific to `a =
  -1`. `EdPointProj`'s four coordinates are held in **Montgomery form**
  (`CMontgomery`, see `utils/montgomery.hpp` above) for the same reason
  `CEcCurve`'s `ECPointJac` is, with `toProjective()`/`toAffine()` as the
  conversion boundary; unlike `CEcCurve`, the context here is a
  construct-on-first-use singleton next to `fieldPrime()`, since edwards448
  has exactly one field prime and it is not a mutable public field. `d` is
  cached in Montgomery form alongside it (`curveDMont()`), and `fieldSqrt()`'s
  `x2^((p+1)/4)` runs through `CMontgomery::modExp()` -- ~446 squarings and
  ~223 multiplies that each used to be followed by a long division, once per
  decoded point, i.e. once per `verify()`.
- **`crypto/asyms/x25519.hpp` / `src/crypto/asyms/x25519.cpp`** define
  `X25519` (Diffie-Hellman key agreement over Curve25519, RFC 7748) --
  same field prime as `Ed25519` (`2^255 - 19`), and in fact the same field
  *implementation* (`Fe25519`, `src/crypto/asyms/fe25519.hpp`), but
  Montgomery-form curve arithmetic rather than twisted-Edwards, since
  X25519 only ever needs the u-coordinate Montgomery ladder (RFC 7748 5),
  not full affine point addition. `sign()`/`verify()` are left at
  `IAsymmetricContext`'s
  `ERET_NOTSUP` defaults (no signing operation exists); only
  `deriveSharedSecret()` is overridden. A private key's raw 32 bytes are
  stored unclamped and clamped at each scalar-mult call site instead
  (RFC 7748 5's own recommended split of responsibility), so
  `serialize()`/`createPrivateKey()` always round-trip the caller's exact
  original bytes. `deriveSharedSecret()` rejects an all-zero computed
  secret (RFC 7748 6.1 -- a low-order peer point, e.g. `u = 0`) rather than
  returning predictable output. Keys serialize as RFC 7748's raw 32-byte
  u-coordinate/scalar encodings, no DER. Verified against RFC 7748 5.2's
  Diffie-Hellman and iterated-scalar-multiplication known-answer vectors,
  independently re-derived via a standalone Python implementation of the
  same ladder before hardcoding -- not just transcribed from a single
  fetch, consistent with this module's established constant-verification
  discipline.
- **`crypto/transform.hpp`** defines `ITransformer`, the generic streaming
  transform interface (`blockSize()`, `transform()`, `transformFinal()`)
  both `IAsymmetricTransformer` (encrypt/decrypt with RSA, one block at a
  time) and `ISymmetricTransformer` (below) derive from.
- **`crypto/sym.hpp`** defines `ISymmetric`, `ISymmetricContext`, and
  `ISymmetricTransformer` -- the symmetric-cipher counterpart of
  `asym.hpp`'s `IAsymmetric`/`IAsymmetricContext`/`IAsymmetricTransformer`,
  with one structural difference: `ISymmetric::createContext(key)` binds
  the key immediately (there's no keyless context to fill in later, unlike
  `IAsymmetricContext::keyPair()`), and the IV is set separately via
  `ISymmetricContext::key(key, iv)` (the same method, called again) since
  `createContext()` itself takes no IV. `ISymmetric::builtIn(which)` is the
  `ESymmetrics` (`ESYM_AES`/`ESYM_DES`/`ESYM_3DES`/`ESYM_CHACHA20`) factory,
  mirroring `IAsymmetric::builtIn()`.
- **`crypto/syms/aes.hpp`/`des.hpp`/`des3.hpp` / `src/crypto/syms/aes.cpp`/
  `des.cpp`/`des3.cpp`** define `AES` (FIPS-197, 128/192/256-bit keys),
  `DES` (FIPS 46-3, legacy/interop only), and `TripleDES` (two- or
  three-key EDE, built directly on the same DES block core). All three
  `ISymmetricContext`s operate in CBC mode -- the only mode this library's
  `ISymmetric` block ciphers implement -- via the
  shared `src/crypto/syms/cbctransformer.hpp`/`.cpp` (`CbcTransformer`, not
  part of the public API): buffering, CBC chaining, and padding add/strip
  factored out once rather than duplicated per algorithm, parameterized by
  a per-block encrypt/decrypt callback and the block size. Decrypting always
  holds back the most recently completed block instead of emitting it
  immediately, since it might turn out to be the final (padded) one.

  Padding is PKCS#7 (RFC 5652 6.3) by default and `ESYMPAD_NONE` on request,
  selected per context through `ISymmetricContext::padding()` and read when a
  transformer is created. Unpadded CBC exists for a protocol that pads for
  itself -- IKEv2 (RFC 7296 3.14) builds pad-length-terminated padding into the
  payload, so a PKCS#7 block underneath it would be a second, unexpected one.
  Unpadded, there is nothing to strip and nothing special about the last block,
  so every whole block is emitted as it completes and no block is held back;
  `transformFinal()` produces nothing and returns `ERET_BADREQ` if a partial
  block is left over, rather than quietly rounding the length up. `padding()`
  is deliberately *not* cleared by `reset()` or `key()`, unlike the key, IV and
  block size: it is a mode choice rather than key material, and clearing it
  would make `padding(ESYMPAD_NONE)` followed by `key(...)` silently revert to
  PKCS#7, which is a very quiet way to emit a ciphertext a peer rejects.
  Padding validation (`transformFinal()`'s decrypt path) is written to run
  every byte comparison unconditionally, with no early exit on the first
  mismatch and no branch on the pad value itself, specifically to avoid a
  Vaudenay-style CBC padding oracle (the exact class of bug behind
  POODLE/Lucky13) for any caller that lets an attacker observe many decrypt
  attempts against adaptively chosen ciphertexts -- the one place in this
  module where timing-side-channel hardening is treated as load-bearing
  rather than out of scope (contrast `CEcCurve`'s/`CBigNum`'s own
  correctness-over-constant-time stance elsewhere in `crypto/`). `AesCore`
  (shared private `aescore.hpp`/`.cpp`, used by both `aes.cpp` and
  `aeads/aesgcm.cpp`), `DesCore` (shared private `descore.hpp`/`.cpp`, used by both
  `des.cpp` and `des3.cpp`), and `TripleDesCore` (`des3.cpp`) hold each
  algorithm's own block-cipher math, kept private since nothing outside
  module needs them (`SymRawKey`, a trivial raw-byte `ISymmetricKey` with
  no validation beyond length, is shared the same way via
  `src/crypto/syms/symkey.hpp`).

  `AesCore` additionally has a hardware-accelerated path (x86-64 only, and
  only when `CERTPP_DISABLE_HWACCEL_AES` isn't set), the same shape as
  `SHA1`/`Sha2_32Core::transform`'s SHA-NI dispatch above: `encryptBlock()`/
  `decryptBlock()` are thin dispatchers that call
  `encryptBlockAccelerated()`/`decryptBlockAccelerated()` when a runtime
  CPUID check (`hasAesNi()`, leaf 1, ECX bit 25) passes, falling back to
  `encryptBlockPortable()`/`decryptBlockPortable()` (the original
  round-by-round implementation) otherwise. The accelerated path is the
  Intel-published `AESENC`/`AESENCLAST`/`AESDEC`/`AESDECLAST`/`AESIMC`
  intrinsics sequence (`<wmmintrin.h>`): encryption runs the standard
  cipher directly against `expandKey()`'s existing forward round keys
  (byte-identical to what AES-NI's own key schedule would produce, so no
  separate hardware key expansion is needed); decryption uses the
  "Equivalent Inverse Cipher" construction -- the forward round keys in
  reverse order, each put through `AESIMC` except the first and last --
  rather than re-deriving a true inverse key schedule. `DES`/`TripleDES`/
  have no equivalent: there is no mainstream x86 hardware extension for
  DES/3DES's Feistel network. ChaCha20's ARX rounds have no dedicated
  extension either, but they vectorize across blocks, so it has an SSE2 path
  of its own under `CERTPP_DISABLE_HWACCEL_SIMD` -- see the
  `src/crypto/syms/chacha20core.hpp` bullet above.
  Verified by the same SP 800-38A/FIPS-46/RFC 8439 known-answer vectors
  this module already runs -- on an AES-NI-capable CPU they exercise the
  accelerated path automatically, with `CERTPP_DISABLE_HWACCEL_AES`
  available to force the portable path for an explicit comparison.
- **`crypto/syms/chacha20.hpp` / `src/crypto/syms/chacha20.cpp`** defines
  `ChaCha20` (RFC 8439): a 256-bit key, a 96-bit nonce (`iv()`), and an
  internal 32-bit block counter (always starting at 0) are expanded into a
  keystream XORed with the input -- encryption and decryption are the
  identical operation, so `createDecrypter()` just returns another
  `createEncrypter()`-shaped transformer. Being a stream cipher, it needs
  no padding and places no block-alignment requirement on input length;
  `sizeOfBlock()` (64, once a key is bound) only reports the cipher's
  internal keystream-generation granularity, not an alignment requirement.
  Verified against RFC 8439 Appendix A.1's block-function known-answer
  vector.
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

  Real, currently-valid commercial certificates (fetched via `openssl
  s_client`/crt.sh) are checked into `tests/x509/certs/implemented/` as
  `.der` files (read via a small `readCertFile()` test helper, located
  through a generic `CERTPP_TEST_DIR` compile-definition every test target
  gets -- see `CMakeLists.txt`'s test-registration loop). There is no
  `certs/unimplemented/` directory any more. It held two certificates -- an
  RSASSA-PSS intermediate and an ML-DSA root -- and both now import, parse and
  verify, so both moved. The RSASSA-PSS one had always been mislabelled there:
  RSA-PSS the *algorithm* has been implemented since `crypto/asyms/rsa.cpp`'s
  `signPss()`/`verifyPss()`; what was missing was the certificate path to it, and
  its import actually failed on an unrecognized `organizationIdentifier` in the
  subject `Name`, before the signature algorithm was read at all. Recreate the
  directory if a future certificate exercises a real gap -- the split is what
  keeps "this is a known gap" from being indistinguishable from "nobody looked".
  One of the implemented ones carries its weight differently from the rest.
  `identrust-mldsa-root.der` is the real "IdenTrust Pilot Root TLS ML-DSA CA 1"
  (OID 2.16.840.1.101.3.4.3.19, which is **id-ml-dsa-87**; the arc runs
  .17/.18/.19 for ML-DSA-44/65/87, and the certificate's own 2592-byte key and
  4627-byte signature confirm which), and because it is self-signed
  `cert.verifyBy(cert)` on it is a genuine third-party post-quantum signature
  verified end to end. That is the only check in the suite that an ML-DSA
  implementation cannot pass by being consistently wrong -- a sign/verify round
  trip against itself survives a transposed `expandA`, a mis-shaped `Decompose`
  carve-out, or the internal signing interface used where the external one
  belongs. A companion test case flips one bit in the TBS, in the signature and
  in the public key, and requires each to fail.
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
- **`certpp.hpp`** is the single include point for consumers; as new public
  headers are added under `include/certpp/`, add their `#include` here. The
  optional `utils/json.hpp` include is guarded by `CERTPP_WITHOUT_JSON`, which
  CMake propagates to consumers when the JSON utility is disabled. Two other
  public headers are deliberately *not* included: `crypto/kem.hpp` (no
  implementation behind it yet -- see its own bullet) and `io/base64.hpp`,
  which is an empty placeholder (`CBase64` lives in `utils/base64.hpp`).
- **`tests/`** holds every test case, built via `CERTPP_BUILD_TESTS`
  (default `ON`) as one executable per source file and registered with
  CTest. See [coding-conventions.md](coding-conventions.md#tests) for the
  file-layout/naming convention and [build.md](build.md#tests) for how to
  build and run them; both cover the vendored `doctest` framework these
  files use.

### `dnssec`

A separate module rather than part of `x509`, because DNSSEC shares none of
X.509's encodings. Where a certificate carries a public key as a
`SubjectPublicKeyInfo` and an ECDSA signature as a DER `SEQUENCE { r, s }`,
DNSSEC writes the bare key material and the bare concatenation `r | s`. So a
DNSKEY cannot be handed to `IAsymmetric::createPublicKey()` and an RRSIG
signature cannot be handed to `verify()`; something has to re-encode in
between, and that is the whole purpose of this module.

- **`dnssec/name.hpp` / `src/dnssec/name.cpp`** define `CDnsName`.
  `toWire()` always folds ASCII uppercase to lowercase, and the API
  deliberately gives the caller no choice about it: a DS digest is taken over
  the owner name followed by the DNSKEY RDATA, so a name reaching the digest
  unfolded produces a DS that disagrees with every published one, and an
  option to skip the folding would only make that reachable by accident.
  Compression pointers (RFC 1035 4.1.4) are rejected rather than resolved,
  since DNSSEC forbids them in signed names and a name carrying one cannot be
  canonicalised without the rest of the message. `fromWirePrefix()` exists for
  RRSIG RDATA, where the signer's name is followed immediately by the
  signature with nothing to separate them.
- **`dnssec/records.hpp` / `src/dnssec/records.cpp`** define `SDnskey`,
  `SDsRecord` and `SRrsig`. The key tag is derived on demand rather than
  stored, because it is a checksum over the whole RDATA rather than an
  identifier: holding it as a field would let it disagree with the key it
  names. `SRrsig::toSignedPrefix()` emits the RDATA with the signature field
  omitted, which is the first thing fed to the hash (RFC 4034 3.1.8.1);
  assembling the canonical RRset that follows it is left to the caller, since
  this library does not model DNS RRsets. The public key stays in its DNS
  encoding here and is converted only by `CDnssecKeys`, because the two can
  fail independently -- RDATA can be perfectly well-formed and still hold a
  key for an algorithm this library has no implementation of, while the key
  tag and the DS digest are computed over the raw RDATA either way.
- **`dnssec/keys.hpp` / `src/dnssec/keys.cpp`** define `CDnssecKeys`, which is
  the re-encoding layer. RSA (RFC 3110) writes an exponent length, the
  exponent, then the modulus, where this library wants a DER
  `SEQUENCE { INTEGER modulus, INTEGER exponent }` -- note that the two
  operands even appear in opposite order. ECDSA (RFC 6605) writes `x | y`,
  which is the SEC1 uncompressed point less its `0x04` prefix. EdDSA
  (RFC 8080) is already in the right form, and is handled by an explicit case
  rather than a default, so that an algorithm nobody has implemented is
  rejected instead of silently treated as raw. Signatures go the same way,
  and the ECDSA direction is the one that has to be careful: a DER `INTEGER`
  carries no leading zero octets, so writing `r` and `s` back out without
  left-padding each to the curve's field size would shift `s` by however many
  octets `r` was short, and RFC 6605 2 requires a fixed width.

`fromPublicKey()` has to be told the DNSSEC algorithm number rather than
inferring it, because several numbers share one key type: RSA/SHA-1,
RSA/SHA-256 and RSA/SHA-512 all carry the same RSA key and differ only in the
hash. `hasherOf()` reports `EHASH_UNKNOWN` for Ed25519 and Ed448 while still
returning true, since those hash internally as part of the signature scheme
and so have no external hash for a caller to apply first.

What this module does *not* do is verify an RRset. It converts records and
keys, computes key tags and DS digests, and hands the caller the signed
prefix; canonical RRset construction and the verification call itself are
outside it.

## Build model

CMake builds one target, `certpp` (aliased `certpp::certpp`), either as a
shared library (default) or static library via `-DCERTPP_BUILD_SHARED=OFF`.
The `__COMPILES_LIBCERTPP__` definition is `PRIVATE` (only the library's own
translation units get dllexport), while `__SHARED_LIBCERTPP__` is `PUBLIC`
so consumers linking against the shared build automatically get
dllimport-annotated declarations. See [build.md](build.md) for commands.

Hardware acceleration is split into three independent build options, matching
the unrelated instruction-set families it draws on -- disabling one never
affects the others:

- `CERTPP_DISABLE_HWACCEL_SIMD` (`OFF` by default) forces `CGf2m::mul()`/
  `CBigNum::mul()` to always use their portable schoolbook implementations,
  even on a CPU that supports the hardware instructions those functions can
  otherwise use (PCLMULQDQ, BMI2/ADX) -- see those two classes' own doc
  comments in this file's module-responsibilities section for what each
  accelerated path does and how it's gated. Since every asymmetric algorithm
  (`crypto::asyms::*`) is built on `CBigNum`/`CGf2m`, this one option covers
  RSA/DSA/ECDSA/Ed25519/Ed448/X25519/ECDH's modular exponentiation and field
  arithmetic transitively -- none of them have their own separate
  acceleration to gate.
- `CERTPP_DISABLE_HWACCEL_SHA` (`OFF` by default) forces `SHA1::transform()`/
  `SHA256::transform()` (`src/crypto/hashers/sha1.cpp`,
  `src/crypto/hashers/sha256.cpp`) to always use their portable compression
  loop instead of the x86 SHA Extensions (SHA1RNDS4/SHA1NEXTE/SHA1MSG1/
  SHA1MSG2 and SHA256RNDS2/SHA256MSG1/SHA256MSG2 respectively), gated behind
  a runtime CPUID check (`hasSha()`, CPUID leaf 7 sub-leaf 0, EBX bit 29) the
  same way `CBigNum`'s/`CGf2m`'s paths gate on their own CPUID bits. `MD5`/
  `SHA384`/`SHA512`/`SHA3-256`/`SHA3-512`/`SHAKE128`/`SHAKE256` have no accelerated path and
  are unaffected by this option -- there is no mainstream x86 hardware extension
  for MD5 or Keccak, and no widely-deployed x86 SHA-512 extension the way
  there is for SHA-1/SHA-256.
- `CERTPP_DISABLE_HWACCEL_AES` (`OFF` by default) forces `AesCore`'s block
  functions (`src/crypto/syms/aes.cpp`) to always use the portable round
  loop instead of the AES-NI instructions (AESENC/AESENCLAST/AESDEC/
  AESDECLAST/AESIMC), gated on its own runtime CPUID check (`hasAesNi()`,
  leaf 1, ECX bit 25). `DES`/`TripleDES` have no accelerated path and are
  unaffected; `ChaCha20` has one, but it is SSE2 rather than an AES extension
  and so answers to `CERTPP_DISABLE_HWACCEL_SIMD` instead -- see the
  `crypto/syms/aes.hpp` bullet above for the Equivalent Inverse Cipher
  construction the decrypt side uses.

All three settings' accelerated and portable paths are expected to produce
byte-identical results and are verified against the full test suite before
any change to either path is considered done; a separate build directory
(e.g. `build_noaccel/`) is a convenient way to keep an accelerated and a
portable-only configuration built at once without rebuilding the whole
library on every toggle, since these options -- like `CERTPP_RNG_FALLBACK`
above -- are `target_compile_definitions` switches that force a full
rebuild of `certpp` itself when changed.

## Where this will grow

`third-party/` now vendors its first dependency: `doctest` (single header,
under `third-party/doctest/`), used only by `tests/`. Its
`third-party/CMakeLists.txt` exposes each vendored dependency as its own
CMake target (`doctest` today); the root `CMakeLists.txt` only
`add_subdirectory(third-party)`s when `CERTPP_BUILD_TESTS=ON`, since
nothing outside `tests/` needs it. Everything the library itself does is
implemented from scratch and needs no dependency at all: the hashes
(`MD4`/`MD5`/`SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512`/`SHAKE128`/`SHAKE256`),
the symmetric ciphers, the asymmetric algorithms, and the big-number and
binary-field arithmetic under them. There is consequently no non-test
dependency yet and no concrete candidate for one; if a future piece of work
ever genuinely needs one, it follows the same pattern -- vendor it under its
own `third-party/<name>/` directory and add a matching target in
`third-party/CMakeLists.txt`, linked from `certpp` itself rather than gated
behind `CERTPP_BUILD_TESTS`.

Every concrete `IAsymmetric` implementation this library set out to build --
RSA, DSA, ECDSA over P-192/P-224/P-256/P-384/P-521/secp256k1/the 14
Brainpool curves/the 10 binary-Koblitz curves, Ed25519, Ed448, and X25519 --
now exists, under `include/certpp/crypto/asyms/` and `src/crypto/asyms/`,
mirroring how the concrete `IHasher` implementations
live under `crypto/hashers/` rather than next to `hasher.hpp` itself: the
singular `asym.hpp`/`hasher.hpp` file defines the interface, the plural
`asyms/`/`hashers/` directory holds one file per concrete algorithm. Tests
for a new `asyms/` implementation follow the same mirrored path under
`tests/crypto/asyms/`, exactly as `tests/crypto/hashers/` does today.
`IAsymmetric::builtIn()` (`src/crypto/asym.cpp`) dispatches each
`EAsymmetrics` value to its concrete class; a new algorithm adds one
`case` there, and its enumerator goes **immediately before `EASYM_MAX`,
never inserted in the middle**: the enum crosses an ABI boundary (this
library ships as a shared object and is consumed as an installed package),
so renumbering it leaves a caller compiled against the old header silently
selecting a different algorithm, with nothing to diagnose it. Then check
every exhaustive switch over the enum, and `CCert`'s `KEY_ALGOS`/`SIG_ALGOS`
tables and `signsMessageDirectly()` if the algorithm appears in a
certificate. RSA's key/signature DER encoding, and every future `asyms/`
implementation's, goes through `asn1::CDer` (`asn1/der.hpp`) for the
arbitrary-precision `INTEGER`s `CEncoder`/`CDecoder` don't handle -- see
its own doc comment. A future genuinely non-library-providable dependency
(there isn't one yet: RSA needed only `CBigNum`, itself built from scratch)
would follow the vendor-and-expose-a-target pattern above, instead.

`x509/` both parses and generates: `CCert`/`CCertBuilder` read and build
(and sign) a `Certificate`, `CCrlReader`/`CCrlWriter` a `CertificateList`,
`COcspRequest`/`COcspResponse` plus their builders an OCSP exchange, and
`CCertRequest`/`CCertRequestBuilder` a PKCS#10 `CertificationRequest`, all
ten extensions have a parse/build pair, and PEM as well as DER is handled
(`ECertFormat`, `importPem()`/`exportPem()`, both of which delegate to
`CPemChainFormat` -- see `x509/chain/pem.hpp` below). A new extension type follows
`x509/exts/`'s established shape (a concrete `IExtension` subclass with its
own `OID`, added to `ext.cpp`'s dispatch table, plus the matching
`IExtensionBuilder`) and, if it needs to hold a GeneralName-shaped or
list-of-value-object-shaped field, reuses
`x509/generalname.hpp`/`access.hpp`/`policy.hpp` rather than redefining
those shapes locally.

Single-link signature verification is in place: `CCert::verifyBy(issuer)`,
`CCrlReader::verifyBy(issuer)`, `CCertRequest::verify()` and OCSP's own
`verifySignature()` each answer "did this key sign this?" against the original
signed bytes (`CCert::tbsCertificate()`/`CCrlReader::tbsCertList()`/
`CCertRequest::certificationRequestInfo()` expose those bytes for a caller
that wants to do it by hand). What is still missing is the *relational* half
of X.509, deliberately scoped out for now rather than half-built:

- **Chain building and path validation** -- name chaining, validity
  windows, `BasicConstraints`/`KeyUsage`/`NameConstraints` enforcement, and
  RFC 5280's "reject an unrecognized critical extension" rule. This library
  parses and preserves everything a validator needs and enforces none of it;
  see this document's own scope note at the top. The same gap shows up on the
  CA side of PKCS#10: `CCertBuilder::subjectFrom()` hands over a verified
  request's subject and key, and deciding whether that subject name and those
  requested extensions *should* be certified is policy this library does not
  model.
