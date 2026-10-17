# Project structure

[한국어](structure.ko.md)

## Public API layout

← [Repository layout](../CONCEPTS.md#detailed-concept-pages)

```
include/
  certpp.hpp             # umbrella header, re-includes the public API
  certpp/
    common.hpp            # CERTPP_API export macro, fixed-width type aliases, ERetCode
    arch.hpp              # compile-time architecture gates and runtime CPU feature probes used by accelerated paths
    oid.hpp               # SRawOid/COid and the central table of named OIDs
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
      policy.hpp                  # CAlgorithmPolicy/EAlgorithmPolicy: centralized defaults and explicit legacy-generation opt-in
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
        aria.hpp                       # ARIA: RFC 5794 keygen (128/192/256-bit) + CBC encrypt/decrypt, using the same padding modes
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
      kemspki.hpp                     # CKemSubjectPublicKeyInfo: RFC 9935 ML-KEM SubjectPublicKeyInfo import/export
      validator.hpp                   # CTrustStore/CPathValidator and explicit core-validation policy/result/status types
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
```

## Implementation layout

← [Repository layout](../CONCEPTS.md#detailed-concept-pages)

```
src/
  common.cpp              # namespace scaffold (no out-of-line code yet)
  version.cpp              # SVersion + GetLibraryVersion() implementation
  time.cpp                 # SDateTime implementation (uses <ctime>'s gmtime_s/gmtime_r, localtime_s/localtime_r)
  string.cpp                # empty stub -- TString<T> is entirely templates, so there's nothing to put in it
  name.cpp                   # CName::reset()/compare()/equals()/toString()
  oid.cpp                    # OID parsing, formatting, comparison, and named-OID cache
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
    policy.cpp                 # CAlgorithmPolicy process-wide generation policy
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
      cbctransformer.hpp              # CbcTransformer: private, shared CBC-mode buffering+chaining+padding (PKCS#7 or none, per ESymPaddings), used by aes.cpp/aria.cpp/des.cpp/des3.cpp
      cbctransformer.cpp
      aescore.hpp                      # AesCore: private, shared AES block cipher (own S-box/key schedule, AES-NI/VAES paths behind CERTPP_DISABLE_HWACCEL_AES), used by aes.cpp/aeads/aesgcm.cpp
      aescore.cpp
      aes.cpp                          # AES: AesCore + CbcTransformer
      ariacore.hpp                     # AriaCore: private ARIA block cipher (S-boxes, diffusion, and key schedule)
      ariacore.cpp
      aria.cpp                         # ARIA: AriaCore + CbcTransformer
      descore.hpp                      # DesCore: private, shared DES block cipher (key schedule + Feistel network), used by des.cpp/des3.cpp
      descore.cpp
      des.cpp                           # DES: DesCore + CbcTransformer
      des3.cpp                          # TripleDES: TripleDesCore (DES-EDE3 composition over DesCore) + CbcTransformer
      chacha20.cpp                      # ChaCha20: from-scratch quarter-round/block function + keystream XOR transformer
      chacha20core.hpp                   # ChaCha20Core: private, shared ChaCha20 block function, used by chacha20.cpp/aeads/chacha20poly1305.cpp
      chacha20core.cpp
    hmac.cpp                     # CHmac implementation: the ipad/opad two-pass construction over any IHasher, with verify() going through CSecure::equals()
    blake2smac.cpp                # CBlake2sMac implementation: drives Blake2sCore with the key in the parameter block and the key block absorbed first
    siphash.cpp                    # CSipHash implementation: 2-round compression and 4-round finalization
    hkdf.cpp                       # CHkdf implementation: extract-then-expand over CHmac
    pbkdf2.cpp                     # CPbkdf2 implementation: iterated HMAC password derivation
    poly1305.cpp                 # CPoly1305 implementation (130-bit accumulator over 26-bit limbs)
    aeads/
      chacha20poly1305.cpp           # CChaCha20Poly1305: ChaCha20Core + CPoly1305, RFC 8439 2.8's framing
      ghash.hpp                       # Ghash: private GHASH + GCM's GF(2^128) multiply (bit-reflected; PCLMULQDQ and four-block aggregation behind CERTPP_DISABLE_HWACCEL_SIMD), used only by aesgcm.cpp
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
    kemspki.cpp                     # RFC 9935 ML-KEM SubjectPublicKeyInfo codec
    validator.cpp                   # explicit-trust X.509 core path validation
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
    keys.cpp                      # CDnssecKeys implementation for RSA/ECDSA/EdDSA and RFC 9558 GOST 2012; the RSA direction also swaps exponent/modulus field order
```

## Names and distinguished names

← [Modules](../CONCEPTS.md#detailed-concept-pages)

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
