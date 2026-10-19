# 프로젝트 구조

[English](structure.md)

## 공개 API 구성

← [저장소 구성](../CONCEPTS.ko.md#세부-개념-문서)

```
include/
  certpp.hpp             # 엄브렐라 헤더. 공개 API를 다시 포함합니다
  certpp/
    common.hpp            # CERTPP_API export 매크로, 고정 폭 타입 별칭, ERetCode
    arch.hpp              # 가속 경로가 쓰는 컴파일 타임 아키텍처 관문과 런타임 CPU 기능 검사
    oid.hpp               # SRawOid/COid와 명명된 OID 중앙 표
    version.hpp            # SVersion 구조체, GetLibraryVersion() 선언
    time.hpp                # STimeSpan(기간). SDateTime: 달력 필드 시간, now()/from()/toUtc()/toLocal()/toSeconds()/add()/diff()/...
    string.hpp               # TString<T>: 소유하며 증가 가능한 문자열 버퍼 (템플릿 전용, .cpp 없음)
    name.hpp                  # CName: X.509 식별 이름(distinguished name, DN) 구성요소, ENameType
    utils/
      djb.hpp                  # CDjb: DJB 해시(평문/대소문자 무시), SDjbValue
      hex.hpp                   # CHex: 16진 문자열 -> 바이트 디코더("0x"/"0X" 접두사 선택적). CBigNum::fromHex()/CGf2m::fromHex()가 공유
      secure.hpp                 # CSecure: 컴파일러가 제거할 수 없는 영 소거, 그리고 constant-time equals()/equalsMask()/select() — 실행 시간이 입력에 의존해서는 안 되는 연산들
      base64.hpp                 # CBase64: base64 코덱. 스트리밍 push()/finish() 변환과 정적 일괄 encode()/decode() 둘 다. EBase64Mode
      json.hpp                   # CJson: JSON 값 트리, parseJson()/parseBson(), toString()/toBson()
      bignum.hpp                 # CBigNum: 임의 정밀도 음이 아닌 정수 (RSA/DSA/EC/Ed25519 연산)
      montgomery.hpp              # CMontgomery: 홀수 모듈러스 하나와 미리 계산한 Montgomery 상수들. 나눗셈 없는 mul/add/sub/dbl/neg/modExp/modExpProduct
      gf2m.hpp                    # CGf2m: 고정 용량 GF(2^m) 이진체 원소(다항식 기저). EGf2mKnownField + CGf2m::knownField()/knownFieldPtr()가 B-*/K-* 이진 곡선들이 공유하는 다섯 가지 체 크기를 지칭합니다
    io/
      span.hpp              # TSpan<T> / TReadOnlySpan<T> (템플릿 전용, .cpp 없음). SByteSpan/SReadOnlyByteSpan 별칭
      array.hpp               # TArray<T, TAllocator>: allocator를 선택하는 소유 배열. TSecureArray<T>, EArrayType (템플릿 전용, .cpp 없음)
      buffer.hpp                # CBuffer와 CSecureBuffer: 일반 또는 CSecure 기반의 크기 조절 가능 바이트 버퍼
      octet.hpp                 # COctet와 CSecureOctet: 일반 또는 CSecure 기반의 고정 크기 바이트 소유자
      stream.hpp                  # IStream 인터페이스, IStreamPtr, ESeekMode/EStreamCapability
    asn1/
      tag.hpp                # CTag (ASN.1 태그 인코드/디코드), ETagClass, EUniversalTags
      decoder.hpp             # CDecoder (TLV 디코드 + 타입별 값 디코더), EEncodingRule, EDecoderStatus
      encoder.hpp              # CEncoder (TLV 인코드 + 타입별 값 인코더, 확정 길이 형식)
      reader.hpp                # CReader: IStream(또는 span) 위의 순차 CDecoder
      writer.hpp                  # CWriter: IStream 위의 순차 CEncoder
      der.hpp                      # CDer: 임의 정밀도 INTEGER/SEQUENCE DER 보조 함수 (CBigNum 크기를 다루는 CEncoder/CDecoder 확장)
    crypto/
      hasher.hpp               # IHasher 인터페이스: reset()/push()/finish(), byteWidth()
      hashers/                   # 구체 IHasher 구현들, 파일 하나당 하나
        md4.hpp                    # MD4 (RFC 1320) — 깨진 알고리즘. NTLM/EAP-MSCHAPv2의 NT 해시 때문에만 있습니다
        md5.hpp                    # MD5 (RFC 1321)
        sha1.hpp                   # SHA-1 (FIPS 180-4)
        sha224.hpp                 # SHA-224 (FIPS 180-4) — SHA-256의 압축 함수, 자체 IV, 절단된 출력
        sha256.hpp                 # SHA-256 (FIPS 180-4)
        sha384.hpp                 # SHA-384 (FIPS 180-4)
        sha512.hpp                 # SHA-512 (FIPS 180-4)
        sha3_256.hpp                # SHA3-256 (FIPS 202): 고정 32바이트 출력과 0x06 도메인 바이트를 쓰는 Keccak 스펀지
        sha3_512.hpp                 # SHA3-512 (FIPS 202): 같은 것. 64바이트 출력, 72바이트 rate
        shake128.hpp                # SHAKE128, SHAKE256의 128비트 보안 형제 — 같은 모양, KeccakCore 공유
        shake256.hpp                # SHAKE256, Keccak/SHA-3 계열 XOF (FIPS 202). 출력 길이는 알고리즘이 아니라 생성자를 통해 인스턴스별로 고정됩니다
        blake2s.hpp                 # BLAKE2s (RFC 7693), 키 없음. 리틀엔디언 HAIFA 구성, 1–32의 digest 길이가 파라미터 블록에 묶입니다
        streebog256.hpp             # Streebog256: 256비트 해시 코드를 쓰는 GOST R 34.11-2012 (RFC 6986) — 512비트 digest를 자른 것이 아니라 자체 IV를 씁니다
        streebog512.hpp             # Streebog512: 512비트 해시 코드를 쓰는 GOST R 34.11-2012 (RFC 6986)
      keys.hpp                   # SKeySize, SKeySizeSpec, IPublicKey/IPrivateKey 인터페이스, SKeyPair. EKems/IKemKeyBase/IKemPublicKey/IKemPrivateKey/SKemKeyPair (병렬 KEM 키 계열)
      kem.hpp                     # IKem/IKemContext: asym.hpp의 KEM 대응물 — sign/verify/encrypt/decrypt 자리에 encapsulate()/decapsulate()가 옵니다. KEM은 호출자가 고른 평문을 암호화하는 것이 아니라 ciphertext와 새 비밀을 함께 만들어 내기 때문입니다
      policy.hpp                  # CAlgorithmPolicy/EAlgorithmPolicy: 중앙 기본 정책과 명시적 레거시 생성 opt-in
      kems/                        # 구체 IKem 구현들, 파일 하나당 하나 (asyms/를 반영)
        mlkem.hpp                     # CMlKem/SMlKemParams/SMlKemPoly/CMlKemSampler: 원시 span 위의 ML-KEM (FIPS 203, 포스트 양자). K-PKE와 암묵적 거부를 갖춘 FO 변환. 그리고 같은 세 파라미터 집합을 IKem으로 노출하는 MLKEM
      rng.hpp                     # IRng 인터페이스와 운영체제 기반 CSPRNG 구현 CRng
      eccurve.hpp                  # CEcCurve/SEcPoint: short-Weierstrass 점 연산(아핀 좌표). EEcKnownCurves + CEcCurve::knownCurves()가 내장 P-192/P-224/P-256/P-384/P-521/secp256k1/Brainpool(RFC 5639, 14개 곡선)과 GOST R 34.10-2012(9개 파라미터 집합, 그중 2개는 cofactor 4) 도메인 파라미터를 지칭합니다
      ec2curve.hpp                 # CEc2Curve/SEc2Point: CGf2m 위의 이진 곡선 점 연산(아핀 좌표). EEc2KnownCurves + CEc2Curve::knownCurves()가 내장 B-163/K-163 .. B-571/K-571 열 개의 도메인 파라미터를 지칭합니다
      asym.hpp                   # IAsymmetric(알고리즘 기술자/팩토리) + IAsymmetricContext(바인딩된 키로 서명/검증 + deriveSharedSecret 키 합의 + encrypter/decrypter 팩토리) + IAsymmetricTransformer(암호화/복호화 세션)
      asyms/                      # 구체 IAsymmetric 구현들, 파일 하나당 하나 (hashers/를 반영)
        rsa.hpp                     # RSA: PKCS#1 키 생성, PKCS#1 v1.5 + RSASSA-PSS (RFC 8017) 서명/검증, PKCS#1 v1.5 암호화/복호화
        dsa.hpp                      # DSA: FIPS 186-4 키 생성(도메인 파라미터 포함) + 서명/검증만
        ecdsa.hpp                     # CEcdsa: 임의의 EEcKnownCurves 값 위의 ECDSA. 키 생성 + 서명/검증 + ECDH IAsymmetricContext::deriveSharedSecret() (RFC 5903)
        ecdsa2.hpp                    # CEcdsa2: 임의의 EEc2KnownCurves 값 위의 ECDSA. 키 생성 + 서명/검증만
        ed25519.hpp                    # Ed25519: edwards25519 위의 EdDSA (RFC 8032). 키 생성 + 서명/검증만
        ed448.hpp                       # Ed448: edwards448/"Goldilocks" 위의 EdDSA (RFC 8032). 키 생성 + 서명/검증만
        x25519.hpp                      # X25519: Curve25519 위의 Diffie-Hellman 키 합의 (RFC 7748). 키 생성 + IAsymmetricContext::deriveSharedSecret()만
        gost3410.hpp                     # CGost3410: 임의의 ECURVE_GOST* 파라미터 집합 위의 GOST R 34.10-2012 (RFC 7091). 키 생성 + 서명/검증만 — 곡선만 다른 ECDSA가 아닙니다(s/검증 식이 다르고, GOST 자체의 해시-정수 변환 규칙과 RFC 9215 자체의 키/서명 바이트 순서를 씁니다)
        mldsa.hpp                         # CMlDsa: 세 파라미터 집합 전부의 ML-DSA (FIPS 204, 포스트 양자). 키 생성 + 서명/검증만. sign()/verify()가 digest가 아니라 MESSAGE를 받으며(sizeOfDigest() == 0), 빈 context를 쓰는 FIPS 204 외부 인터페이스를 구현합니다. 그것이 RFC 9881의 id-ml-dsa-* OID가 뜻하는 것입니다
      transform.hpp                # ITransformer: IAsymmetricTransformer와 ISymmetricTransformer가 공유하는 범용 스트리밍 변환 인터페이스
      sym.hpp                      # ISymmetric(알고리즘 기술자/팩토리) + ISymmetricContext(바인딩된 키로 encrypter/decrypter 팩토리) + ISymmetricTransformer
      syms/                        # 구체 ISymmetric 구현들, 파일 하나당 하나 (asyms/를 반영)
        aes.hpp                        # AES: FIPS-197 키 생성(128/192/256비트) + CBC 암호화/복호화. ISymmetricContext::padding()에 따라 PKCS#7 padding 있음 또는 없음
        aria.hpp                       # ARIA: RFC 5794 키 생성(128/192/256비트) + CBC 암호화/복호화. 같은 padding 모드를 사용합니다
        des.hpp                         # DES: FIPS 46-3 키 생성(64비트) + CBC/PKCS#7 암호화/복호화 — 레거시/상호운용 전용
        des3.hpp                         # TripleDES: 2키/3키 EDE 키 생성 + CBC/PKCS#7 암호화/복호화. DES 자체의 블록 코어 위에 구현
        chacha20.hpp                      # ChaCha20: RFC 8439 스트림 암호. 키 생성 + 암호화/복호화 (어느 쪽이든 같은 XOR 연산)
      hmac.hpp                     # CHmac: 임의의 IHasher 위의 HMAC (RFC 2104). constant-time verify()를 갖추고 있습니다 — tag를 memcmp로 비교하면 일치하는 접두사의 길이가 누출되어 위조 oracle이 됩니다
      blake2smac.hpp                # CBlake2sMac: BLAKE2s 자체의 키 모드 (RFC 7693 2.6). HMAC-BLAKE2s가 아닙니다 — 키가 HMAC의 2패스 구성을 거치지 않고 파라미터 블록에 들어갑니다
      siphash.hpp                   # CSipHash: SipHash-2-4. 짧은 입력용 키 PRF — RFC 9018의 DNS 서버 쿠키, 그리고 해시 테이블 키잉용입니다. 범용 MAC이 아닙니다
      poly1305.hpp                 # CPoly1305: RFC 8439 일회용 MAC. 스트리밍 push()/finish() + 일괄 compute()
      hkdf.hpp                      # CHkdf: CHmac이 지원하는 임의의 해시 위의 HKDF (RFC 5869) extract/expand/derive — 이미 충분한 엔트로피를 가진 입력용이고, 의도적으로 저렴합니다
      pbkdf2.hpp                     # CPbkdf2: PBKDF2 (RFC 8018 5.2) derive() — 비밀번호용이고, 의도적으로 저렴하지 않습니다. CHkdf와 교체 가능하지 않습니다
      aeads/                       # AEAD들: 각각 seal()/open() 쌍 하나. ISymmetric 표면의 일부가 아닙니다(그쪽에는 AAD나 tag를 둘 자리가 없습니다)
        chacha20poly1305.hpp           # CChaCha20Poly1305: RFC 8439 2.8. 256비트 키, 96비트 nonce, 128비트 tag
        xchacha20poly1305.hpp            # CXChaCha20Poly1305: draft-irtf-cfrg-xchacha. 256비트 키, 192비트 nonce — 96비트짜리와 달리 무작위로 고를 만큼 깁니다
        aesgcm.hpp                      # CAesGcm: NIST SP 800-38D. 128/192/256비트 키, 96비트 IV, 96–128비트 tag
    x509/
      ext.hpp                    # IExtension: 디코드된 확장의 구체 기반(oid()/value()), IExtensionPtr, IExtension::create() OID 디스패치 팩토리
      generalname.hpp             # CGeneralName (GeneralName CHOICE, RFC 5280 4.2.1.6), EGeneralNameType. CGeneralSubtree (NameConstraints의 GeneralSubtree)
      policy.hpp                   # CPolicyInformation (CertificatePolicies의 PolicyInformation)
      access.hpp                    # CAccessDescription (AuthorityInformationAccess의 AccessDescription). ECrlReasons, CDistributionPoint (CRLDistributionPoints의 DistributionPoint)
      exts/                          # 구체 IExtension 구현들, 파일 하나당 하나. 확장의 통용 약칭으로 이름을 붙였습니다
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
      cert.hpp                        # CCert: DER X.509 Certificate를 파싱합니다. EKeyUsages는 exts/ku.hpp를 통해 다시 노출됩니다. CCertBuilder: 하나를 빌드하고 자기 서명합니다
      kemspki.hpp                     # CKemSubjectPublicKeyInfo: RFC 9935 ML-KEM SubjectPublicKeyInfo 입출력
      validator.hpp                   # CTrustStore/CPathValidator와 명시적 core 검증 정책/결과/상태 타입
      crl.hpp                          # CCrlReader/CCrlWriter: DER X.509 CertificateList(CRL)를 파싱/빌드합니다. CCrlRevokationInfo: 폐기된 인증서 항목 하나
      ocsp.hpp                          # COcspRequest/COcspRequestBuilder: OCSPRequest를 파싱/빌드합니다. COcspResponse: OCSPResponse를 파싱+빌드합니다. COcspCertId(CertID), COcspEntry(SingleResponse)
      csr.hpp                            # CCertRequest/CCertRequestBuilder: PKCS#10 CertificationRequest를 파싱(자기 서명을 검증하며)/빌드+자기 서명합니다. SCertRequestAttribute: Attribute 하나. PKCS#9 extensionRequest는 extensions로 디코드됩니다
      chain.hpp                          # SCertEntry/CCertCollection: 인증서와 선택적 키, 그리고 그 둘을 짝지어 주는 PKCS#9 속성. 발급자 연결 조회와 buildChain()을 갖추고 있습니다(경로 검증은 아닙니다). IChainFormat: 컨테이너 포맷 인터페이스, EChainFormats, builtIn()/detect()
      chain/                              # 컨테이너 포맷당 IChainFormat 구현 하나. exts/가 확장 타입에 대해 갖는 것과 같은 배치입니다
        pem.hpp                            # CPemChainFormat: 이어 붙인 RFC 7468 PEM 블록들 — 그리고 이 라이브러리의 PEM 처리 전부(CCert::importPem()/exportPem()이 여기에 위임합니다). 비밀번호 없음, 암호화 없음
        pfx.hpp                             # CPfxFormat: PKCS#12/PFX (RFC 7292). PBES2/AES-256-CBC + PBKDF2 암호화, MacData HMAC 무결성
    dnssec/
      name.hpp                       # CDnsName: 표현형 <-> 정규 와이어 포맷 도메인 이름 (RFC 4034 6.2 대소문자 폴딩). 압축 포인터는 의도적으로 거부합니다
      records.hpp                     # EDnsAlgorithms/EDnsDigests (IANA 번호, 고정). SDnskey (RDATA + RFC 4034 부록 B의 키 태그), SDsRecord (RDATA + 소유자 이름 || DNSKEY RDATA에 대한 5.1.4 digest), SRrsig (RDATA + toSignedPrefix())
      keys.hpp                         # CDnssecKeys: DNSKEY <-> IPublicKey, 그리고 RRSIG 서명 <-> 이 라이브러리의 인코딩. RFC 3110/5702(RSA), 6605(ECDSA), 8080(EdDSA)에 따릅니다
```

## 구현 구성

← [저장소 구성](../CONCEPTS.ko.md#세부-개념-문서)

```
src/
  common.cpp              # 네임스페이스 뼈대 (아직 out-of-line 코드 없음)
  version.cpp              # SVersion + GetLibraryVersion() 구현
  time.cpp                 # SDateTime 구현 (<ctime>의 gmtime_s/gmtime_r, localtime_s/localtime_r 사용)
  string.cpp                # 빈 스텁 — TString<T>는 전부 템플릿이므로 넣을 것이 없습니다
  name.cpp                   # CName::reset()/compare()/equals()/toString()
  oid.cpp                    # OID 파싱, 포매팅, 비교 및 명명 OID 캐시
  utils/
    djb.cpp                    # CDjb::compute()/computeAsUpper()/computeAsLower()
    hex.cpp                     # CHex::decode()
    json.cpp                    # JSON/BSON 파싱과 직렬화, 문자열 escape 및 BSON 경계 검사
    base64.cpp                   # CBase64 스트리밍 push()/finish() + 정적 일괄 encode()/decode()
    bignum.cpp                   # CBigNum: schoolbook add/sub/mul, Knuth-D divMod, modExp/modInverse/gcd, Miller-Rabin 소수 판정 + crypto::CRng를 통한 소수 생성
    montgomery.cpp                # CMontgomery: -m^-1 mod 2^32 Newton 반복, R^2 mod m, 그리고 CBigNum의 원시 limb 위의 CIOS Montgomery 곱셈
    secure.cpp                    # CSecure 공개 facade: 제거 불가능 영 소거, 비교/선택, 잠금 할당 진입점
    securepool.hpp                # SecurePool private 선언. 설치되거나 공개 API에 포함되지 않습니다
    securepool.cpp                # large-page 우선 사용과 잠긴 표준 페이지 폴백, 정렬 블록 분할/병합 및 CSecure::zero()를 통한 재사용/반환 전 영 소거
    gf2m.cpp                      # CGf2m: XOR 덧셈, shift-and-XOR 캐리 없는 곱셈 + 워드 단위 다항식 축약, 이진 확장 유클리드 역원. 다섯 개 알려진 체의 축약 다항식은 최초 사용 시 생성되는 접근자 뒤에 있습니다(이유는 이 모듈의 doc 주석 참고)
  io/
    buffer.cpp                # CBuffer와 CSecureBuffer의 저장/크기 변경 동작
    octet.cpp                 # COctet와 CSecureOctet의 저장/해제 동작
    stream.cpp               # IStream::createMemory() 팩토리
    memstream.hpp             # MemStream: private IStream 구현. 공개 API의 일부가 아닙니다
    memstream.cpp              # MemStream 구현
  asn1/
    tag.cpp                   # CTag::decode()/encode()
    decoder.cpp                 # CDecoder::decodeLength()/readEncodedValue()/tryReadEncodedValue()
    encoder.cpp                  # CEncoder::encodeLength()/writeEncodedValue()
    reader.cpp                    # CReader 구현
    writer.cpp                     # CWriter 구현
    der.cpp                          # CDer 구현. CEncoder/CDecoder 위에 구현
  crypto/
    hasher.cpp                # 빈 스텁 — IHasher는 순수 가상 인터페이스이므로 out-of-line인 것이 없습니다
    hashers/
      md4.cpp                     # MD4 변환(16회씩 3라운드) + reset()/push()/finish()
      md5.cpp                     # MD5 변환 + reset()/push()/finish()
      sha1.cpp                    # SHA-1 변환 + reset()/push()/finish()
      sha2_32core.hpp              # Sha2_32Core::transform(): private, SHA-224/SHA-256가 공유하는 압축 함수
      sha2_32core.cpp
      sha224.cpp                    # SHA-224: 자체 컨텍스트/IV/절단, 공유 변환
      sha256.cpp                     # SHA-256: 자체 컨텍스트/IV, 공유 변환
      sha2_64core.hpp              # Sha2_64Core::transform(): private, SHA-384/SHA-512가 공유하는 압축 함수
      sha2_64core.cpp
      sha384.cpp                    # SHA-384: 자체 컨텍스트/IV/절단, 공유 변환
      sha512.cpp                     # SHA-512: 자체 컨텍스트/IV, 공유 변환
      keccakcore.hpp                  # KeccakCore: private, 모든 SHA-3/SHAKE 변종이 쓰는 공유 Keccak-f[1600] permutation + 스펀지 흡수
      keccakcore.cpp
      sha3core.hpp                     # Sha3Core: private, KeccakCore 위의 공유 SHA-3 버퍼링/padding(0x06 도메인 바이트). sha3_256.cpp/sha3_512.cpp가 사용
      sha3core.cpp
      sha3_256.cpp                      # SHA3-256: RATE=136으로 Sha3Core를 구동
      sha3_512.cpp                       # SHA3-512: RATE=72로 Sha3Core를 구동
      shake128.cpp                     # SHAKE128: RATE=168로 KeccakCore를 구동
      shake256.cpp                    # SHAKE256: RATE=136으로 KeccakCore를 구동
      blake2score.hpp                  # Blake2sCore: private, BLAKE2s 상태 기계 전체(파라미터 블록, 압축, 버퍼링, 마무리). blake2s.cpp와 blake2smac.cpp가 공유
      blake2score.cpp
      blake2s.cpp                       # BLAKE2s: 생성자의 digest 길이로, 키 없이 Blake2sCore를 구동
      streebogcore.hpp                 # StreebogCore: private, 공유 Streebog g_N 라운드 함수(S/P/L을 Pi와 A에서 최초 사용 시 유도한 8x256 테이블 하나로 합침) + mod-2^512 N/EPSILON 누산기. streebog256.cpp/streebog512.cpp가 사용. RFC 6986 바이트 순서가 적혀 있는 유일한 곳이기도 합니다
      streebogcore.cpp
      streebog256.cpp                   # Streebog-256: 자체 IV((00000001)^64), 자체 컨텍스트/padding, 최종 상태의 MSB_256을 내놓습니다
      streebog512.cpp                   # Streebog-512: 자체 IV(0^512), 자체 컨텍스트/padding, 최종 상태 전체를 내놓습니다
    keys.cpp                  # SKeySizeSpec::compare() — IPublicKey/IPrivateKey 자체는 순수 가상이고 SKeyPair는 평범한 구조체이므로, 그 외에 out-of-line인 것이 없습니다
    kem.cpp                    # IKem::builtIn(): EKems를 구체 kems/ 구현으로 디스패치
    policy.cpp                 # CAlgorithmPolicy 프로세스 전역 생성 정책
    kems/                       # 구체 IKem 구현들, 파일 하나당 하나
      mlkemring.hpp / .cpp          # MlKemRing: private, q = 3329인 R_q = Z_q[X]/(X^256 + 1). NTT/역 NTT/기본 경우 곱셈. 트위들은 옮겨 적지 않고 ZETA에서 유도합니다
      mlkemcodec.hpp / .cpp          # MlKemCodec: private, FIPS 203의 ByteEncode/ByteDecode와 Compress/Decompress, 그리고 isCanonical12() — ByteDecode_12는 mod q로 축약하므로 단사가 아니고, 그것 자체가 캡슐화 키 유효성 검사입니다
      mlkemsampler.cpp                # MlKemSampler: private, SampleNTT(SHAKE128::squeeze()의 첫 소비자)와 중심 이항 샘플러
      mlkem.cpp                        # CMlKem(원시 span 위의 K-PKE + 암묵적 거부를 갖춘 FO 변환)과 MLKEM(같은 세 집합을 IKem으로). CRng를 끌어다 쓰는 유일한 ML-KEM 계층입니다
    rng.cpp                    # IRng 도우미와 CRng::fillTo(): Windows BCryptGenRandom / Linux getrandom(2)(실패 시 /dev/urandom) / 그 외 POSIX /dev/urandom. 옵션을 켠 경우에만 std::random_device로 대체
    transform.cpp               # 빈 스텁 — ITransformer는 순수 가상 인터페이스이므로 out-of-line인 것이 없습니다
    sym.cpp                      # ISymmetric::builtIn() 팩토리 디스패치
    syms/
      symkey.hpp                     # SymRawKey: private, 공유 원시 바이트 ISymmetricKey (길이 외에는 검증하지 않습니다)
      cbctransformer.hpp              # CbcTransformer: private, 공유 CBC 모드 버퍼링+체이닝+padding(ESymPaddings에 따라 PKCS#7 또는 없음). aes.cpp/aria.cpp/des.cpp/des3.cpp가 사용
      cbctransformer.cpp
      aescore.hpp                      # AesCore: private, 공유 AES 블록 암호(자체 S-box/키 스케줄, CERTPP_DISABLE_HWACCEL_AES 뒤의 AES-NI/VAES 경로). aes.cpp/aeads/aesgcm.cpp가 사용
      aescore.cpp
      aes.cpp                          # AES: AesCore + CbcTransformer
      ariacore.hpp                     # AriaCore: private ARIA 블록 암호(S-box, 확산, 키 스케줄)
      ariacore.cpp
      aria.cpp                         # ARIA: AriaCore + CbcTransformer
      descore.hpp                      # DesCore: private, 공유 DES 블록 암호(키 스케줄 + Feistel 네트워크). des.cpp/des3.cpp가 사용
      descore.cpp
      des.cpp                           # DES: DesCore + CbcTransformer
      des3.cpp                          # TripleDES: TripleDesCore(DesCore 위의 DES-EDE3 합성) + CbcTransformer
      chacha20.cpp                      # ChaCha20: 밑바닥부터 구현한 quarter-round/블록 함수 + 키스트림 XOR 변환기
      chacha20core.hpp                   # ChaCha20Core: private, 공유 ChaCha20 블록 함수. chacha20.cpp/aeads/chacha20poly1305.cpp가 사용
      chacha20core.cpp
    hmac.cpp                     # CHmac 구현: 임의의 IHasher 위의 ipad/opad 2패스 구성. verify()는 CSecure::equals()를 거칩니다
    blake2smac.cpp                # CBlake2sMac 구현: 키를 파라미터 블록에 넣고 키 블록을 먼저 흡수시켜 Blake2sCore를 구동
    siphash.cpp                    # CSipHash 구현: 2라운드 압축 / 4라운드 마무리, 리틀엔디언 워드 적재
    hkdf.cpp                        # CHkdf 구현: CHmac 위의 extract-then-expand
    pbkdf2.cpp                       # CPbkdf2 구현: HMAC을 반복 횟수만큼 접는 PBKDF2 — 반복 횟수가 요점 전체이므로, 저렴해지도록 만들어서는 안 되는 유일한 코드입니다
    poly1305.cpp                 # CPoly1305 구현 (26비트 limb 위의 130비트 누산기)
    aeads/
      chacha20poly1305.cpp           # CChaCha20Poly1305: ChaCha20Core + CPoly1305, RFC 8439 2.8의 프레이밍
      ghash.hpp                       # Ghash: private GHASH + GCM의 GF(2^128) 곱셈(비트 반전. CERTPP_DISABLE_HWACCEL_SIMD 뒤의 PCLMULQDQ와 4블록 집계). aesgcm.cpp만 사용
      ghash.cpp
      xchacha20poly1305.cpp             # CXChaCha20Poly1305: HChaCha20이 nonce의 앞 16바이트에서 부분키를 유도하고, 남은 8바이트로 ChaCha20-Poly1305를 수행합니다 — 192비트 nonce가 부분키 유도 외에 아무 비용도 들지 않는 이유입니다
      aesgcm.cpp                       # CAesGcm: AesCore(카운터 모드) + Ghash, SP 800-38D 7.1의 프레이밍
    eccurve.cpp                  # CEcCurve/SEcPoint 구현, 그리고 CEcCurve::_knownCurves의 정의(P-192/P-224/P-256/P-384/P-521/secp256k1/Brainpool과 GOST R 34.10-2012 도메인 파라미터, EEcKnownCurves 순서로 — GOST 것들은 RFC 4357/7091/7836/9215에서 파싱해 하드코딩 전에 곡선 위에 있는지와 위수를 기계로 확인했습니다)
    ec2curve.cpp                 # CEc2Curve/SEc2Point 구현, 그리고 CEc2Curve::_knownCurves의 정의(10개 B-*/K-* 도메인 파라미터, EEc2KnownCurves 순서로 — 각각 하드코딩 전에 곡선 위에 있는지와 위수를 독립적으로 검증했습니다. 이 모듈의 doc 주석 참고)
    asym.cpp                   # IAsymmetric::builtIn(): EAsymmetrics를 구체 asyms/ 구현으로 디스패치
    asyms/                       # 구체 IAsymmetric 구현들, 파일 하나당 하나
      rsa.cpp                      # RSA 구현, 그리고 private RsaPublicKey/RsaPrivateKey/RsaContext/RsaTransformer 클래스들
      dsa.cpp                      # DSA 구현, 그리고 private DsaPublicKey/DsaPrivateKey/DsaContext 클래스들
      ecdsa.cpp                     # CEcdsa 구현(EcContext::deriveSharedSecret(), 소수 곡선 ECDH 포함), 그리고 private EcPublicKey/EcPrivateKey/EcContext 클래스들
      ecdsa2.cpp                    # CEcdsa2 구현, 그리고 private Ec2PublicKey/Ec2PrivateKey/Ec2Context 클래스들
      fe25519.hpp                    # Fe25519: private, 기수 2^25.5의 부호 있는 열 개 limb로 표현한 GF(2^255 - 19) — constant-time이고 나눗셈이 없습니다. ed25519.cpp와 x25519.cpp가 공유
      fe25519.cpp
      ed25519.cpp                    # Ed25519 구현(Fe25519 위의 edwards25519 점 연산, CBigNum 위의 mod L 스칼라 연산, EdDSA 로직), 그리고 private EdPublicKey/EdPrivateKey/EdContext 클래스들
      ed448.cpp                       # Ed448 구현(edwards448 체/점 연산, SHAKE256 기반 EdDSA 로직), 그리고 자체 private EdPublicKey/EdPrivateKey/EdContext 클래스들
      x25519.cpp                       # X25519 구현(Fe25519 위의 Montgomery ladder Curve25519 스칼라 곱, RFC 7748), 그리고 private X25519PublicKey/X25519PrivateKey/X25519Context 클래스들
      gost3410.cpp                      # CGost3410 구현, 그리고 private GostPublicKey/GostPrivateKey/GostContext 클래스들
      mldsa.cpp                          # CMlDsa 구현, 그리고 private MlDsaPublicKey/MlDsaPrivateKey/MlDsaContext 클래스들. CRng를 끌어다 쓰는 유일한 ML-DSA 계층입니다
      mldsaring.hpp / .cpp                # MlDsaRing: private, q = 8380417인 R_q = Z_q[X]/(X^256 + 1). 완전한 8단 NTT
      mldsarounding.hpp / .cpp             # MlDsaRounding: private, FIPS 204 7.4의 Power2Round/Decompose/MakeHint/UseHint
      mldsacodec.hpp / .cpp                 # MlDsaCodec: private, FIPS 204 7.1–7.2의 비트 패킹과 hint 인코딩
      mldsasampler.hpp / .cpp                # MlDsaSampler: private, FIPS 204 7.3의 거부 샘플러들과 Expand* 절차
      mldsaparams.hpp                         # MlDsaParams: private, 모든 길이를 유도한 FIPS 204 표 1의 세 파라미터 집합
      mldsascheme.hpp / .cpp                   # MlDsaScheme: private, 원시 span 위의 ML-DSA 자체 — 7.2 인코더와, 내부·외부 양쪽 형태의 KeyGen/Sign/Verify
  x509/
    ext.cpp                    # UnknownExtension(대체 IExtension) + IExtension::create()의 OID 디스패치 테이블
    generalname.cpp             # CGeneralName::decode()/decodeList() (GeneralName CHOICE 파싱)
    access.cpp                   # CDistributionPoint::decode()/encode()
    policy.cpp                    # CPolicyInformation::encode() — policy.hpp가 선언하는 유일한 out-of-line 멤버
    crlreason.hpp                  # CrlReasonCodec: private, RFC 5280 5.3.1의 CRLReason ENUMERATED 값과 ECrlReasons 플래그 비트를 상호 변환(의도적으로 1:1 대응이 아닙니다)
    crlreason.cpp
    ocspcodec.hpp                   # OcspCodec: private, 요청/응답과 그 빌더들이 공유하는 OCSP 와이어 보조 함수(nonce와 basic-response OID, 단일 확장 목록, GeneralizedTime)
    ocspcodec.cpp
    exts/                          # exts/ 헤더당 .cpp 하나, 같은 약칭 파일명
      bc.cpp, ku.cpp, eku.cpp, san.cpp, ski.cpp, aki.cpp, cdp.cpp, aia.cpp, cp.cpp, nc.cpp
    cert.cpp                        # CCert 구현: importDer()/importPem()/importFrom(), 지연 평가 publicKey()/privateKey(), extension<T>() 호출자들. CCertBuilder::build()/subjectFrom(). 그리고 crl.cpp/ocsp.cpp/csr.cpp가 friend로 접근하는 공유 encode/decode/sign/verify static들
    kemspki.cpp                     # RFC 9935 ML-KEM SubjectPublicKeyInfo codec
    validator.cpp                   # 명시적 신뢰 저장소 기반 X.509 core 경로 검증
    crl.cpp                          # CCrlReader/CCrlWriter/CCrlRevokationInfo 구현. CCert 자체의 private encodeName()/encodeTime()/readTime()/resolveSigAlgoForSigning() 위에 구현(friend 접근)
    ocsp.cpp                          # COcsp*/CCert friend 접근 구현 (RFC 6960). CCert 자체의 UTCTime|GeneralizedTime CHOICE 보조 함수와 구분되는, 자체 파일 지역 GeneralizedTime 전용 시간 인코드/디코드를 가집니다
    csr.cpp                            # CCertRequest/CCertRequestBuilder 구현 (RFC 2986). 전부 CCert 자체의 encodeName()/encodeAlgorithmIdentifier()/encode+decodeSubjectPublicKeyInfo()/encodeExtensions()/parseExtensions()/signTbs()/verifySignedBlob() 위에 구현(friend 접근). Attributes SET을 위한 자체 X.690 11.6 SET-OF 정렬
    chain.cpp                          # SCertEntry/CCertCollection 구현(조회, buildChain(), verifyLinks(), checkKeyPairing()) + IChainFormat::detect()/builtIn(). 어떤 컨테이너 포맷이 존재하는지 아는 유일한 곳입니다
    chain/                              # chain/ 헤더당 .cpp 하나
      pem.cpp                           # CPemChainFormat 구현: 캡슐화 경계 스캔, 레이블, base64 프레이밍, PKCS#9 "Bag Attributes", 그리고 SEC1/PKCS#8/RFC 8410 개인키 블록 인코딩
      pfx.cpp                             # CPfxFormat 구현. 파일 지역 PBES2 파싱/빌드, RFC 7292 부록 B의 KDF(MAC 키 전용), 그리고 UTF-8 <-> BMPString 비밀번호/friendlyName 변환
  dnssec/
    name.cpp                    # CDnsName 구현. walk() 하나를 공유하므로 어느 연산에서 걸렸든 잘못된 이름이 동일하게 거부됩니다
    records.cpp                  # SDnskey/SDsRecord/SRrsig 구현. 빅엔디언 필드 보조 함수(옆집 Poly1305/ChaCha20과 달리 — 그쪽은 리틀엔디언입니다)
    keys.cpp                      # RSA/ECDSA/EdDSA와 RFC 9558 GOST 2012용 CDnssecKeys 구현. RSA 방향은 지수/모듈러스 필드 순서도 바꿉니다
```

## 이름 및 고유 이름

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

- **`name.hpp` / `src/name.cpp`**는 `CName`을 정의합니다. X.509 식별 이름의
  구성요소 하나(예: `CN=...` 하나 또는 `OU=...` 하나)와 `ENameType`입니다.
  여섯 개 기본 X.520 타입(`ENAME_CN`/`ENAME_OU`/`ENAME_O`/`ENAME_L`/
  `ENAME_ST`/`ENAME_C`), 그 다음 `ENAME_OI`(`organizationIdentifier`, 2.5.4.97
  — ETSI EN 319 412. EU 규제 인증서에서 일상적입니다), `ENAME_SERIAL`,
  `ENAME_TITLE`, `ENAME_GN`, `ENAME_SURNAME`, `ENAME_PSEUDONYM`,
  `ENAME_DNQ`, `ENAME_DC`이고, 전부 `ENAME_MAX`로 경계가 지어집니다. 이
  값들은 shared 라이브러리 ABI 경계를 넘으므로, 새 타입은 `ENAME_MAX` 바로
  앞에 *추가*되고 절대 삽입되지 않습니다 — 삽입하면 더 오래된 헤더로
  컴파일된 호출자에게 그 뒤의 모든 enumerator가 조용히 밀립니다. 같은
  `ENAME_MAX`가 `TYPE_KEYS`/`TYPE_LABELS`/`TYPE_OIDS`의 크기를 정하는데,
  선언된 크기보다 초기화자가 적은 C++ 배열은 한마디 없이 컴파일되며 꼬리를
  기본 생성된 상태로 남깁니다. 그래서 `tests/name.cpp`는 `ENAME_NONE + 1`부터
  `ENAME_MAX`까지 모든 enumerator를 훑으며 세 테이블 각각에 항목이 있기를
  요구합니다. 내용은 ASCII로 기대합니다. `reset()`(private — `CName(ENameType,
  const char*, size_t limit)` 생성자에서만 호출됩니다)은 저장할 때 127보다 큰
  바이트를 앞에 `\`를 붙여 escape하며, 이는 `ENameType`과 같은 `uint16_t`에
  담긴 `FLAG_ESCAPED` 비트로 추적됩니다(`type()`이 다시 mask로
  떼어냅니다). `toString(out, escaped)`은 기본적으로(`escaped=false`) escape를
  되돌려 원래 바이트로 돌려놓거나, `escaped=true`일 때는 원시 내부(여전히
  escape된) 형태를 반환합니다 — `CString`/`CWideString`에 대해
  오버로드되어 있고, 새 `TString<U>`를 반환하는 `toString<U>(escaped)` 편의
  템플릿도 있습니다. `CName::keyOf()`/`labelOf()`(정적)와
  `key()`/`label()`(멤버)은 `TYPE_KEYS`/`TYPE_LABELS` 테이블을 통해 타입을 그
  DN 속성 키(`"CN"`, `"OU"`, ...)와 사람이 읽을 수 있는
  레이블(`"Common Name"`, ...)로 매핑합니다.
  `attributeOid()`/`attributeTypeOf()`(정적)는 `TYPE_OIDS` 테이블을 통해
  타입을 그 DN 속성 OID arc와 상호 매핑하며(예: `ENAME_CN` <-> `{2, 5, 4, 3}`),
  `asn1` 모듈이 `CDistinguishedName`의 구성요소를 인코드/디코드하는 데
  씁니다(아래 참고). 그 테이블은 평평한 `[4]` 행이 아니라 타입당
  `SAttributeOid { count, arcs[MAX_OID_ARCS] }`인데, `ENAME_DC`의
  OID(`0.9.2342.19200300.100.1.25`, RFC 4519)가 2.5.4 `attributeType` arc
  밖에 있는 유일하게 인식되는 속성이고 arc가 10개나 되기 때문입니다.
  `typeOf()`는 `strlen(key) + 1` 바이트를 비교하므로 테이블 키 자신의 NUL이
  비교에 참여합니다. `strlen(key)`만 비교하면 조회가 *접두사* 일치가 되고,
  `"organizationIdentifier"`가 `ENAME_O`로 해석되었습니다.
  `compare()`는 먼저 `type()`으로, 그 다음 내용으로 정렬합니다.
  `equals()`/`operator==`는 정확한 `memcmp` 앞에 `type()` + 미리 계산된
  `CDjb::computeAsLower()` 해시(`hash()`로 노출됨) + 길이를 사전 검사하므로,
  대부분의 불일치는 데이터를 전혀 건드리지 않고 단축 평가로 끝납니다. 복사
  생성자/대입은 `_data`/`_len`/`_hash`/`_type`을 그대로 깊은 복사합니다
  (`reset()`을 거치지 않고 직접 인라인했고, 공유 private 보조 함수로 빼지 않고
  둘에 중복해 두었습니다. 각각 몇 줄에 불과하기 때문입니다) — 여기서
  `other._data`로 `reset()`을 호출하는 것은 잘못입니다. `other._data`에는 이전
  `reset()`에서 온 escape 표시가 이미 들어 있을 수 있고 `reset()`의 escape
  로직은 그것을 원시 입력과 구별할 수 없으므로, 이미 escape된 바이트를 그대로
  복사하는 대신 그 앞에 *새* 백슬래시를 붙일 것입니다(비-ASCII 내용을 가진
  `CName`이 `CDistinguishedName`의 `std::map`을 통해 복사된 뒤 이 프로젝트가
  실제로 겪은 버그이고, 복사가 거듭될수록 누적되었습니다). 이동
  생성/대입은 먼저 `this`를 지우고 소유권을 가져오는 대신 들어오는 값과
  상태를 swap합니다(멤버별로 수식 없는 `swap()`이고 `std::swap`으로
  해석됩니다 — 아래 `common.hpp`의 설명 참고). 이 프로젝트의 표준 이동 대입
  관례이며, `COctet`과 `TString<T>`도 같은 패턴을 따릅니다.
- **`name.hpp` / `src/name.cpp`**는 `CDistinguishedName`도 정의합니다.
  `CName` 구성요소들의 순서 있는 컬렉션(`std::map<ENameType, CName>`.
  타입당 최대 하나)입니다. `trySet()`/`tryGet()`/`has()`/`keys()`가 map을
  관리합니다. `compare()`는 *어느 쪽* DN에든 존재하는 구성요소 타입들을
  `ENameType` 오름차순으로 훑으며, 둘이 공통으로 가진 쌍을 먼저
  비교하고(`CName::compare()`를 통해), 남은 동점은 어느 DN이 상대에게 없는
  구성요소를 더 가졌는지로 가릅니다(서수가 더 낮은 추가 구성요소를 가진 DN이
  뒤로 정렬됩니다). `toString(out, escaped)`은 map의 (타입 오름차순) 순회
  순서로 `"key1=value1, key2=value2"`를 렌더링합니다.
  `tryParse(out, s)`(정적. `CString`/`CWideString`에 대해 오버로드)는 바로 그
  `"key1=value1, key2=value2"` 모양을 새 DN으로 되돌려 파싱합니다. 최상위
  `,`로 나누고, 각 구성요소를 첫 `=`로 나누고, 양쪽의 공백을 다듬고,
  `CName::typeOf()`로 키를 해석하고(대소문자 무시), 결과를
  `overwrite=true`로 `trySet()`합니다(그래서 반복된 키는 마지막 것이
  남습니다). 잘못된 구성요소(`=`가 없음, 비었거나 인식되지 않는 키)가 하나라도
  있으면 전체 파싱이 실패하고 `out`을 비워 둡니다. 와이드 오버로드는 좁은
  조회/`CName` 생성을 하기 전에 다듬은 각 키/값을
  `TString<T>::convertTo<char>()`로 변환합니다. `CName`은 항상 좁은(escape될
  수 있는) 바이트만 저장하기 때문입니다. `out`은 null/빈 입력 검사보다도
  먼저 항상 비워지므로, 그 지점 이후에 도달하는 경로만이 아니라 모든 실패
  경로가 그것을 비워 둡니다.
