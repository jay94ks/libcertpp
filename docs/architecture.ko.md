# 아키텍처

[English](architecture.md)

## 개요

`libcertpp`는 C++17 라이브러리이며, 아직 초기 단계이지만 최초의 뼈대는
넘어섰습니다. `common` 기반, `version` 모듈, `utils`
모듈(DJB 해시 유틸리티, `CHex` 16진 디코딩, `CBase64` base64, 임의 정밀도
정수인 `CBigNum`, 이진체(binary-field, GF(2^m)) 원소인 `CGf2m`, JSON 파싱과
직렬화를 위한 `CJson`), `io`
계층(span, 증가 가능한 배열, 크기 조절 가능한 작업용 바이트
버퍼(`CBuffer`), 고정 크기 소유 버퍼(`COctet`), 그리고 스트림 추상),
`net` 모듈(IPv4/IPv6/Unix-domain socket 주소와 `CSocket` 연산, OS 오류의
`ERetCode` 변환), `asn1` 모듈(태그 인코드/디코드, TLV 디코더/인코더, 순차 reader/writer 래퍼,
그리고 `CDer`의 임의 정밀도 `INTEGER`/`SEQUENCE` DER 보조 함수), `crypto`
모듈, `x509` 모듈, 그리고 `dnssec` 모듈이 있습니다.

`crypto`에는 다음이 있습니다. 밑바닥부터 구현한 MD4/MD5/SHA-1/SHA-224/
SHA-256/SHA-384/SHA-512/SHA3-256/SHA3-512/SHAKE128/SHAKE256/BLAKE2s/
Streebog-256/Streebog-512 구현을 갖춘 `IHasher` 인터페이스. CSPRNG
유틸리티(`CRng`). 여덟 개의 구체 구현을 갖춘 `IAsymmetric` 인터페이스
(RSA — PKCS#1 v1.5와 RSASSA-PSS 서명/검증, PKCS#1 v1.5 암호화/복호화.
DSA. `CEcdsa`, NIST P-192/P-224/P-256/P-384/P-521, secp256k1, 또는 14개
Brainpool 곡선(RFC 5639) 중 어느 것 위의 ECDSA와, 같은 곡선들 위의 ECDH 키
합의(RFC 5903 / SP 800-56A). `CEcdsa2`, 10개 NIST 이진/Koblitz 곡선
B-163/K-163 .. B-571/K-571 위의 ECDSA. `Ed25519`/`Ed448`, EdDSA
(RFC 8032). `X25519`, Diffie-Hellman 키 합의(RFC 7748). 그리고
`CGost3410`, 아홉 개 파라미터 집합 중 어느 것 위의 GOST R 34.10-2012
(RFC 7091)). 네 개의 구체 구현을 갖춘 `ISymmetric` 인터페이스(`AES`,
`DES`, `TripleDES` — 모두 CBC, PKCS#7 padding 있음 또는 없음 — 그리고
`ChaCha20` 스트림 암호). 그리고 그 인터페이스 밖의 AEAD 셋,
`CChaCha20Poly1305`(RFC 8439 2.8), `CXChaCha20Poly1305`
(draft-irtf-cfrg-xchacha), `CAesGcm`(NIST SP 800-38D) — 모두 밑바닥부터이고
제3자 의존성은 없습니다.

`x509`는 DER로 인코딩된 `Certificate`(`CCert`/`CCertBuilder`),
`CertificateList`/CRL(`CCrlReader`/`CCrlWriter`), OCSP 요청/응답
(RFC 6960. `COcspRequest`/`COcspRequestBuilder`, `COcspResponse`/
`COcspResponseBuilder`)을 파싱하며(`CCert`의 경우 빌드/자기 서명도 합니다),
더해서 `x509/exts/` 아래에 열 개의 구체 `IExtension` 타입
(BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAlternativeName,
SubjectKeyIdentifier, AuthorityKeyIdentifier, CRLDistributionPoints,
AuthorityInformationAccess, CertificatePolicies, NameConstraints)이
있습니다. 링크 하나 단위의 서명 검증은 셋 모두에 있지만
(`CCert::verifyBy(issuer)`, `CCrlReader::verifyBy(issuer)`,
`COcspRequest`/`COcspResponse::verifySignature()`), 그 위에 체인 검증 /
경로 구축 엔진은 없습니다 — 이름 연결, 유효 기간,
BasicConstraints/KeyUsage/NameConstraints 강제가 없습니다. 아래 "이것이
자라날 곳"을 보십시오.

인증서와 그 키는 컨테이너로 담을 수 있습니다. `x509/chain.hpp`의
`CCertCollection`이 그것들을 짝지어 주는 PKCS#9 속성과 함께 보유하고
발급자 연결로 정렬하며(다시 말하지만 이는 검증이 아닙니다),
`IChainFormat`이 그 컬렉션을 파일로 읽고 씁니다. `x509/chain/pfx.hpp`가
PBES2와 `MacData` HMAC 위에 PKCS#12/PFX를 구현합니다.

공개 API 표면은 [`include/certpp/`](../include/certpp/) 아래 헤더 기반이며,
엄브렐라 헤더 [`include/certpp.hpp`](../include/certpp.hpp)를 통해 다시
노출됩니다 — 모든 공개 헤더가 거기 포함되어 있으므로, 소비자는
`#include <certpp.hpp>` 하나만으로 됩니다. 구현 파일은
[`src/`](../src/) 아래에 있고 자신이 구현하는 헤더를 반영합니다(예:
`include/certpp/version.hpp` <-> `src/version.cpp`).

```
include/
  certpp.hpp             # 엄브렐라 헤더. 공개 API를 다시 포함합니다
  certpp/
    common.hpp            # CERTPP_API export 매크로, 고정 폭 타입 별칭, ERetCode
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
      montgomery.hpp              # CMontgomery: 홀수 모듈러스 하나와 미리 계산한 Montgomery 상수들. EC 체 연산을 위한 나눗셈 없는 mul/add/sub/dbl/neg/modExp
      gf2m.hpp                    # CGf2m: 고정 용량 GF(2^m) 이진체 원소(다항식 기저). EGf2mKnownField + CGf2m::knownField()/knownFieldPtr()가 B-*/K-* 이진 곡선들이 공유하는 다섯 가지 체 크기를 지칭합니다
    io/
      span.hpp              # TSpan<T> / TReadOnlySpan<T> (템플릿 전용, .cpp 없음). SByteSpan/SReadOnlyByteSpan 별칭
      array.hpp               # TArray<T>: 소유하며 증가 가능한 배열 (템플릿 전용, .cpp 없음). EArrayType
      buffer.hpp                # CBuffer: 소유하며 크기 조절 가능한 원시 바이트 버퍼 — COctet 결과를 만들어 내는 작업용 버퍼
      octet.hpp                 # COctet: 소유하는 고정 크기 바이트 버퍼
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
      kems/                        # 구체 IKem 구현들, 파일 하나당 하나 (asyms/를 반영)
        mlkem.hpp                     # CMlKem/SMlKemParams/SMlKemPoly/CMlKemSampler: 원시 span 위의 ML-KEM (FIPS 203, 포스트 양자). K-PKE와 암묵적 거부를 갖춘 FO 변환. 그리고 같은 세 파라미터 집합을 IKem으로 노출하는 MLKEM
      rng.hpp                     # CRng: CSPRNG 유틸리티 (OS API, std::random_device 대체)
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
src/
  common.cpp              # 네임스페이스 뼈대 (아직 out-of-line 코드 없음)
  version.cpp              # SVersion + GetLibraryVersion() 구현
  time.cpp                 # SDateTime 구현 (<ctime>의 gmtime_s/gmtime_r, localtime_s/localtime_r 사용)
  string.cpp                # 빈 스텁 — TString<T>는 전부 템플릿이므로 넣을 것이 없습니다
  name.cpp                   # CName::reset()/compare()/equals()/toString()
  utils/
    djb.cpp                    # CDjb::compute()/computeAsUpper()/computeAsLower()
    hex.cpp                     # CHex::decode()
    json.cpp                    # JSON/BSON 파싱과 직렬화, 문자열 escape 및 BSON 경계 검사
    base64.cpp                   # CBase64 스트리밍 push()/finish() + 정적 일괄 encode()/decode()
    bignum.cpp                   # CBigNum: schoolbook add/sub/mul, Knuth-D divMod, modExp/modInverse/gcd, Miller-Rabin 소수 판정 + crypto::CRng를 통한 소수 생성
    montgomery.cpp                # CMontgomery: -m^-1 mod 2^32 Newton 반복, R^2 mod m, 그리고 CBigNum의 원시 limb 위의 CIOS Montgomery 곱셈
    secure.cpp                    # CSecure: 최적화기가 지울 수 없는 영 소거, 그리고 constant-time 비교/선택 프리미티브 — volatile 쓰기와 mask 연산이고, 파일 어디에도 비밀에 대한 분기가 없습니다
    gf2m.cpp                      # CGf2m: XOR 덧셈, shift-and-XOR 캐리 없는 곱셈 + 워드 단위 다항식 축약, 이진 확장 유클리드 역원. 다섯 개 알려진 체의 축약 다항식은 최초 사용 시 생성되는 접근자 뒤에 있습니다(이유는 이 모듈의 doc 주석 참고)
  io/
    buffer.cpp                # CBuffer::store()/resize()
    octet.cpp                 # COctet::store()/clear()/secureClear()
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
    kems/                       # 구체 IKem 구현들, 파일 하나당 하나
      mlkemring.hpp / .cpp          # MlKemRing: private, q = 3329인 R_q = Z_q[X]/(X^256 + 1). NTT/역 NTT/기본 경우 곱셈. 트위들은 옮겨 적지 않고 ZETA에서 유도합니다
      mlkemcodec.hpp / .cpp          # MlKemCodec: private, FIPS 203의 ByteEncode/ByteDecode와 Compress/Decompress, 그리고 isCanonical12() — ByteDecode_12는 mod q로 축약하므로 단사가 아니고, 그것 자체가 캡슐화 키 유효성 검사입니다
      mlkemsampler.cpp                # MlKemSampler: private, SampleNTT(SHAKE128::squeeze()의 첫 소비자)와 중심 이항 샘플러
      mlkem.cpp                        # CMlKem(원시 span 위의 K-PKE + 암묵적 거부를 갖춘 FO 변환)과 MLKEM(같은 세 집합을 IKem으로). CRng를 끌어다 쓰는 유일한 ML-KEM 계층입니다
    rng.cpp                    # CRng::fill(): Windows에서는 BCryptGenRandom / Linux에서는 getrandom(2)(실패 시 /dev/urandom) / 그 외 POSIX에서는 /dev/urandom. 사용할 수 없으면 std::random_device로 대체
    transform.cpp               # 빈 스텁 — ITransformer는 순수 가상 인터페이스이므로 out-of-line인 것이 없습니다
    sym.cpp                      # ISymmetric::builtIn() 팩토리 디스패치
    syms/
      symkey.hpp                     # SymRawKey: private, 공유 원시 바이트 ISymmetricKey (길이 외에는 검증하지 않습니다)
      cbctransformer.hpp              # CbcTransformer: private, 공유 CBC 모드 버퍼링+체이닝+padding(ESymPaddings에 따라 PKCS#7 또는 없음). aes.cpp/des.cpp/des3.cpp가 사용
      cbctransformer.cpp
      aescore.hpp                      # AesCore: private, 공유 AES 블록 암호(자체 S-box/키 스케줄, CERTPP_DISABLE_HWACCEL_AES 뒤의 AES-NI 가속 경로). aes.cpp/aeads/aesgcm.cpp가 사용
      aescore.cpp
      aes.cpp                          # AES: AesCore + CbcTransformer
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
      ghash.hpp                       # Ghash: private GHASH + GCM의 GF(2^128) 곱셈(비트 반전. CERTPP_DISABLE_HWACCEL_SIMD 뒤의 PCLMULQDQ 경로). aesgcm.cpp만 사용
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
    keys.cpp                      # CDnssecKeys 구현. RSA 방향은 필드 순서도 바꿉니다. DNS는 지수-다음-모듈러스로 쓰고 이 라이브러리의 DER는 모듈러스-다음-지수를 원하기 때문입니다
tests/
  time.cpp                  # SDateTime / STimeSpan 테스트 케이스
  string.cpp                 # TString<T> 테스트 케이스
  name.cpp                    # CName 테스트 케이스
  utils/
    djb.cpp                    # CDjb 해시 테스트 케이스
    json.cpp                    # JSON/BSON primitive, 중첩 값, 잘못된 입력, escape 및 왕복 테스트
    base64.cpp                  # CBase64 스트리밍/일괄 인코드/디코드 테스트 케이스. PEM 줄바꿈 포함
    bignum.cpp                 # CBigNum 산술/modexp/modinverse/소수 판정 테스트 케이스
    divmod.cpp                  # CBigNum::divMod()를 공개 API로 만든 비트 직렬 참조에 대해 차분 퍼징. 더해서 알고리즘 D의 add-back 분기를 위한 구성된 입력(무작위 테스트로는 도달 불가)
    montgomery.cpp               # CMontgomery를 자신이 빠른 경로가 되어 주는 CBigNum 연산들에 대해 차분 퍼징. 라이브러리가 담고 있는 모든 모듈러스(29개 곡선의 p와 n, edwards448의 p와 L)와 1–32 limb의 무작위 홀수 모듈러스에 걸쳐
    secure.cpp                   # CSecure 테스트 케이스: equals()/equalsMask()/select()를 다른 바이트 위치와 길이 전부에 대해, 그리고 zero()가 아직 스코프에 있는 버퍼에 아무것도 남기지 않는지
    gf2m.cpp                     # CGf2m 체 공리/기지 응답 벡터/인코드-디코드 테스트 케이스. 체 크기당 기지 응답 벡터 하나씩이고, 독립 Python 구현으로 교차 유도했습니다
  io/
    array.cpp                 # TArray<T> 테스트 케이스
    octet.cpp                   # COctet 테스트 케이스
    stream.cpp                    # IStream/MemStream 테스트 케이스
  asn1/
    tag.cpp                   # CTag 테스트 케이스
    decoder.cpp                 # CDecoder 테스트 케이스
    encoder.cpp                   # CEncoder 테스트 케이스
    reader.cpp                      # CReader 테스트 케이스
    writer.cpp                       # CWriter 테스트 케이스
    roundtrip.cpp                   # 인코드/디코드 통합 테스트
    der.cpp                           # CDer 테스트 케이스
    malformed.cpp                      # 적대적/음성 DER: 길이 규칙, 태그 형식, BIT STRING, INTEGER, OID, 시간 관문에 거부해야 하는 바이트를 먹입니다
  crypto/
    asyms/
      rsa.cpp                        # RSA 키 생성/DER 왕복/서명-검증/암호화-복호화 테스트 케이스
      dsa.cpp                        # DSA 키 생성/DER 왕복/서명-검증 테스트 케이스 (케이스들이 생성된 키 쌍 하나를 공유합니다 — 도메인 파라미터 생성이 비쌉니다)
      p192.cpp                       # P192 키 생성/DER 왕복/서명-검증 테스트 케이스 (케이스들이 생성된 키 쌍 하나를 공유)
      p224.cpp                       # P224: p192.cpp와 같은 범위
      p256.cpp                       # P256: p192.cpp와 같은 범위
      p384.cpp                       # P384: p192.cpp와 같은 범위
      p521.cpp                       # P521: p192.cpp와 같은 범위
      secp256k1.cpp                  # SECP256K1: p192.cpp와 같은 범위
      kat_ecdsa.cpp                   # NIST CAVP 186-4 SigVer 벡터(K-163/B-163/B-233/K-283/B-283 + P-256 대조군)에 대한 ECDSA 검증. 양성과 음성 모두 — 곡선별 왕복이 볼 수 없는 FIPS 186-4 digest 절단 규칙에 대한 외부 oracle입니다
      kat_dsa.cpp                      # NIST CAVP 186-3 SigVer 벡터(L=1024/N=160, L=2048/N=256)에 대한 DSA 검증
      kat_rsa.cpp                       # NIST CAVP 186-3 SigVer15 벡터에 대한 RSA PKCS#1 v1.5 검증
      kat_ecdh.cpp                       # RFC 5903 8.1/8.2(P-256/P-384) 벡터에 대한 소수 곡선 ECDH. 더해서 구성된 선행 0바이트 비밀(발행된 벡터들은 left-pad를 거치지 않습니다), 생성된 키들에 대한 양방향 합의, 그리고 잘못된 곡선 거부
      bpool160r1.cpp, bpool192r1.cpp, bpool224r1.cpp, bpool256r1.cpp,
      bpool320r1.cpp, bpool384r1.cpp, bpool512r1.cpp, bpool160t1.cpp,
      bpool192t1.cpp, bpool224t1.cpp, bpool256t1.cpp, bpool320t1.cpp,
      bpool384t1.cpp, bpool512t1.cpp
                                     # 14개 Brainpool 곡선(RFC 5639). 각각 p192.cpp와 같은 범위
      fe25519.cpp                    # Fe25519 테스트 케이스. 모든 연산을 CBigNum을 정확한 oracle로 삼아 확인합니다(무작위 값, 캐리 체인 경계를 전부 쌍으로, aliasing, 역원, 제곱근 대 CBigNum의 Legendre 기호) — fe25519.cpp를 자체 실행 파일로 컴파일합니다. CERTPP_TEST_PRIVATE_SOURCES 참고
      ed25519.cpp                    # Ed25519 키 생성/왕복/서명-검증 테스트 케이스. RFC 8032 7.1절의 기지 응답 벡터 다섯 개 전부 포함(빈·1·2·64·1023바이트 메시지. 서명이 결정론적이므로 정확한 바이트 일치가 파이프라인 전체를 한 번에 검증합니다)
      ed448.cpp                      # Ed448: ed25519.cpp와 같은 범위. 자체 RFC 8032 TEST 1 기지 응답 벡터 포함
      x25519.cpp                     # X25519 키 생성/왕복/deriveSharedSecret 테스트 케이스. RFC 7748 5.2의 Diffie-Hellman과 반복 스칼라 곱 기지 응답 벡터 포함(한 번 가져온 것을 그대로 옮긴 것이 아니라, 하드코딩 전에 독립 Python 구현으로 재유도했습니다)
      b163.cpp, k163.cpp, b233.cpp, k233.cpp, b283.cpp, k283.cpp,
      b409.cpp, k409.cpp, b571.cpp, k571.cpp
                                     # 10개 이진/Koblitz 곡선. 각각 p192.cpp와 같은 범위
      gost3410.cpp                   # GOST R 34.10-2012 테스트 케이스: RFC 7091 7절의 (r, s) 기지 응답, RFC 9215 부록 D의 세 테스트 인증서 종단 간(해시 + 서명 + 두 바이트 순서 모두), 아홉 파라미터 집합 전부의 서명/검증 왕복, 그리고 잘못된 키/조작된 메시지/조작된 서명/뒤바뀐 절반 음성 케이스
      mldsaring.cpp                  # MlDsaRing: 트위들 테이블을 FIPS 204 부록 B에 대조하고 ZETA에서 재유도, 완전한 8단 NTT를 schoolbook negacyclic 곱셈에 대조, centered()/infinityNorm()
      mldsarounding.cpp              # MlDsaRounding: Power2Round/Decompose/HighBits/LowBits/MakeHint/UseHint, 버킷 경계에서의 역변환 항등식, 그리고 Decompose의 (q-1) 구간
      mldsacodec.cpp                 # MlDsaCodec: SimpleBitPack/BitPack과 그 역, HintBitPack/HintBitUnpack과 그 세 가지 거부 조건 각각
      mldsasampler.cpp               # MlDsaSampler: SampleInBall/RejNTTPoly/RejBoundedPoly와 ExpandA/ExpandS/ExpandMask를 고정된 기지 응답에 대조. ExpandA의 전치된 시드 순서 포함
      mldsaparams.cpp                # MlDsaParams: 유도된 모든 길이를 FIPS 204 표 2에 대해 static_assert
      kat_mldsa.cpp                    # NIST ACVP에 대한 ML-DSA keyGen/sigGen: 결정론적(rnd = 0)과 hedged, 내부와 외부 인터페이스. 더해서 두 인터페이스가 서로 다르다는 것과 skDecode가 범위를 벗어난 s1을 거부한다는 것
      kat_mldsaver.cpp                  # NIST ACVP에 대한 ML-DSA sigVer. 네 가지 음성 사유(변형된 메시지, commitment, hint, z) 전부, 영역별 비트 뒤집기 스윕, 그리고 파라미터 집합 간 거부 포함
      mldsa.cpp                          # IAsymmetric으로서의 CMlDsa: digest가 아니라 메시지라는 관례(sizeOfDigest() == 0), 호출마다 달라지는 hedged 서명, publicKey() 재유도, 그리고 잘못된/다른 구현의 키 거부
    hashers/
      md4.cpp                    # MD4 테스트 케이스 (RFC 1320 A.5 벡터 + 문서화된 "password"의 NT 해시 + 경계/chunk 테스트)
      md5.cpp                    # MD5 테스트 케이스 (RFC 1321 벡터 + FIPS 식 스트레스/chunk 테스트)
      sha1.cpp                     # SHA-1 테스트 케이스 (FIPS 180-4 벡터)
      sha224.cpp                     # SHA-224 테스트 케이스 (FIPS 180-4 벡터. openssl과 교차 확인)
      sha256.cpp                     # SHA-256 테스트 케이스 (FIPS 180-4 벡터)
      sha384.cpp                       # SHA-384 테스트 케이스 (FIPS 180-4 벡터)
      sha512.cpp                         # SHA-512 테스트 케이스 (FIPS 180-4 벡터)
      sha3.cpp                            # SHA3-256/SHA3-512 테스트 케이스 (FIPS 202 발행 예제, rate 경계 길이, 'a' 백만 개 스트레스, chunk 무관성, 그리고 같은 출력 길이에서 SHA-3가 SHAKE와 다르다는 것)
      shake128.cpp                        # SHAKE128 테스트 케이스 (Python hashlib 벡터 + NIST CSRC가 발행한 빈 메시지 벡터 하나. hashlib과 교차 확인)
      shake256.cpp                        # SHAKE256 테스트 케이스 (Python hashlib으로 로컬 생성한 기지 응답 벡터. rate 블록 경계 케이스 포함)
      shake_squeeze.cpp                   # SHAKE128/SHAKE256 squeeze() 테스트 케이스: 1바이트부터 시작하는 모든 chunk 크기에 걸친 chunk 무관성. 각 rate 경계에 걸치는·바로 앞인·바로 뒤인 분할 포함 — 커서 off-by-one이 드러나는 유일한 곳입니다
      blake2s.cpp                         # BLAKE2s 테스트 케이스 (RFC 7693 부록 B, 256개 항목의 키 없는 참조 KAT, 1–32의 모든 digest 길이, 블록 경계 길이, chunk 무관성)
      streebog.cpp                         # Streebog-256/-512 테스트 케이스 (RFC 6986의 두 예제 메시지, 발행된 빈 메시지 digest들, chunk 무관성, 256비트 digest가 512비트 것을 자른 게 아니라는 것, 그리고 RFC 9385의 HMAC SKEYSEED — 해시 입력이 정확히 64바이트 블록의 배수인 유일하게 구할 수 있는 벡터)
      streebogcore.cpp                     # StreebogCore 테스트 케이스: Pi'가 전단사라는 것, Tau가 빠른 테이블이 의존하는 Tau(8w+t) == w+8t 항등식을 만족한다는 것, 합친 LPS 테이블이 명세를 글자 그대로 3패스로 읽은 것과 일치한다는 것, 그리고 mod-2^512 누산기가 올바르게 캐리한다는 것
    kems/
      mlkemring.cpp                 # MlKemRing: 트위들 테이블을 ZETA에서 재유도, 정방향-역방향 NTT 왕복, NTT 영역 곱셈을 schoolbook negacyclic 참조에 대조, 그리고 X^256 == -1을 직접 단정
      mlkemcodec.cpp                 # MlKemCodec: 모든 폭에서의 ByteEncode/ByteDecode 왕복, 그리고 [0, q) 안의 모든 계수에 대해 정확한 유리수 정의에 대조한 압축 라운딩
      kat_mlkem.cpp                   # 세 파라미터 집합 전부에 대한 NIST ACVP ML-KEM keyGen/encap/decap. modified-ciphertext 레코드(암묵적 거부는 정의된 출력이므로 ACVP가 기대 비밀을 발행합니다)와 두 키 검사 음성 그룹 포함
      mlkem.cpp                        # IKem으로서의 MLKEM: 반복 encapsulate() 호출이 서로 다르다는 것, 조작된 ciphertext가 다른 비밀과 함께 ERET_OK를 반환한다는 것, 그리고 표준이 정의한 적 없는 파라미터 집합이 여덟 진입점 전부에서 거부된다는 것
    rng.cpp                       # CRng::fill() 테스트 케이스
    hmac.cpp                      # CHmac 테스트 케이스 (RFC 4231의 SHA-224/256/384/512 벡터와 RFC 2202의 SHA-1 것들, 과도하게 긴 키의 해싱 규칙, 그리고 verify()가 정확한 tag만 받아들인다는 것)
    hkdf.cpp                       # CHkdf 테스트 케이스 (RFC 5869 부록 A의 SHA-256 A.1–A.3과 SHA-1 A.4–A.6. 더해서 salt가 없는 것이 HashLen만큼의 0 salt와 같다는 것)
    pbkdf2.cpp                      # CPbkdf2 테스트 케이스 (RFC 6070의 HMAC-SHA1 벡터, RFC 7914 11절의 HMAC-SHA256 것들, iterations가 0인 경우와 출력 길이 거부. 16777216 반복 케이스를 빼 둔 이유도 적혀 있습니다)
    siphash.cpp                   # CSipHash 테스트 케이스 (SipHash 참조 구현의 vectors_sip64 항목 64개 전부, chunk 처리, 키 재사용/재시작 의미, 오류 경로)
    syms/
      aes.cpp                      # AES 테스트 케이스 (NIST SP 800-38A CBC 기지 응답 벡터. F.2의 4블록 케이스를 padding 없이 포함. 왕복, 조작, 오류 경로)
      des.cpp                       # DES 테스트 케이스 (고전적인 FIPS-46 벡터)
      des3.cpp                       # TripleDES 테스트 케이스 (DES 합성 교차 확인)
      chacha20.cpp                    # ChaCha20 테스트 케이스 (RFC 8439 부록 A.1 블록 함수, chunk 단위 키스트림)
    aeads/
      chacha20poly1305.cpp          # CPoly1305 + CChaCha20Poly1305 테스트 케이스 (RFC 8439 2.5.2/2.6.2/2.8.2)
      xchacha20poly1305.cpp          # CXChaCha20Poly1305 테스트 케이스 (draft-irtf-cfrg-xchacha A.3의 벡터, HChaCha20 부분키를 A.1에 대조, 그리고 마지막 8바이트가 반복되는 192비트 nonce가 키스트림을 반복하지 않는다는 것)
      aesgcm.cpp                     # CAesGcm 테스트 케이스 (GCM 명세 부록 B의 96비트 IV 케이스 1–4/7–10/13–16, aliasing, tag 절단, 조작, 오류 경로)
      ghash.cpp                       # Ghash 테스트 케이스 (GCM 비트 순서에서의 체 항등식, x 곱셈을 shift에 대조, chunk 처리, 이식 가능 경로 대 PCLMULQDQ 차분)
    eccurve.cpp                   # CEcCurve/SEcPoint 테스트 케이스 (군 법칙, SEC1 인코딩, 군 위수 검사)
    ec2curve.cpp                  # CEc2Curve/SEc2Point 테스트 케이스. 알려진 10개 곡선 전부에 대해 (곡선 위에 있음, 부정, 군 법칙, SEC1 인코딩, 군 위수 검사)
  x509/
    cert.cpp                  # CCert::importDer() 테스트 케이스 (자체 자기 서명 RSA/EC/KeyUsage/개인키 픽스처), extension<T>() 조회, CCertBuilder::build() (자기 서명 RSA/DSA/EC/EdDSA, 모든 digestAlgo/rsaPss 조합)
    crl.cpp                      # CCrlWriter::add()/remove()/build() + CCrlReader::decode()/find()/check() 왕복 테스트 케이스 (자체 자기 서명 CA 픽스처)
    ocsp.cpp                      # COcspCertId/COcspEntry/COcspRequestBuilder/COcspResponse 왕복 + 서명 검증 테스트 케이스
    csr.cpp                       # CCertRequest/CCertRequestBuilder (PKCS#10): 외부에서 생성한 픽스처 다섯 개(`openssl req` 넷, RFC 2986에서 손으로 조립해 `openssl dgst`로 서명한 둘), 이 라이브러리 자신의 출력에 대한 바이트 단위 기지 응답, 존재하지만 빈 `attributes`, 조작 거부, 그리고 CCertBuilder::subjectFrom()
    exts/                         # 확장 타입당 .cpp 하나. 각각 자신의 확장을 빌드 -> 인코드 -> 재파싱합니다
      bc.cpp, ku.cpp, eku.cpp, san.cpp, ski.cpp, aki.cpp, cdp.cpp, aia.cpp, cp.cpp, nc.cpp
    verify.cpp                    # CCert::verifyBy()/tbsCertificate()/signature()와 CCrlReader의 대응물들: 진짜 서명, 잘못된 발급자와 조작된 바이트의 거부
    malformed.cpp                 # 적대적/음성 x509: 뒤에 붙은 바이트, 잘못된 [3] extensions 래퍼, 내부/외부 서명 알고리즘 불일치, BIT STRING의 사용하지 않는 비트, pathLenConstraint 범위
    chain.cpp                     # 테스트 안에서 발급한 실제 3단 계층에 대한 CCertCollection 테스트 케이스: 조회, findIssuerOf(), buildChain(), verifyLinks(), checkKeyPairing()
    chain/                        # 컨테이너 포맷당 .cpp 하나
      pem.cpp                       # CPemChainFormat 테스트 케이스: 왕복, 교체가 아니라 추가, 잘못된/잘린/암호화된 컨테이너, CRLF와 블록 사이 텍스트, 더해서 certs/openssl-*.pem — 이 라이브러리가 아니라 OpenSSL 3.4.0이 쓴 픽스처입니다
      pfx.cpp                       # CPfxFormat 테스트 케이스: OpenSSL 3가 쓴 PFX 컨테이너 다섯 개를 읽고, 자기 것을 왕복하고, MAC이 덮는 범위의 조작 스윕, 그리고 CCert PKCS#8 wrap/unwrap 쌍
      certs/                        # PEM 픽스처들. fixtures/에는 PFX 것들이 있습니다 — 둘 다 OpenSSL 3가 한 번 쓴 것을 체크인했으므로 테스트 모음에 openssl이 PATH에 없어도 됩니다. 이 라이브러리가 쓰지 않은 파일을 읽는 것이, 포맷의 구현과 자기 일관적인 것을 가르는 유일한 기준입니다
    realcerts.cpp                # certs/implemented/ 아래 디스크에 있는 실제 상용 인증서들: github.com, amazon.com, sourceforge.net, QuoVadis/DigiCert RSASSA-PSS 중간 인증서, 그리고 자기 서명이 종단 간으로 검증되는 IdenTrust ML-DSA-87 파일럿 루트
  dnssec/
    name.cpp                      # CDnsName 테스트 케이스 (와이어 형식, 대소문자 폴딩, 레이블 세기, 잘못된 이름, 압축 포인터 거부)
    records.cpp                    # RFC 5702, 6605, 8080의 발행된 예제들에 대한 DNSKEY/DS/RRSIG 테스트 케이스 — 모든 키 태그와 DS digest
    keys.cpp                        # CDnssecKeys 테스트 케이스 (알고리즘별 DNSKEY 왕복, 고정 폭 r|s 재padding, 그리고 변환된 DNSKEY를 통한 종단 간 서명/검증)
third-party/
  CMakeLists.txt           # 벤더링된 의존성을 CMake 타깃으로 노출합니다. CERTPP_BUILD_TESTS=ON일 때만 add_subdirectory됩니다
  doctest/
    doctest.h                 # 벤더링된 단일 헤더 테스트 프레임워크 (MIT)
CMakeLists.txt              # certpp(그리고 CERTPP_BUILD_TESTS=ON이면 테스트)를 shared(기본) 또는 static으로 빌드합니다
```

## 모듈별 책임

- **`common.hpp`**은 다른 모든 헤더가 포함하는 기반입니다. 다음을 정의합니다.
  - `CERTPP_API`. `__COMPILES_LIBCERTPP__`(라이브러리 자신을 빌드할 때만
    설정됨)와 `__SHARED_LIBCERTPP__`(certpp를 shared 라이브러리로
    빌드하거나 소비할 때 설정됨)로 전환되는 dllexport/dllimport 매크로입니다.
    MSVC가 아닌 컴파일러에서는 빈 매크로가 되는데, ELF/Mach-O의 기본
    가시성이 이미 심볼을 export하기 때문입니다.
  - `namespace certpp` 안의 고정 폭 정수 별칭들(`uint8_t` .. `int64_t`,
    `float32_t`, `float64_t`, `size_t`, `ptrdiff_t`, `nullptr_t`). 라이브러리의
    나머지가 전역 네임스페이스로 손을 뻗는 대신 `certpp::uint32_t` 등을 쓰게
    하기 위한 것입니다.
  - `ERetCode`. 라이브러리 전체에서 실패할 수 있는 연산이 반환하는 공유
    상태/오류 코드 enum(`ERET_OK`, `ERET_INVAL`, `ERET_NOTIMPL`, ...)으로,
    각 모듈이 자기만의 상태 enum을 만들어 내는 대신 쓰는 것입니다.
  - `using std::swap;`. `namespace certpp`로 들여온 것이며, 라이브러리
    어디에서든 손으로 쓴 이동 대입 연산자가 멤버별로 수식 없는
    `swap(a, b)`를 호출해 `std::swap`으로 해석되게 합니다. 이것은 자체
    `certpp::swap<T>` 템플릿이 아니라 의도적으로 using 선언입니다(이 파일의
    이전 버전에는 바로 그런 것이, 본문이 `std::swap`과 동일한 채로 있었습니다)
    — `certpp` 안에 `swap`이라는 이름의 제약 없는 템플릿이 있으면, `certpp::`
    타입으로 만들어진 *어떤* 타입에 대해서도 인자 의존 조회(ADL) 후보가
    되는데, 이 코드베이스가 스스로 선언한 적 없는 타입까지 포함합니다.
    구체적으로, `CDistinguishedName`은 `std::map<ENameType, CName>`을
    보유합니다. 그 map을 단지 이동하거나 대입하거나 `.swap()`하는 것만으로도
    MSVC-STL 자신의 `<xtree>` 코드가 `certpp::` 타입으로 파라미터화된 내부
    타입들(트리 노드 포인터, 또는 비교자 `std::less<ENameType>`)에 대해 수식
    없는 `swap()`을 하게 되며 — 경쟁하는 `certpp::swap<T>`가 스코프에 있으면
    그것은 고칠 수 없는 모호성 오류입니다(여러 우회책을 시험해 확인했습니다.
    swap 호출 위치를 옮기는 것은 어느 내부 STL swap이 충돌하는지만 바꿨고,
    타입별 특정 오버로드 — 관련 없는 `std::sort` 충돌에 대해
    `TSpan<T>`/`TReadOnlySpan<T>`를 한 번 고쳐 준 수법 — 는 적용되지
    않습니다. 충돌하는 타입이 오버로드를 옆에 추가할 선언이 없는 private STL
    구현 세부이기 때문입니다). 커스텀 템플릿을 using 선언으로 바꾸면
    `certpp::swap`과 `std::swap`이 같은 실체가 되므로, 어떤 타입에 대해서도
    어디에서도 모호해질 것이 없습니다.
- **`version.hpp` / `version.cpp`**는 `SVersion`(major/minor/patch)과
  `certpp::GetLibraryVersion()`을 정의합니다. 헤더의 `HEADER_VERSION`과
  `.cpp`의 `LIBRARY_VERSION`은 소비자가 비교해서 헤더/바이너리 불일치를
  탐지하도록 만들어진 것입니다.
- **`time.hpp` / `time.cpp`**는 `STimeSpan`(밀리초 기간. 전부 인라인/
  `constexpr`입니다: `absolute()`, `total*()`/단위 접근자들, 산술과 비교
  연산자)과 `SDateTime`, 즉 분해된 달력 필드 시간
  (년/월/일/시/분/초/밀리초 + `isUtc` 플래그)을 정의합니다. `SDateTime`은
  `asn1/` 아래가 아니라 최상위에 있는데, 범용 값 타입이기 때문입니다 —
  `asn1/decoder.hpp`의 `decodeUtcTime()`/`decodeGeneralizedTime()`과
  `asn1/encoder.hpp`의 `encodeUtcTime()`/`encodeGeneralizedTime()`이 쓰지만,
  ASN.1이 아닌 코드도 쓸 것입니다(예: X.509 파싱이 생기면 인증서의 유효
  기간). `now()`/`from()`/`toUtc()`/`toLocal()`/`toSeconds()`는 모두
  `<ctime>`을 거쳐 변환합니다. tm-from-time_t 방향에는
  `gmtime`/`localtime`(MSVC에서는 `_s`를, 그 외에서는 스레드 안전성을 위해
  `_r`을 씁니다), 그 반대 방향에는 `mkgmtimeSafe()`(MSVC에서는 `_mkgmtime`,
  그 외에서는 `timegm`)를 씁니다 — `std::mktime`은 UTC 값을 가진 `tm`에
  의도적으로 절대 쓰지 않습니다. 그것은 인자를 항상 지역 시간으로만
  해석하기 때문입니다. `add()`/`subtract()`/`diff()`와 `+`/`-`/`+=`/`-=`
  연산자들(`STimeSpan` 또는 밀리초 기반)은 `toMilliseconds()`/`from()`을 거쳐
  왕복합니다.
- **`string.hpp`**은 `TString<T>`(기본값 `T = char`)를 정의합니다. 소유하고,
  증가 가능하고, 널로 끝나는 문자열 버퍼 — `TSpan<T>`의 소유하는 대응물입니다.
  용량은 `reserve()`를 통해 `CAP_INC`(64개 원소) 단위로 커지고,
  `trimExcess()`가 다시 줄입니다(문자열이 비면 완전히 해제합니다).
  `append()`/`erase()`/`find()`/`findLast()`/`subString()`/`trim()`/
  `toLower()`/`toUpper()`/`reverse()`를 제공하고, `toSpan()`을 통해
  `TSpan<T>`/`TReadOnlySpan<T>`와 상호 변환합니다. 전부 템플릿이므로
  의미 있는 `.cpp`가 없습니다(스텁은 일관성을 위해서만 있습니다).
- **`utils/djb.hpp` / `src/utils/djb.cpp`**는 `CDjb`를 정의합니다. 정적 메서드만
  가진 DJB 해시 유틸리티(`SDjbValue = uint32_t`)로, `compute()`는 바이트 span을
  그대로 해싱하고, `computeAsUpper()`/`computeAsLower()`는 ASCII 글자를 먼저
  대소문자 폴딩합니다(대소문자 무시 해싱용). 각각 시작 `hash`를 선택적으로
  받으므로 호출자가 여러 span을 하나의 논리적 값으로 해싱할 수 있습니다
  (`compute(a)` 다음 `compute(그 결과, b)`가 `compute(a+b)`를 한 번에 호출한
  것과 같습니다). 대소문자 폴딩 함수들은 각 `char`를 `SDjbValue`로 바로가
  아니라 `uint8_t`를 거쳐 넓힌 뒤 해시에 접습니다 — `char`의 부호성은 구현
  정의이고, 최상위 비트가 설정된 바이트(예: `CName`에서 escape된 비-ASCII
  바이트)는 그러지 않으면 부호 있는 `char` 플랫폼(MSVC)에서 부호 확장되어,
  부호 없는 `char` 플랫폼에서 `compute()`가 동일한 바이트에 주는 값과 다른
  값으로 해싱됩니다. `CName`이 전체 `memcmp` 앞에 저렴한 동등성 사전 검사를
  두기 위해 사용합니다.
- **`utils/hex.hpp` / `src/utils/hex.cpp`**는 `CHex`를 정의합니다. 16진
  문자열(`0x`/`0X` 접두사 선택적)을 원시 바이트로 파싱하고 잘못된 입력을
  거부하는 단일 메서드 유틸리티(`static bool decode(const char*,
  TArray<uint8_t>&)`)입니다. 이전에 `CBigNum`/`CGf2m`과 여러
  `crypto/asyms/` 구현에 거의 중복으로 있던 16진 파싱 보조 함수들에서 분리한
  것입니다. 이제 `CBigNum::fromHex()`/`CGf2m::fromHex()`는 그 위의 얇은
  래퍼입니다.
- **`utils/secure.hpp` / `src/utils/secure.cpp`**는 `CSecure`를 정의합니다.
  비밀 바이트에 대한, 당연해 보이는 방식으로는 쓸 수 없는 세 가지 연산입니다.
  `zero()`는 `memset`을 가리키는 volatile 함수 포인터를 통해 버퍼를
  지우므로, 그 호출이 무효함을 증명할 수 없고 따라서 제거될 수 없습니다 —
  다시 읽히지 않는 지역 변수에 대한 평범한 `memset`은 죽은 코드이고, MSVC는
  `/O2`에서 실제로 그것을 삭제합니다(가정이 아니라 생성된 어셈블리를 읽어
  확인했습니다). `equalsMask()`는 결과가 무엇이든 모든 바이트를 읽으며 두
  span을 비교하고, bool이 아니라 `0xFF`/`0x00`을 반환합니다.
  `std::memcmp`는 첫 불일치에서 멈추므로 실행 시간을 통해 일치하는 접두사의
  길이를 누출하기 때문입니다. `select()`는 그런 mask에 따라 두 span 중
  하나를 복사하므로, 호출자가 비교에 대해 분기하지 않고 그 결과에 따라
  행동할 수 있습니다. 그 한 비트가 진짜로 민감하지 않은 경우를 위한 bool
  반환 편의 함수 `equals()`도 있습니다.

  첫 소비자이자 이것이 존재하는 이유는 ML-KEM의 `decapsulate()`입니다.
  Fujisaki-Okamoto 재암호화 검사가 정확히 결과가 관측되어서는 안 되는
  비교이고, FIPS 203은 별도로 거부 플래그가 반환 전에 파괴되어야 한다고
  요구합니다. `CSecure`는 RSA의 EME-PKCS1-v1_5 unpadding이나
  `CbcTransformer`의 PKCS#7 검사에 있는 인라인 mask 연산을 **포함하지
  않습니다**. 둘 다 "두 버퍼를 비교"하거나 "두 버퍼 중 선택"이 아니며, 둘
  모두 masking을 padding 스캔과 엮어 놓았으므로 여기에서 그것들이 호출할
  것이 없습니다.

  `CBigNum::secureClear()`는 큰 수(big-number) 대응물로, limb 할당 전체
  (용량 전부이므로 절단된 길이보다 위의 limb도 포함)를 지우고 값을 0으로
  되돌립니다. `~CBigNum()`이 하는 일이 아니라 선택적(opt-in)인데, 이는
  측정으로 결정되었습니다. 파괴될 때마다 지우면 비대칭 테스트 모음 전체에서
  22%, X25519 하나에서는 32%의 비용이 들었습니다. 스칼라 곱이 아주 많은
  임시 객체를 만들고 그 대부분이 공개 중간값을 담고 있기 때문입니다. 이름이
  붙은 비밀에만 적용하면 측정 노이즈를 넘는 비용이 들지 않습니다. 그 대가로
  생기는 한계는 실재하므로 말해 둘 만합니다. 표현식 안에서, 또는
  `modExp()`/`modInverse()` 안에서 만들어진 임시 객체는 지워지지 않고
  해제되므로, 이것은 비밀이 해제된 메모리에 머무는 창을 닫는 것이 아니라
  좁힙니다.

  적용되는 값들은 노출이 단지 원치 않는 정도가 아니라 치명적인 것들입니다 —
  ECDSA/DSA의 nonce `k`와 그 옆의 `d*r`/`x*r` 곱(어느 쪽이든 발행된 서명에서
  개인키를 곧바로 내놓습니다), EdDSA의 nonce와 그 뒤의 확장된 시드,
  X25519의 clamp된 스칼라와 공유 비밀, 그리고 RSA의 CRT 중간값들
  (`m1`은 `m mod p`이므로 `gcd(m - m1, n)`이 정확히 `p`입니다).
- **`utils/bignum.hpp` / `src/utils/bignum.cpp`**는 `CBigNum`을 정의합니다.
  임의 정밀도 음이 아닌 정수(리틀엔디언 32비트 limb, 전체적으로 schoolbook
  알고리즘 — 성능보다 정확성과 단순성으로, 이 라이브러리의 초기 단계
  우선순위와 일관됩니다)입니다. 모든 `crypto/asyms/` 구현 뒤의 공유 수학
  타입입니다. 기본 및 모듈러 연산을 위한 `add`/`sub`/`mul`/`divMod`/`mod`/
  `mulMod`/`modSub`/`modNeg`/`shl`/`shr`, RSA/DSA/EC 식 모듈러 연산을 위한
  `modExp`/`modInverse`/`gcd`, 그리고 RSA/DSA 키 생성을 위한
  `isProbablePrime`(Miller-Rabin. 앞에 작은 소수 시험 나눗셈이 있습니다)/
  `generatePrime`(`crypto::CRng`를 통해)이 있습니다.
  `fromHex`/`fromLittleEndian`/`toLittleEndian`/`fromBigEndianTruncated`가
  생성/직렬화를 마무리하고(16진 파싱 자체는 독립된 `CHex` 유틸리티에 있습니다.
  위를 보십시오), `condSwap`은 분기 기반 스칼라 곱 ladder(예:
  `crypto/asyms/x25519.cpp`의 Montgomery ladder)를 위한 조건부 swap입니다.
  `crypto/`가 아니라 `utils/` 아래에 있는데, 타입 자체가 어느 한 알고리즘에
  (심지어 `crypto/`에 특정하여) 묶이지 않은 범용 수학이기 때문입니다 —
  암호학적인 것은 그 호출자들뿐입니다.

  **`add`/`sub`/`mul`/`mod`/`mulMod`/`modSub`/`modNeg`/`shl`/`shr`은 `*this`를
  제자리에서 변경하고 `CBigNum&`(`*this`에 대한 참조)를 반환하는데, 순전히
  체이닝(`a.mulMod(b, m).add(c)`)을 허용하기 위해서입니다** — 이름에서 처음
  받는 직관과 달리 함수형/사본 반환 API가 **아닙니다**. 수신자의 호출 전 값이
  여전히 필요한 호출자는 먼저 명시적으로 복사해야 하며
  (`CBigNum saved(original); saved.add(x);`), 몇 줄 뒤 *다른* 변수의 호출에서
  수신자 자신이 `other`/`modulus` 인자로 되돌려 넘겨지는 경우도
  포함합니다(이 모양이 초대하는 전형적인 버그: 곡선 자신의 도메인 파라미터,
  함수의 참조 전달 out 파라미터, 또는 이후 루프 반복에서 여전히 필요한 값을
  변경하는 것. 그것이 그저 별 문제 없어 보이는 표현식의 좌변이었기
  때문입니다). 갓 만든 임시 객체나 rvalue 체인(`CBigNum(1).shl(8)` 또는
  `CBigNum::modExp(...).mulMod(x, m)`)에 대해 이것들을 호출하는 것은 항상
  안전합니다. 임시 객체에 대한 참조를 다른 무엇도 들고 있을 수 없기
  때문입니다. `divMod`은 하나뿐인 예외입니다. 두 결과를 out 파라미터로
  보고하는 `const` 조회로 남아 있는데, 애초에 "바뀐 값을 반환한다"는 모양을
  가진 적이 없기 때문입니다. 정적 팩토리(`fromBigEndian`, `fromHex`, ...)와
  직렬화 함수(`toBigEndian`, `toLittleEndian`)는 영향이 없습니다 — 기존
  인스턴스의 값에 대해 작동하지 않으므로 aliasing할 것이 없습니다.

  `divMod()`은 기수 2^32에서의 Knuth 알고리즘 D(TAOCP 2권, 4.3.1)입니다.
  제수의 최상위 limb의 최상위 비트가 설정되도록 정규화한 뒤, 진행 중인
  나머지의 상위 두 limb에 대한 추정으로 몫 limb를 하나씩 만들어 내고,
  추정을 아래로 보정하며 — 드물게 — 그래도 하나 컸을 때는 제수를 다시
  더합니다. 이전 구현은 비트 직렬 복원 나눗셈이었습니다. *피제수의 비트마다*
  제수 전체에 걸친 시프트 한 번, 비교, 조건부 뺄셈. 모든 `modExp()`가 수천
  번의 축약을 수행하므로, 이 루틴 하나가 RSA, DSA, ECDSA 모두에서 지배적인
  비용이었습니다 — 교체로 전체 테스트 모음이 1243초에서 140초로 줄었고,
  비대칭 알고리즘들은 개별적으로 7–14배 빨라졌습니다.

  알고리즘 D의 정확성은 평범한 사용으로는 전혀 거치지 않는 두 가지에
  달려 있으므로, 둘 다 `tests/utils/divmod.cpp`에서 의도적으로
  테스트합니다. 추정 보정 루프와, 몫 limb 2^31개당 한 번 정도 발동하고 두
  limb 제수에 대해서는 *불가능한* add-back 분기입니다(두 limb 검사가 그
  경우 제수 전체를 보기 때문에 추정이 정확합니다). 무작위 테스트는 그 분기에
  한 번도 도달하지 못하므로, 그 입력은 구성해 만들었습니다 — 먼저 같은
  알고리즘의 4비트 limb 모델에서 전수로 거친 뒤, 각 32비트 limb의 상위
  니블로 확대했는데 이는 추정이 의존하는 모든 비율을 보존합니다. 루틴 전체는
  또한 `CBigNum`의 공개 연산만으로 쓴, 의도적으로 소박한 비트 직렬 참조에
  대해 차분 퍼징됩니다. 그것이 이 구현이 대체한 알고리즘입니다.

  `mul()`에는 추가로 하드웨어 가속 경로가 있습니다(x86-64 전용이고,
  `CERTPP_DISABLE_HWACCEL_SIMD`가 설정되지 않았을 때만). `mulAccelerated()`는
  네이티브 32비트 limb의 쌍을 64비트 자리로 재해석하고, 이식 가능 루프의
  32비트 schoolbook 곱셈-누산 대신 MULX(BMI2)/ADCX(ADX)를 씁니다. 두 확장
  모두 x86-64에서도 선택적이므로 런타임 CPUID 검사(`hasAdxBmi2()`) 뒤에
  있습니다. 이 라이브러리의 얼마나 많은 부분이 `mul()`의 정확성에
  의존하는지를 감안해, 이 경로는 전용 퍼즈 방식 교차 확인
  (`tests/utils/bignum.cpp`. `add()`/`shl()`/`testBit()`만으로 만든 독립 참조
  곱셈에 대조)으로 많은 무작위 피연산자 쌍에 걸쳐 검증되며, 더해서 이
  라이브러리의 테스트 모음 전체를 `CERTPP_DISABLE_HWACCEL_SIMD`의 두 설정
  모두에서 돌립니다. 그 교차 확인은 곧바로 값을 했습니다. 초기 버전은 64x64
  곱셈의 상위 워드와 덧셈의 캐리 출력을 하나의 진행 중인 "캐리" 값으로
  접어서 다음 열에 바로 더하려 했는데, 3항 합(진행 중인 캐리, 기존 누산기
  자리, 새 자리의 하위 워드)이 2의 캐리 출력을 필요로 할 때마다 그것은
  건전하지 않습니다 — 단일 `_addcarry_u64` 체인이 표현할 수 없는
  것입니다(0 또는 1만 만들어 낼 수 있습니다). 수정은 두 단계를 한 번의
  패스로 융합하려 하는 대신, 각 행을 고전적인 2단계 "긴 곱셈" 모양으로
  재구성합니다 — 먼저 `ai * b[]` 행 전체를 따로 계산하고(안전합니다. 거기의
  모든 단계는 64비트 값 두 개와 암묵적 캐리 입력만 결합합니다), *그 다음*
  그 행을 평범한 다중 정밀도 덧셈으로 진행 중인 합계에 더합니다(같은 이유로
  똑같이 안전합니다).
- **`utils/montgomery.hpp` / `src/utils/montgomery.cpp`**는 `CMontgomery`를
  정의합니다. **홀수** 모듈러스 하나와, 그에 대한 모듈러 연산이 큰 수
  나눗셈을 전혀 하지 않고 돌아가게 해 주는 상수들 — Montgomery의
  `n' = -m^-1 mod 2^32`와 `R^2 mod m`(여기서 `R = 2^(32*limbs(m))`) — 을
  함께 담습니다. 이것이 존재하는 이유는 `CBigNum::mulMod()`에 무엇도 캐시할
  곳이 없기 때문입니다. 그것은 필연적으로 `mul()` 다음 `mod()`이고 `mod()`는
  완전한 Knuth-D 긴 나눗셈이므로, 스칼라 곱 안의 모든 모듈러 곱셈 하나하나가
  그 비용을 치렀습니다. `CMontgomery`는 그 비용을 루프 밖으로 끌어냅니다 —
  루프가 그러지 않으면 수행할 수천 번에 대해, 생성 시점에 두 번의 나눗셈으로.

  이것은 **추가적이고 대체가 아닙니다**. `CBigNum::mod()`/`mulMod()`는
  변경되지 않았고 짝수 모듈러스에 대해서는 여전히 유일한 선택인데,
  Montgomery 축약은 그것을 다룰 수 없습니다(`R`이 2의 거듭제곱인 상태로
  `gcd(R, m) == 1`이 필요합니다). 짝수나 0 모듈러스로 만든 `CMontgomery`는
  `isValid() == false`를 보고하고, 그럴듯해 보이는 무언가를 계산하는 대신
  모든 연산을 아무 일도 하지 않게 만듭니다.

  두 영역(domain)이 관여합니다. *일반* 형태는 평범한 잉여 `a`이고,
  *Montgomery* 형태는 `a*R mod m`입니다. `toMont()`/`fromMont()`가 변환하고,
  `one()`은 1의 Montgomery 형태이며(투영 좌표의 `Z = 1`이 초기화되어야 하는
  값), `mul()`은 두 Montgomery 형태 값을 곱해 세 번째로 만듭니다.
  `add()`/`sub()`/`dbl()`/`neg()`는 `a -> a*R`가 선형이므로 *어느* 영역에서든
  유효합니다 — 그리고 `mul()`만큼이나 중요한데, 그것들이 대체한 코드가 덧셈을
  `.add(x)` 다음 `.mod(p)`로, 즉 최대 `2p`인 합을 축약하기 위한 긴 나눗셈으로
  적어 놓았기 때문입니다. `mulMod()`는 영역을 생각하고 싶지 않은 호출자를
  위한 `CBigNum::mulMod()`의 일반 형태 대체물이고, `modExp()`는 그 영역에서의
  square-and-multiply입니다.

  곱셈 자체는 CIOS(Coarsely Integrated Operand Scanning)입니다. schoolbook
  곱셈과 축약이 두 번째 피연산자의 limb별로 엮여 있으므로, 누산기가
  `limbs(m)+2` 워드를 넘지 않고 스택 버퍼에 들어갑니다(80 limb용으로
  잡았는데 P-521의 17보다 한참 크므로, 어떤 곡선 연산도 할당하지 않습니다).
  새 공개 limb 접근자가 아니라 `friend class CMontgomery`를 통해 `CBigNum`의
  원시 limb 배열에 도달합니다 — 표현은 `CBigNum` 자신의 일로 남고, 연산마다
  복사하지 않는 것이 이 클래스의 목적 전부이기 때문입니다.

  그 마지막 단계는 `[m, 2m)`에 있는 결과를 `m` 아래로 되돌리는 조건부
  뺄셈입니다. 그것을 빼먹는 것이 전형적인 Montgomery 버그이고, 전체 입력의
  약 절반에서만 드러나며 손으로 고른 작은 케이스에서는 절대 드러나지
  않으므로, 이 클래스는 `CBigNum::divMod()`와 같은 방식으로 테스트합니다.
  차분적으로, 각 메서드가 빠른 경로가 되어 주는 `CBigNum` 연산에 대해,
  라이브러리가 실제로 담고 있는 모든 모듈러스(29개 `CEcCurve` 파라미터
  집합의 `p`와 `n`, 더해서 edwards448의 `p`와 `L`)와 1–32 limb의 무작위 홀수
  모듈러스에 걸쳐, 단일 limb 모듈러스에 대해서는 `[0, 2m+2]^2`를 전수로,
  모듈러스마다 손으로 고른 `0`/`1`/`m-1`/`m`/`m+1`/`m^2-1`/`m^2+m` 피연산자
  부류들, 그리고 누적되어야만 드러나는 오류를 노출시킬 200단계 연쇄
  수열로(`tests/utils/montgomery.cpp`, 약 915,000개 단정). 조건부 뺄셈을
  빼거나, `n'`을 교란하거나, `fromMont()` 하나를 생략하면 각각 실패합니다.
- **`utils/gf2m.hpp` / `src/utils/gf2m.cpp`**는 `CGf2m`을 정의합니다. 이진체
  GF(2^m) 원소(다항식 기저)로, `CEc2Curve`의 이진 곡선들이 필요한 체 연산이며
  `CBigNum`이 제공할 수 없는 것입니다(`CBigNum`은 소수에 대한 임의 정밀도
  정수 연산입니다. GF(2^m) 덧셈은 캐리 없는 XOR이고, 곱셈은 캐리가 없으며
  정수 나눗셈이 아니라 고정된 기약 다항식으로 축약됩니다). `CBigNum`처럼
  임의 정밀도가 아니라 고정 용량(`uint64_t[9]`, 576비트. 이 라이브러리가
  정의하는 GF(2^571)까지의 모든 체를 덮습니다)인데, 체 원소의 폭은 그 체의
  고정된 `m`을 절대 넘지 않기 때문입니다. `add()`는 XOR입니다. `mul()`은
  schoolbook shift-and-XOR 캐리 없는 곱셈 다음에 그 체의 삼항/오항 축약
  다항식에 대한 축약이며 — 또는 x86/x86-64에서 `CERTPP_DISABLE_HWACCEL_SIMD`가
  설정되지 않고 런타임 CPUID 검사가 PCLMULQDQ 지원을 확인하면, 같은 축약 전
  넓은 곱을 만드는 하드웨어 캐리 없는 곱셈
  (`_mm_clmulepi64_si128`)의 고정 9x9 격자이고, 축약 단계 자체는 어느 쪽이든
  동일합니다. 그 축약(`reduceWide()`)은 비트 직렬이 아니라 워드 단위입니다.
  `x^m == x^terms[0] + ... + 1`이 *모든* 초과 비트를 같은 양만큼 밀어내므로
  초과분 전체가 한 번에 접힙니다 — `hi = wide >> m`을 취하고, 비트 `m`부터
  위를 지우고, 그 다음 `hi`를 오프셋 0과 각 항 오프셋에 다시 XOR하며, `m`
  이상에 아무것도 남지 않을 때까지 반복합니다(여기의 다섯 체 모두에 대해
  정확히 두 번). 이전 비트 직렬 버전은 `2m-2`에서 `m`까지 한 비트씩 내려가며
  설정된 비트마다 `1+termCount`개 비트를 토글했는데, 곱셈 비용의 95–98%로
  측정되어 PCLMULQDQ 곱이 사 주는 것이 거의 없게 만들었습니다. `square()`는
  전용 비트 분산 빠른 경로가 아니라 `mul(self)`로 구현되어 있습니다 —
  정확하고 훨씬 단순하며, `CBigNum`/`CEcCurve`가 이미 하고 있는 것과 같은
  성능/단순성 교환입니다. `inverse()`는 `GF(2)[x]` 위의 이진 확장 유클리드
  알고리즘입니다. `fromHex()`는 16진 문자열을 파싱하고(`CHex`를 통해. 아래
  참고), `toInteger()`는 이 원소의 다항식 기저 비트를 `CBigNum`으로
  재해석해(FIPS 186-4 부록 C.2) `CEcdsa2`가 필요한 곳에서 `CBigNum` 연산으로
  건너갑니다(예: 이진 곡선 점의 x 좌표를 부분군 위수 `n`으로 축약하는 것.
  `n`은 이진 곡선에서도 `CBigNum`입니다).

  위의 `CBigNum`처럼 `add`/`mul`/`square`/`inverse`는 `*this`를 제자리에서
  변경하고 체이닝을 위해서만 `CGf2m&`를 반환합니다 — "원본이 여전히 필요하면
  먼저 복사하라"는 같은 규칙이 적용됩니다(`CBigNum`의 해당 설명 참고).
  `EGf2mKnownField`는 이 라이브러리의 이진 곡선들이 쓰는 다섯 가지 체
  크기(163/233/283/409/571)를 지칭합니다 — 같은 크기의 "B" 곡선과 "K" 곡선은
  동일한 체를 공유하고 곡선 계수만 다르므로, 체는 `CGf2m`이 보유하는, 다섯
  개 프로그램 수명 싱글턴 중 하나를 가리키는 소유하지 않는
  `const SGf2mField*`입니다(`knownField()`/`knownFieldPtr()`를 통해).
  `CEcCurve`의 알려진 곡선 조회를 반영합니다. 그 싱글턴들은 평범한
  `CGf2m::_knownFields` 클래스 정적 배열이 아니라 최초 사용 시 생성되는
  함수 지역 `static` 뒤에 있습니다. `CEc2Curve::_knownCurves`
  (`ec2curve.cpp`, 다른 번역 단위)가 *자신이* 정적으로 생성되는 동안 그것들을
  읽는데, 표준은 어느 번역 단위의 정적 객체가 먼저 초기화를 마치는지 보장하지
  않습니다 — 이것이 초기 구현을 곧바로 물었습니다(공유 체 싱글턴이 읽히는
  시점에 아직 채워지지 않았기 때문에 모든 `CEc2Curve` 계수/점이 조용히 값이
  0이고 체가 null인 `CGf2m`이 되었고, 아직 실재하지 않는 `field.m`에 대한
  `CGf2m::fromBigEndian()`의 경계 검사가 모든 비트에서 실패해 `out`
  파라미터를 전부 null인 기본값 그대로 두었습니다 — 연산이 그 null 체
  포인터를 처음 역참조했을 때의 `SIGSEGV`로 잡혔습니다). 함수 지역 `static`은
  그 순서 문제를 완전히 비켜 갑니다. 어느 번역 단위의 정적 초기화기가 먼저
  호출하든 최초 사용 시 초기화됨이 보장됩니다. 축약 다항식 자체
  (FIPS 186-4 부록 D / SEC 2의 표준 삼항/오항식)는 하드코딩 전에 독립
  검사(Python `sympy`)로 올바른 차수의 기약 다항식임을 확인했습니다.
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
- **`io/span.hpp`**은 `TSpan<T>`(가변)와
  `TReadOnlySpan<T>`(읽기 전용. `TSpan<T>`에서 암묵적으로 생성 가능)를
  정의합니다 — 연속 메모리에 대한 소유하지 않는 뷰이고, 라이브러리 전체에서
  원시 포인터+길이 쌍 대신 씁니다.
  `SByteSpan`/`SReadOnlyByteSpan`은 `uint8_t` 인스턴스화의 별칭입니다(이것이
  따르는 `T` 대 `S` 접두사 규칙은
  [coding-conventions.ko.md](coding-conventions.ko.md#타입)를 보십시오). 전부
  템플릿이므로 `.cpp`가 없습니다.
- **`io/array.hpp`**은 `TArray<T>`를 정의합니다. 소유하며 증가 가능한
  배열로, 임의 원소 타입에 대한 `TSpan<T>`의 소유하는 대응물입니다
  (`TString<T>`은 문자 타입에 특화해 같은 역할을 합니다). `EArrayType`은
  직교하는 두 가지를 하나의 `uint8_t`에 담아 추적합니다. 상호 배타적인
  STATIC/DYNAMIC 하위 타입(`EARRAY_TYPE_MASK`. 배열이 자기 힙 할당을
  소유하는지, 아니면 — 정적 `wrap()`을 통해 — 절대 `delete[]`해서는 안 되는
  호출자 제공 버퍼를 단지 가리키고 있는지)과, 독립적인 `EARRAY_FIXED`
  플래그(현재 용량을 넘어 커져야 하는
  `reserve()`/`trimExcess()`/모든 `resize()`/`add()`/`insert()`를 거부)입니다.
  fixed가 아닌 STATIC 배열은 실제로 커져야 할 필요가 처음 생길 때 DYNAMIC으로
  변환됩니다 — 그 성장이 `reserve()`로 직접 요청되었든
  `resize()`/`add()`/`insert()`를 통해 간접적으로 요청되었든(모두 자리를
  만들기 위해 `reserve()`로 모이므로). 그 시점에 자기 버퍼를 할당하고
  wrap된 것을 가리키는 일을 멈추되, 애초에 소유한 적이 없으므로 해제하지는
  않습니다. `markFixed()`는 이미 설정된 하위 타입이 무엇이든 그것에
  `EARRAY_FIXED`를 OR하며, 아직 `EARRAY_NONE`인(갓 기본 생성되어 원소를 한
  번도 추가하지 않은) 배열에서는 아무 일도 하지 않습니다. 모든 변경 메서드
  (`add()`, `insert()`, `remove()`, `pop()`, `resize()`, `reserve()`,
  `trimExcess()`, `clear()`)는 `T`가 자명하게 생성/파괴 가능하다고 가정하지
  않고 placement `new`/명시적 `~T()` 호출로 원소 수명을 직접 관리하는데,
  `COctet`과 `TString<T>`가 자기 원소 타입에 대해 취하는 것과 같은 수동 수명
  접근입니다. `TSpan<T>`처럼 전부 템플릿이므로 `.cpp`가 없습니다.

  수명을 추적하는 원소 타입(소멸자가 나가면서 쓰는 낡은 매직 바이트 등을
  통해, 피연산자의 수명이 이미 끝난 생성자/`operator=` 호출을 표시해 주는
  타입)에 대해 `tests/io/array.cpp`를 쓰면서 실제 버그 세 개가 드러났습니다.
  `reserve()`는 `EARRAY_STATIC`을 `EARRAY_DYNAMIC`으로만 전환했고, 그것도
  `_data`가 이미 null이 아닐 때만 그랬습니다 — 그래서 평범하게 기본 생성된
  `TArray<T>()`(`EARRAY_NONE`)는 실제 원소를 `add()`한 뒤에도 영원히
  `EARRAY_NONE`을 보고하는 상태에 갇혔고, 이는 이 클래스를 쓰는 가장 흔한
  방식 하나에 대해 `empty()`/`operator bool()`(둘 다 크기와 무관하게
  `EARRAY_NONE`을 빈 것으로 취급합니다)을 영구히 틀리게 만들었습니다.
  `insert()`는 원본을 제자리로 이동 생성하고 파괴하는 방식으로 원소를
  밀어낸 뒤, 비워진 슬롯에 새 값을 placement 생성이 아니라 평범하게
  대입했습니다 — 그런데 그 슬롯의 객체 수명은 이미 끝나 있었고(밀어내기의
  일부로 소멸자가 돌았거나, 순수 추가의 경우에는 `resize()`가 방금 거기
  생성해 둔 살아 있는 기본 객체였으며, 수정은 재사용 전에 그것을 파괴해야
  합니다), 따라서 그 대입(또는 순수 추가의 경우 뒤따르는 밀어내기의
  placement `new`)이
  죽은 메모리 또는 아직 살아 있는 메모리에 대해 실행되었습니다. 그리고
  `markFixed()`는 `EARRAY_FIXED`를 OR하기 전에 `_type`을
  `~EARRAY_TYPE_MASK`로 mask했는데, 건드리지 말아야 했을 STATIC/DYNAMIC 하위
  타입 비트를 지워 버렸습니다(`EARRAY_FIXED`는 분리된 비트이므로 그런 mask가
  필요 없습니다. 그 코드가 분명히 복사해 온 `reserve()`/`trimExcess()`의
  정당한 "하위 타입을 교체한다" 패턴과 다릅니다). 관련 없는 네 번째 버그 —
  뒤집힌 `resize()` 단축 평가(`(_type & EARRAY_FIXED) || !reserve(size)`가
  아니라 `!(_type & EARRAY_FIXED) && !reserve(size)`)로, 커져야 하는 fixed
  배열에 대해 용량 검사를 완전히 건너뛰어 `add()`/`resize()`가 `_cap` 끝을
  넘어 placement `new`를 하게 만든 것 — 은 나머지 셋이 고쳐지고 테스트 모음이
  깨끗하게 돌 수 있게 된 뒤에 같은 테스트 모음이 잡았습니다.
- **`io/buffer.hpp` / `src/io/buffer.cpp`**는 `CBuffer`를 정의합니다.
  소유하며 크기 조절 가능한 원시 바이트 버퍼로, `resize()`, `store()`, 원시
  포인터를 위한 `toPtr()`, 그리고 넘겨주기 위한 `toSpan()`이 있습니다. 여기
  세 바이트 컨테이너 중 *작업용* 버퍼이고, 그 구분이 충분히 중요해서
  [`coding-conventions.ko.md`](coding-conventions.ko.md)의 "버퍼 처리" 절이
  그것을 규정합니다. `CBuffer`는 결과를 조립하는 곳이고(한 번 resize하고,
  `memcpy`/`memset`으로 채우고, 다시 읽습니다), `COctet`은 완성된 고정 길이
  결과를 담아 두는 곳이며, `TArray<T>`는 바이트가 아니라 진짜로 구별되는
  원소들의 수열을 위한 것입니다. 라이브러리의 거의 모든
  `encode()`/`build()`가 `CBuffer`에 누적하고 마지막에 `COctet`으로
  변환합니다. 알아 둘 만한 날카로운 모서리 둘: `resize()`는 기존 내용을
  보존하지만 추가되는 바이트를 0으로 만들지는 **않습니다**
  (`TArray<uint8_t>`와 달리). 그리고 `bool`을 반환하므로 — 그것을 무시하고
  `toPtr()`로 쓰는 호출자는 할당 실패 시 범위를 벗어나 쓰는 것입니다.
- **`utils/base64.hpp` / `src/utils/base64.cpp`**는 `CBase64`를 정의합니다.
  base64 코덱의 양쪽 절반을 한 클래스에 담았습니다. 증분 변환
  (`push()`/`finish()`. 방향을 고정하는 `EBase64Mode` —
  `EB64M_ENCODE`, `LINE_LENGTH`에서 PEM 식으로 줄을 바꾸는
  `EB64M_ENCODE_BR`, `EB64M_DECODE` — 과 내부 `MAX_BUFFER` chunk 처리와
  함께), 그리고 버퍼 전체를 한 번에 처리하는 정적 일괄
  `encode()`/`decode()`입니다. 디코더는 `=` padding과 공백에 대해 의도적으로
  관대한데, 그것이 PEM 블록이 실제 세상에 나타나는 모습 그대로에 쓸 수 있게
  만들어 줍니다. `CCert::importPem()`/`exportPem()`이 주요 소비자입니다.
  `io/base64.hpp`는 이것이 **아니라는** 점에 유의하십시오. 아무것도 선언하지
  않고 `certpp.hpp`가 의도적으로 포함하지 않는 빈 자리표시 헤더입니다.
- **`utils/json.hpp` / `src/utils/json.cpp`**는 `CJson`을 정의합니다. null,
  boolean, number, string, array, object를 담는 JSON 값 트리입니다.
  `parseJson()`은 완전한 JSON 값 하나만 받고, `toString()`은 문자열과 객체
  키의 escape를 처리하며 유한한 `double`의 왕복 정밀도를 보존합니다. 깊이
  제한을 넘는 값과 유한하지 않은 숫자는 `null`로 출력됩니다.
  `toBson()`과 `parseBson()`은 중첩 객체/배열, boolean, string, null, double,
  BSON 정수(`double`로 변환)를 포함하는 BSON 문서를 처리하며, 지원하지 않는
  BSON 타입은 거부합니다. BSON scalar 루트는 인코딩할 수 없습니다.
  `CERTPP_WITHOUT_JSON`을 켜면 `certpp.hpp`의 선택적 include가 비활성화되고,
  설치 헤더에서 `json.hpp`가 빠지며 `tests/utils/json.cpp`도 건너뜁니다.
- **`io/octet.hpp` / `src/io/octet.cpp`**는 `COctet`을 정의합니다. 소유하는
  고정 크기 바이트 버퍼(`TString<T>`와 달리 크기 조절/증가 불가)입니다 —
  `store()`가 내용을 교체하고(복사해 소유권을 가집니다. null 포인터나 크기 0은
  거부되고 이전 내용을 건드리지 않으므로, 실패한 `store()`가 기존 인스턴스를
  망가뜨릴 수 없습니다), `clear()`가 해제하며,
  `toSpan()`/`toPtr()`이 읽기 전용 접근을 줍니다. 복사 생성/대입은 깊은
  복사입니다. 이동 *생성*은 소유권을 옮기고 원본을 비웁니다. 이동 *대입*은
  대신 swap하므로 원본이 대상이 가지고 있던 것을 갖게 됩니다 — 아래
  `io/array.hpp` 항목에서 설명하는 프로젝트 전반의 관례이며, 자기 자신으로의
  이동을 안전하게 유지하고 옛 버퍼를 원본 자신의 소멸자가 해제하도록
  남깁니다. `secureClear()`는 해제하기 전에 내용을 영으로 지웁니다. 비밀을
  담고 있는 `COctet`에 필요한데, 그 바이트가 읽기 전용
  `toPtr()`/`toSpan()`으로만 도달 가능하므로 `CSecure::zero()`를 밖에서
  겨눌 수 없기 때문입니다.
- **`io/stream.hpp` / `src/io/stream.cpp`**는 `IStream`을 정의합니다.
  읽기/쓰기/탐색 스트림 인터페이스
  (`capabilities()`/`EStreamCapability`로 능력을 질의하고,
  `trimExcess()`/`length(newLen)`/`flush()` 같은 선택적 연산은 순수 가상이
  아니라 기본적으로 `ERET_NOTIMPL`입니다)와, `IStream::createMemory(...)`
  팩토리 함수들입니다. `.cpp`는 팩토리만 구현합니다. 구체적인 메모리 내
  구현은 `MemStream`이며, `src/io/` 아래의 private 클래스
  (`memstream.hpp`/`.cpp`)로 `include/certpp/`를 통해 노출되지 않습니다
  (`MemStream::write()`가 성공한 모든 쓰기에서 바이트 수가 아니라 0을
  반환했습니다 — 실제 버그였는데, 그 반환값이 `IStream::write()`의 계약이
  호출자에게 짧거나 실패한 쓰기를 탐지하도록 허용하는 유일한 수단이기
  때문입니다. `CWriter`가 그것에 의존하기 시작했을 때 고쳤습니다). 왜 거기에
  있고 그 헤더 가드/include가 공개 헤더와 어떻게 다른지는
  [coding-conventions.ko.md](coding-conventions.ko.md#내부-구현-헤더)를
  보십시오.
- **`net/sockaddr.hpp` / `src/net/sockaddr.cpp`**는 IPv4, IPv6,
  Unix-domain 주소와 숫자 주소/호스트 이름 해석을 위한 `SSocketAddress`를
  정의합니다. **`net/socket.hpp` / `src/net/socket.cpp`**는 stream/datagram
  소켓을 소유하는 `CSocket` 래퍼를 정의하며, OS 오류를 `ERetCode`로
  변환합니다. 이 모듈은 TLS나 인증서 경로 검증을 제공하지 않습니다.
- **`asn1/tag.hpp` / `src/asn1/tag.cpp`**는 `CTag`를 정의합니다. ASN.1
  태그(클래스 + constructed 플래그 + 태그 번호)이며,
  `TReadOnlySpan<uint8_t>`/`TSpan<uint8_t>`와 상호 변환하는
  `decode()`/`encode()`, 그리고 표준 태그 클래스/universal 태그 번호를 위한
  `ETagClass`와 `EUniversalTags`가 있습니다.
- **`asn1/decoder.hpp` / `src/asn1/decoder.cpp`**는 `CDecoder`를 정의합니다.
  ASN.1 데이터를 디코드하는 정적 메서드들(`EEncodingRule`이 BER/CER/DER를
  선택하고, `EDecoderStatus`가 디코드가 왜 실패했는지 보고합니다)이며, 두
  계층으로 나뉩니다.
  - **TLV 프레이밍**(태그와 무관): `readEncodedValue()`가 완전한
    tag-length-value를 읽으며, 확정 길이 값과 BER/CER 비확정 길이 값 양쪽을
    다룹니다(후자는 end-of-contents 표시를 찾아 중첩된 값들을 스캔해
    해결하며, 악의적으로 깊은 비확정 길이 중첩이 스택을 소진시킬 수 없도록
    `MAX_NESTING_DEPTH` 가드로 경계가 지어집니다).
    `readNextElement()`는 그 위에 커서를 얹어 SEQUENCE/SET의 멤버를
    순회합니다. `tryReadEncodedValue()`는 같은 연산이면서 `bool`이 아니라
    `EDecoderStatus`를 반환하므로, 한 번에 한 chunk씩 바이트를 받는 호출자가
    "잘렸으니 더 보내라"(`EDEC_NEED_MORE`)와 "잘못됐으니 포기하라"를
    구별할 수 있습니다.
  - **내용 디코딩**(태그와 독립적이므로, 호출자의 태그가 평범한 universal
    태그였든 IMPLICIT/context-specific 태그였든 동작합니다):
    `decodeBoolean()`, `decodeInteger()`, `decodeEnumerated()`,
    `decodeNull()`, `decodeOctetString()`, `decodeBitString()` +
    `testNamedBit()`(NamedBitList. 예: X.509 KeyUsage), `decodeOid()` +
    `countOidArcs()`/`decodeOidString<TChar>()`(후자는 arc들을 점으로 구분된
    10진 텍스트로, 예컨대 "1.2.840.113549.1.1.1"로 `TString<TChar>`에
    포매팅합니다 — 순전히 ASCII 숫자와 `.`뿐이므로
    `decodeString<TChar>()`과 달리 두 `TChar` 모두에 대해 로케일과
    무관합니다), `decodeText()`/`decodeString<TChar>()`
    (UTF8String/PrintableString/IA5String/NumericString 문자 집합을
    검증합니다. 다른 문자열 태그는 통과시킵니다 —
    `decodeString<TChar>()`은 추가로 `TUtf8Encoding<TChar>`를 통해
    `TString<TChar>`로 전사합니다), 그리고
    `decodeUtcTime()`/`decodeGeneralizedTime()`(`SDateTime`으로),
    `decodeDistinguishedName()`(SEQUENCE의 내용 옥텟에서
    `CDistinguishedName`으로 — 기대하는 정확한 구조는 아래를 보십시오).
    이것들은 tag+length 헤더가 아니라 값의 내용 옥텟만 받습니다(바깥
    `readEncodedValue()` 호출의 `outArea`). `decodeOctetString()`과
    `decodeBitString()`은 각각 `SReadOnlyByteSpan&` 버전 옆에 `COctet&`
    오버로드를 가지며, 원본 버퍼를 가리키는 대신 내용을 소유하는 `COctet`에
    복사합니다.

  `decodeDistinguishedName()`은 X.501 Name/RDNSequence를 파싱합니다. 각 내용
  원소는 정확히 하나의 AttributeTypeAndValue(SEQUENCE { type OBJECT
  IDENTIFIER, value ANY })를 담은 SET(RelativeDistinguishedName)이어야
  합니다 — 다중 값 RDN은 곧바로 거부되는데, `CDistinguishedName`은
  `ENameType`당 `CName` 하나만 보유하므로 첫 값만 남기고 나머지를 조용히
  버리는 것이 잘못된 실패 방식이기 때문입니다. `type`은
  `CName::attributeTypeOf()`로 해석되어야 합니다 — 이름을 댈 수 없는 속성
  타입은 `Name` 전체를 실패시키며, 이것이 `organizationIdentifier` 하나가
  실제 EU 규제 인증서를 import 불가로 만들곤 했던 이유이고, 디코더가 건너뛰는
  법을 배우는 대신 `ENameType`이 자라야 했던 이유입니다(이름 없는 속성을
  버리면 서로 다른 두 DN이 같다고 비교되고, DN 동등성은 미래의 체인 빌더가
  발급자와 주체를 맞추는 기준입니다). `value`는 PrintableString, UTF8String
  또는 IA5String이어야 하며(`CEncoder::encodeDistinguishedName()`이 쓰는 세
  종류 — 아래 참고), `decodeString<wchar_t>()`로 디코드한 뒤 `CName`을
  생성하기 전에 `TString<wchar_t>::convertTo<char>()`로 좁은 형태로
  변환합니다(`CDistinguishedName::tryParse(CWideString)`의 같은 변환 경로를
  반영합니다). 바깥 문서의 규칙 집합과 무관하게 항상 DER의 규칙을
  적용하는데, X.501 Name은 BER/CER 문서 안에서도 실무에서 DER로 인코드되기
  때문입니다 — 그래서 `readEncodedValue()`와 달리 `EEncodingRule` 파라미터를
  받지 않습니다.

  `decoder.hpp`는 `EEncodingRule`/`checkEncodingRule`과 CER 세그먼트 한계
  검사(`CER_MAX_SEGMENT`/`exceedsCerSegmentLimit`)도 담고 있습니다. 디코더와
  `CEncoder` 둘 다 필요하기 때문입니다.
- **`asn1/encoder.hpp` / `src/asn1/encoder.cpp`**는 `CEncoder`를 정의합니다.
  쓰기 쪽 대응물이고, `CDecoder`의 두 계층을 반영합니다.
  - **TLV 프레이밍**: `writeEncodedValue()`가 확정 길이 형식으로
    tag-length-value를 씁니다(세 규칙 집합 모두에서 유효합니다. BER/CER의
    선택적 비확정 길이 형식은 절대 만들지 않습니다). 그리고
    `encodedValueSize()`가 목적지 버퍼 크기를 미리 잡아 줍니다.
    `writeSequenceOf()`/`writeSetOf()`는 이미 인코드된 자식들을 이어 붙여
    SEQUENCE/SET의 내용을 만듭니다. `writeSetOf()`는 추가로 먼저 CER/DER의
    정규 오름차순으로 재배열합니다(BER에서도 유효하므로 항상 적용합니다).
  - **내용 인코딩**: `encodeBoolean()`, `encodeInteger()`,
    `encodeEnumerated()`, `encodeNull()`, `encodeOctetString()`,
    `encodeBitString()` + `encodeNamedBitList()`(X.690 11.2.2에 따라
    뒤쪽의 0 비트를 다듬습니다), `encodeOid()` + `encodedOidSize()`,
    `encodeOidString<TChar>()` + `encodedOidStringSize<TChar>()`
    (`decodeOidString<TChar>()`의 역. private `parseOidArcs<TChar>()` 보조
    함수로 점 구분 10진 `TString<TChar>`를 파싱한 뒤 `encodeOid()`와 정확히
    같이 인코드합니다), `encodeText()`/`encodeString<TChar>()`
    (`decodeText()`/`decodeString<TChar>()`의 역. `TString<TChar>`를
    UTF-8로 전사한 뒤 `decodeText()`로 검증합니다) +
    `encodedStringSize<TChar>()`,
    `encodeUtcTime()`/`encodeGeneralizedTime()`(+
    `encodedGeneralizedTimeSize()`. 소수점 이하 초 부분이 있는지에 따라
    길이가 달라지기 때문입니다), 그리고 `encodeDistinguishedName()`(+
    `encodedDistinguishedNameSize()`. 아래 참고). `encodeOctetString()`과
    `encodeBitString()`도 각각 `const COctet&` 오버로드를 가지며,
    `COctet::toSpan()`을 통한 `SReadOnlyByteSpan` 버전의 얇은 래퍼입니다.
    이것들은 항상 DER 정규 값 인코딩(최소 길이 정수, `0xFF`/`0x00` 불리언,
    ...)을 내놓습니다 — 쓰는 쪽에게는 자유로운 선택이고 정규 형태는
    BER/CER에서도 유효하므로, 어느 것도 `EEncodingRule` 파라미터를 받지
    않습니다.

  `encodeDistinguishedName()`은 `decodeDistinguishedName()`의 역입니다.
  구성요소당 RDN(SET) 하나를, `CDistinguishedName`의 `ENameType`
  오름차순(`std::map` 자신의 순회 순서)으로, 각각 정확히 하나의
  AttributeTypeAndValue를 담아 씁니다 — `type`은 `CName::attributeOid()`에서,
  `value`는 구성요소의 *escape되지 않은* 텍스트
  (`CName::toString<wchar_t>(false)`)를 `encodeString<wchar_t>()`로 인코드한
  것(진짜, 로케일과 무관한 UTF-8)이며, 먼저 PrintableString으로 시도하고 그
  문자 집합 검사가 실패할 때에만 UTF8String으로 시도합니다. `ENAME_DC`가
  하나뿐인 예외입니다. RFC 4519 2.4가 `domainComponent`의 문법을 대안 없이
  IA5String으로 주므로, 그렇게 쓰고 대체로 넘어가지 않고 곧바로 실패합니다.
  private `buildAttributeTypeAndValue()`/`buildDistinguishedNameContent()`
  보조 함수들이 중첩된 TLV 바이트 전체를 스크래치 `TArray<uint8_t>`에
  아래에서 위로 만듭니다(OID TLV + 값 TLV -> AttributeTypeAndValue SEQUENCE
  TLV -> RDN SET TLV -> 이어 붙인 RDNSequence 내용).
  `encodedDistinguishedNameSize()`와 `encodeDistinguishedName()`은 둘 다 같은
  private 보조 함수를 호출하므로(무엇이 인코드되는지에 대해 서로 의견이
  갈릴 수 없습니다) 결과를 측정하는지 호출자의 목적지로 복사하는지만
  다릅니다. 구성요소가 없는 빈 `CDistinguishedName`은 내용 옥텟 0개(빈
  SEQUENCE)로 성공적으로 인코드됩니다 — `encodedStringSize()`와 마찬가지로,
  크기만 구하는 보조 함수의 `0` 반환은 "비었음"과 "인코드 불가" 사이에서
  모호합니다. 둘을 구별하려면 `encodeDistinguishedName()`을 직접 호출하고 그
  반환값을 확인하십시오. 디코더 쪽과 마찬가지로 항상 DER의 규칙을 적용하고
  `EEncodingRule` 파라미터를 받지 않습니다.
- **`asn1/reader.hpp` / `src/asn1/reader.cpp`**는 `CReader`를 정의합니다.
  `CDecoder`의 내용 수준 `decode*()` 메서드들을 스트림/커서 관리와 짝지어,
  호출자가 모든 필드마다 `readNextElement()` + `decode*()`를 손으로 쓰지
  않게 합니다. `IStream`에서 생성되며 그것을 지연 평가로 읽습니다.
  `growBuffer()`는 파싱 시도가 실제로 버퍼된 데이터를 다 썼을 때에만 소유하는
  `COctet`으로 chunk를 하나 더 당겨 오고, 스트림 전체를 미리 읽지 않으므로,
  생성 이후(그러나 필요해지기 전에) 스트림에 쓰인 데이터도 여전히
  보입니다. `CDecoder`는 여전히
  시도마다 연속된 span이 필요하고(BER/CER 비확정 길이 파싱은 앞을 스캔해야
  합니다) 따라서 성장 자체는 피할 수 없으며 그 시점만 조절됩니다. span에서
  직접 생성되면(예: 부모 원소의 이미 완전히 버퍼된 내용) 자라날 스트림이
  없으므로 단지 그 span을 가리킵니다. `growBuffer()`가 `COctet`을 재할당하므로
  (옛 할당을 해제합니다) 평범하게 저장한 `SReadOnlyByteSpan` 커서 스냅샷은
  호출 중간에 낡아질 수 있습니다 — 실패 시 커서를 되돌려야 하는 모든 메서드는
  private `withRollback()` 보조 함수를 거치는데, 그것은 재할당마다 올라가는
  `_generation` 카운터를 추적하고 매달릴 수 있는 저장된 포인터를 믿는 대신
  올바른 되돌림 대상을 재구성합니다(아무것도 자라지 않았다면 저장된 span,
  자랐다면 현재 버퍼 전체입니다. `growBuffer()`는 항상 저장된 span의 소비되지
  않은 바이트와 새로 읽은 바이트로 정확히 그것을 다시 만들기 때문입니다). 이
  소유하며 필요할 때 재할당되는 버퍼 때문에 `CReader`는 이동 전용입니다
  (복사하면 사본의 커서가 원본의 버퍼를 가리키게 됩니다). 모든 타입별
  `readBoolean()`/`readInteger()`/`readEnumerated()`/`readNull()`/
  `readOctetString()`/`readBitString()`(`SReadOnlyByteSpan`과 `COctet`
  오버로드)/`readOid()`/`readOidString<TChar>()`/`readText()`/
  `readString<TChar>()`/`readUtcTime()`/`readGeneralizedTime()`은 특정한
  평범한 UNIVERSAL, *primitive* 태그를 기대하며 다음 원소를 읽습니다
  (constructed 인코딩도 거부합니다. `CDecoder`의 내용 수준 디코더 중 어느
  것도 constructed/분절된 BER/CER 문자열을 재조립하지 않기 때문입니다) —
  불일치나 디코드 실패가 있으면 커서는 있던 자리에 정확히 남으므로, 호출자가
  다른 읽기를 시도하거나 OPTIONAL/DEFAULT 필드를 없는 것으로 취급할 수
  있습니다. `readDistinguishedName()`은 같은 태그-불일치-시-커서-유지 계약을
  따르지만 (`readSequence()`처럼) *constructed* SEQUENCE를 기대하고, 중첩된
  `CReader`를 반환하는 대신 `CDecoder::decodeDistinguishedName()`으로 완전히
  디코드합니다. `CDistinguishedName`은 그 자체로 완전한 값이고, 호출자가
  멤버 단위로 순회하는 것이 아니기 때문입니다.
  `readSequence()`/`readSet()`/`readConstructed()`는 constructed 값의 내용에
  대한 중첩 `CReader`를 반환하며, SEQUENCE/SET으로(또는
  `readConstructed()`의 경우 그 외의 임의 constructed 태그, 예컨대
  context-specific `[n]` EXPLICIT 래퍼로) 내려가기 위한 것입니다. 저수준
  `readNextElement()`가 이 모두의 바탕이고, 타입별 메서드들이 평범한
  universal 태그로 인식할 수 없는 IMPLICIT 태그 또는 CHOICE 내용을 위한
  비상구입니다.
- **`asn1/writer.hpp` / `src/asn1/writer.cpp`**는 `CWriter`를 정의합니다.
  쓰기 쪽 대응물이고, 각 타입별 `writeBoolean()`/`writeInteger()`/... 메서드가
  대응하는 `CEncoder::encode*()`로 내용을 스크래치 버퍼에 인코드한 뒤,
  `writeElement()`(내부적으로 `CEncoder::writeEncodedValue()`)로 완전한
  tag-length-value를 스트림에 쓰며, 스트림이 모든 바이트를 썼다고 보고하는지
  검증합니다. `writeSequence()`/`writeSet()`은 새로운 중첩 빌더 API를
  들이지 않고 `CEncoder::writeSequenceOf()`/`writeSetOf()`를 정확히
  반영합니다(이미 인코드된 자식들의 배열). 각 자식은 기존 `CEncoder` 전용
  테스트들이 이미 하는 것과 똑같이 `CEncoder`(또는 자기 메모리 스트림 위의
  중첩 `CWriter`)로 먼저 만드십시오. `writeDistinguishedName()`은 다른 타입별
  쓰기와 같은 스크래치-버퍼-다음-`writeElement()` 패턴을 따르며,
  `CEncoder::encodedDistinguishedNameSize()`로 버퍼 크기를 잡고
  `CEncoder::encodeDistinguishedName()`으로 채운 뒤 SEQUENCE 태그 아래로
  씁니다. `CReader`와 달리 `CWriter`는 `IStreamPtr` + `EEncodingRule`만
  보유하므로 자유롭게 복사 가능합니다.
- **`crypto/hasher.hpp`**은 `IHasher`를 정의합니다. 모든 해시 알고리즘이
  구현하는 인터페이스로, `reset()`(알고리즘의 초기 상태로),
  `push(buf)`(입력을 더 먹입니다. 스트리밍이므로 같은 전체 입력을 어떻게
  쪼개도 같은 digest가 나옵니다), 그리고 `finish(out)`(호출자가 제공한
  `SByteSpan`에 digest를 씁니다. `out`이 `byteWidth()`보다 짧으면
  실패합니다)입니다. `byteWidth()`(바이트 단위 digest 길이:
  MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512에 각각 16/20/28/32/48/64)는
  구체 hasher에 대해 인스턴스별로 달라지는 일이 없으므로 가상 함수가 아니라
  생성자를 통해 한 번 설정되고 읽기 전용으로 노출됩니다. `IStream`과 달리
  `IHasher`의 메서드 중 어느 것도 기본적으로 `ERET_NOTIMPL`이 아닙니다 —
  모든 구체 hasher가 셋 모두를 구현하므로 셋 모두 순수 가상입니다.
- **`crypto/hashers/md4.hpp`/`md5.hpp`/`sha1.hpp`/`sha224.hpp`/`sha256.hpp`/`sha384.hpp`/`sha512.hpp`**
  (그리고 대응하는 `src/crypto/hashers/*.cpp`)는 `MD4`, `MD5`, `SHA1`,
  `SHA224`, `SHA256`, `SHA384`, `SHA512`를 밑바닥부터 구현합니다(제3자 의존성
  없음) — 각각 구체 `IHasher`이고, 인터페이스 자체를 정의하는
  `crypto/hasher.hpp`(단수)와 달리 `hashers/` 하위 디렉터리(복수)에
  있습니다. `crypto/asym.hpp`/`asyms/`도 비대칭 알고리즘에 대해 정확히 같은
  단수-인터페이스/복수-구현 분리를 따릅니다 — X.509 도구들이 널리 참조하는
  암호학적 해시 함수들(메시지 digest, 인증서 지문,
  `AuthorityKeyIdentifier`/`SubjectKeyIdentifier` 계산, 그리고 레거시 서명
  알고리즘)이므로, `C` 접두사가 아니라 알고리즘 이름 그대로
  붙였습니다(`CMD5`가 아니라 `MD5`). `asn1`의 enumerator들이 새 이름을
  만들어 내지 않고 표준 자신의 약칭을 쓰는 방식과 일치합니다. MD4, MD5,
  SHA-1은 암호학적으로 깨졌고 그것들을 아직 참조하는 레거시 인증서/지문과
  상호운용하는 데에만 쓸모가 있으며 새로 만드는 무엇에도 절대 쓰지 않습니다 —
  MD4가 가장 그런데, NTLM과 EAP-MSCHAPv2가 NT 해시를 UTF-16LE 비밀번호의
  MD4로 정의하고 그것들을 말해야 하는 클라이언트에게 다른 선택이 없기
  때문에만 여기 있습니다. 각각 private `Context` 구조체(진행 중인 상태 워드
  + 처리되지 않은 입력 버퍼 + 전체 길이 카운터)를 자기 블록 크기에 맞춰
  보유합니다(MD4/MD5/SHA-1/SHA-224/SHA-256은 64바이트, SHA-384/SHA-512는
  128). `push()`는 이전 호출에서 남은 부분 블록을 채우고, 호출자의 span에서
  직접 소비할 수 있는 만큼 전체 블록에 대해 압축 함수를 돌린 뒤, 남은
  것(블록 하나보다 적습니다)을 버퍼에 담습니다. `finish()`는 `_ctx`를
  제자리에서 변경하는 대신 컨텍스트의 *지역 사본*에 대해 padding + 압축을
  돌리므로(스크래치 인스턴스를 만들어 그 `Context`를 덮어씁니다), 한 번 넘게
  호출할 수 있고 살아 있는 객체를 건드리지 않으면서 항상 같은 digest를
  반환합니다 — 그 뒤에 다시 `push()`를 호출하면 `finish()`가 호출된 적 없는
  것처럼 원래의 (마무리되지 않은) 상태를 그대로 이어 갑니다.
  MD4와 MD5는 메시지 워드와 64비트 길이 필드를 리틀엔디언으로
  담습니다(전체가 빅엔디언인 SHA 계열과 다른 한 지점입니다). MD4는 MD5의
  직계 조상이고 padding과 버퍼링을 정확히 공유하지만, 4라운드가 아니라 16단계
  3라운드를 돌고, 단계마다가 아니라 라운드마다 상수 하나를 더하고(없음, 그
  다음 `sqrt(2) * 2^30`, 그 다음 `sqrt(3) * 2^30`), MD5의 2라운드가 선택
  함수를 쓰는 자리에 다수결 함수를 쓰며 — 그리고 어떤 공식으로도 만들어지지
  않는 부분 — 2라운드와 3라운드의 메시지 워드 순서를 MD5의 산술적
  `(5i + 1) % 16` 계열이 아니라 RFC 1320 3.4에 적혀 있는 고정 순열에서
  가져옵니다. SHA-1/SHA-224/SHA-256/SHA-384/SHA-512는 모두 같은 방식으로
  padding하지만(`0x80` 바이트, 블록 크기별 경계까지 0 바이트, 그 다음 비트
  길이) 알고리즘별 블록/워드 크기와 라운드 수를 씁니다. SHA-224와 SHA-256은
  초기 해시 값과 SHA-224의 절단된 출력(28바이트. 상태 워드 8개 중 앞 7개)
  외에는 동일하고, SHA-384와 SHA-512는 워드 크기가 한 단계 올라간 같은
  관계입니다(48바이트. 상태 워드 8개 중 앞 6개). 각 쌍은 진짜로 오류를
  일으키기 쉬운 한 조각 — 라운드별 압축 함수 — 를 각각 private(공개 API의
  일부가 아닌) `src/crypto/hashers/sha2_32core.hpp`/`.cpp`와
  `sha2_64core.hpp`/`.cpp`의 `Sha2_32Core::transform()`/
  `Sha2_64Core::transform()`을 통해 공유합니다. 그 외의 모든 것(`Context`
  배치, `reset()`/`push()`/`finish()`, padding)은 공유 기반 클래스로 빼지 않고
  `sha224.cpp`/`sha256.cpp` 사이에(그리고 별도로
  `sha384.cpp`/`sha512.cpp` 사이에) 중복해 두었습니다. 그 보일러플레이트는
  짧고 기계적이기 때문입니다 — 두 사본 사이에 어긋날 위험이 있을 만큼 실제로
  복잡한 부분(압축 함수)만 공유합니다. SHA-384/SHA-512의 128비트 길이 필드의
  상위 64비트는 항상 0으로 쓰이는데, 하위 64비트만으로도 넘치기 전에 2^61
  바이트까지 셀 수 있으므로 현실적인 어떤 입력에도 올바릅니다.

  `SHA1::transform()`/`Sha2_32Core::transform()`에는 추가로 하드웨어 가속
  경로가 있습니다(x86-64 전용이고, `CERTPP_DISABLE_HWACCEL_SHA`가 설정되지
  않았을 때만). `transformAccelerated()`는 같은 압축 함수를 이식 가능한
  라운드별 루프(`transformPortable()`) 대신 x86 SHA 확장(SHA-1에는
  SHA1RNDS4/SHA1NEXTE/SHA1MSG1/SHA1MSG2. 압축 함수를 공유하는
  SHA-224/SHA-256에는 SHA256RNDS2/SHA256MSG1/SHA256MSG2)으로 돌립니다. 이
  확장은 x86-64에서도 선택적이므로 런타임 CPUID 검사(`hasSha()`. leaf 7
  sub-leaf 0, EBX 비트 29) 뒤에 있으며 — 위의 `CBigNum::mul()`의
  `hasAdxBmi2()`/`CGf2m::mul()`의 `hasPclmul()` 관문과 같은 모양입니다. 이런
  코드에서 명령어 하나를 옮겨 적다 미묘하게 틀리기가 얼마나 쉬운지를 감안해,
  둘 다 독립적으로 유도한 것이 아니라 널리 알려진 Intel 발행 intrinsic
  수열입니다("Intel SHA Extensions". OpenSSL/BoringSSL/Linux 커널에도 같은
  것이 있습니다). 이 라이브러리의 기존 FIPS 180-4/RFC 3174 테스트 벡터로
  검증했으며(각 알고리즘의 'a' 백만 개 다중 블록 스트레스 벡터 포함. 이것이
  수천 개 블록에 걸쳐 `transform()`을 거칩니다), SHA-NI를 지원하는 CPU에서는
  전용 강제 경로 테스트 없이 가속 경로가 자동으로 거쳐집니다.
  MD5/SHA-384/SHA-512/SHA3-256/SHA3-512/SHAKE128/SHAKE256에는 대응물이
  없습니다 — MD5나 Keccak을 위한 주류 x86 하드웨어 확장이 없고,
  SHA-1/SHA-224/SHA-256에 있는 식으로 널리 배포된 x86 SHA-512 확장도 없으므로
  `Sha2_64Core::transform()`과 `SHAKE256`의 Keccak-f permutation은 이식
  가능 경로만 유지합니다.
- **`crypto/hashers/shake256.hpp` / `src/crypto/hashers/shake256.cpp`**는
  `SHAKE256`을 구현합니다. Keccak/SHA-3 계열(FIPS 202)의 256비트 보안 확장
  출력 함수(XOF)이며, 다른 모든 hasher와 마찬가지로 밑바닥부터입니다.
  MD5/SHA 계열과 구조적으로 다릅니다. 진행 중인 해시 상태에 대한 고정 크기
  압축 함수 대신 스펀지 구성입니다(136바이트 "rate" 블록 단위로
  Keccak-f[1600] permutation을 통해 1600비트 상태에 입력을 흡수한 뒤, 같은
  방식으로 출력을 짜냅니다). 진짜 XOF를 둘러싼 것이고, 그 출력 길이는
  알고리즘이 전혀 고정하지 않습니다 — 그래서 여기의 모든 고정 digest
  hasher와 달리 `byteWidth()`가 알고리즘의 내재적 속성이 아니라 생성자
  인자를 통해 *호출자*가 설정합니다(Ed448의 용도에는 `SHAKE256(114)`,
  그 외에는 `SHAKE256()`이 기본 32). 명세 문서에서 손으로 옮겨 적지 않고
  Python `hashlib`(성숙하고 독립적인 구현)으로 로컬 생성한 기지 응답 벡터로
  검증했으며, off-by-one padding 버그를 잡기 위해 특별히 136바이트 rate
  경계에 정확히/하나 아래/하나 위인 입력들을 포함합니다 — 회전 오프셋
  테이블의 초기 전치 버그(행과 열이 FIPS 202 자신의 배치에서 뒤바뀐 것)가
  `Ed448`에 닿기 전에 곧바로 잡힌 방식이 바로 그것입니다. `Ed448`(RFC
  8032)이 필요하며, 그것은 `Ed25519`가 SHA-512를 쓰는 모든 곳에서
  `SHAKE256(x, 114)`를 씁니다.

  Keccak-f[1600] permutation과 스펀지 흡수 로직
  (`theta`/`rho`/`pi`/`chi`/`iota`, 24라운드, 그리고 다중 rate `0x1F`/`0x80`
  도메인 분리 padding)은 rate와 무관합니다 — 즉 1600비트에서 보안 수준의 2배를
  뺀 rate가 무엇이든 어느 SHAKE 변종에나 동일합니다 — 그래서 알고리즘별로
  중복하지 않고 공유 private `KeccakCore` 클래스
  (`src/crypto/hashers/keccakcore.hpp`/`.cpp`, `STATE_BYTES=200`,
  `permute()`/`absorbBlock()`)에 있습니다. `SHAKE256`(RATE=136, 512비트 용량)과
  `SHAKE128`(`crypto/hashers/shake128.hpp`/`src/crypto/hashers/shake128.cpp`,
  RATE=168, 256비트 용량)은 둘 다 자기 rate로 `KeccakCore`를 구동하기만
  합니다. `EHashers`는 기존 `EHASH_SHAKE256` 옆에 `EHASH_SHAKE128`을
  얻었습니다. `SHAKE128`은 `SHAKE256`과 같은 방식으로 검증합니다 — Python
  `hashlib`으로 생성한 벡터(167/168/169바이트 입력의 rate 경계 케이스 포함)와
  NIST가 발행한 벡터 하나(CSRC의 `SHAKE128_Msg0.pdf` 빈 메시지 예제. PDF에서
  옮겨 적다 생긴 오류를 배제하기 위해 `hashlib.shake_128`과 교차
  확인했습니다). 현재 이 라이브러리의 어떤 서명/암호 알고리즘도 쓰지
  않습니다(`SHAKE256`/Ed448과 달리) — [`docs/pqc-review.ko.md`](pqc-review.ko.md)에
  설명된 ML-KEM/ML-DSA 기초 작업의 첫 단계로, FIPS 203/204가 둘 다 행렬/벡터
  확장에 SHAKE128을 쓰므로 필요해지기 전에 추가했습니다.

  두 XOF 모두 추가로 `squeeze(const SByteSpan&)`를
  `finish()` 옆에 노출합니다. 연속 호출은 출력 스트림의 연속 chunk를
  반환하며 스펀지를 전진시키므로, 출력 길이가 `byteWidth()`와 무관합니다.
  `finish()`는 고정 길이이고 반복 가능한 관점이며(사본에서 짜내고 커서를
  건드리지 않습니다), `squeeze()`가 스트리밍 쪽입니다. 둘은 번갈아 쓸 것이
  아니라 대안입니다. 이것이 존재하는 이유는 FIPS 203의 `SampleNTT`와
  FIPS 204의 챌린지/마스크 확장이 충분한 후보가 수락될 때까지 SHAKE
  스트림에서 거부 샘플링을 하기 때문입니다 — 길이를 미리 알 수 없습니다.
  `MlKemSampler::sampleNtt()`는 시드에 따라 453–498바이트를 소비하는데,
  그것이 구체적인 증명입니다.
- **`crypto/hashers/sha3_256.hpp`/`sha3_512.hpp` /
  `src/crypto/hashers/sha3_256.cpp`/`sha3_512.cpp`**는 SHA3-256과
  SHA3-512(FIPS 202 6.1)를 구현합니다. 이름과 달리 이것들은 SHA-2의 변종이
  아닙니다. SHA-3는 위의 SHAKE XOF와 같은 스펀지이므로 같은 `KeccakCore`
  permutation을 재사용하고, 두 digest에 공통인 버퍼링/padding은 공유 private
  `Sha3Core`(`src/crypto/hashers/sha3core.hpp`/`.cpp`)에 있습니다 —
  `Sha2_32Core`가 SHA-224와 SHA-256 사이에 갖는 것과 같은 배치이며, 각 공개
  헤더가 `src/` 아래의 무엇에도 의존하지 않고 자기 컨텍스트를 선언할 수 있도록
  원시 배열에 대한 자유 함수로 되어 있습니다. SHA-3는 SHAKE와 정확히 두
  지점에서 다릅니다. rate가 `200 - 2*digestWidth`이고(SHA3-256은 136바이트,
  SHA3-512는 72바이트. 용량이 출력 길이의 두 배입니다), 도메인 분리 바이트가
  SHAKE의 `0x1F`가 아니라 `0x06`입니다. 그 바이트 하나가 동일한 스펀지 위에서
  같은 길이의 SHA-3 digest와 SHAKE 출력 사이의 차이 전부이고, 그래서
  `tests/crypto/hashers/sha3.cpp`는 digest를 벡터에 대조하는 것만이 아니라
  그 둘이 실제로 다르다는 것을 단정합니다. `finish()`는 XOF의 관례가 아니라
  SHA-2의 관례를 따릅니다. 스펀지를 건드리지 않는 조회이므로 반복되며 그
  뒤에도 흡수를 이어 갈 수 있습니다. 이것들은 ML-KEM이 FIPS 203의 `H`와
  `G`로 필요해서 추가되었지만(라이브러리에 SHAKE는 있었으나 고정 출력 SHA-3가
  전혀 없었으므로 `docs/pqc-review.ko.md`의 계획이 놓쳤던 선행 조건입니다),
  어디서든 쓸 수 있는 평범한 `EHashers` 멤버
  (`EHASH_SHA3_256`/`EHASH_SHA3_512`)입니다.
- **`crypto/keys.hpp` / `src/crypto/keys.cpp`**는
  `SKeySize`/`SKeySizeSpec`(`IAsymmetric`이 자기 `keySizes()`를 검증하는
  `{minSize, maxSize, step}` 범위), `IKeyBase`(`keySize()`,
  `serialize(COctet&)`, `compare()` — 대칭이든 비대칭이든 모든 키에 공통),
  `IPublicKey`/`IPrivateKey`(비대칭의 경우에 대해 `IKeyBase`를 확장하고,
  `IStream` 식 `Ptr` 별칭을 가지며, 직접 생성되는 일이 없습니다 —
  `IAsymmetric`만이 만들어 냅니다. `IPrivateKey`는 자기 공개 절반을 유도하는
  `publicKey()`를 더합니다), 그리고 `SKeyPair`(그 둘을 짝지은 평범한 구조체.
  인터페이스가 아닙니다 — 키 쌍은 그 절반들 외의 어떤 동작도 없습니다)를
  정의합니다. 같은 헤더는 KEM을 위한 세 번째 병렬 키 계열도 정의합니다(아래
  `crypto/kem.hpp` 참고): `EKems`, `IKemKeyBase`,
  `IKemPublicKey`/`IKemPrivateKey`, `SKemKeyPair` —
  `EAsymmetrics`/`IAsymmetricKeyBase`/`IPublicKey`/`IPrivateKey`/`SKeyPair`를
  정확히 반영하되, KEM 키는 여전히 비대칭이지만 서명 키도 DH 키도 아니므로
  별개 계열로 두었습니다(`ESymmetrics`가 이미 쓰고 있는 것과 같은 논리입니다).
- **`crypto/kem.hpp` / `src/crypto/kem.cpp`**는 `IKem`/`IKemContext`를
  정의합니다. `asym.hpp`의 `IAsymmetric`/`IAsymmetricContext`에 대응하는 키
  캡슐화 쪽입니다. `IKem::builtIn()`은 `EKems`의 세 멤버 —
  `EKEM_MLKEM512`/`EKEM_MLKEM768`/`EKEM_MLKEM1024` — 를
  `MLKEM`(아래 `crypto/kems/mlkem.hpp`)으로 디스패치합니다. 이 인터페이스는
  [`docs/pqc-review.ko.md`](pqc-review.ko.md)의 ML-KEM 작업 첫 단계로서 어떤
  격자 암호 구현보다 먼저 설계되고 커밋되었고, 그래서 `IAsymmetric`을 그만큼
  가깝게 반영합니다. 단지 `IAsymmetric`을 재사용한 것이 의도적으로
  아닙니다. KEM의 핵심 연산은 알고리즘이 고른 공유 비밀을, 그것을 캡슐화한
  ciphertext와 *함께* 만들어 내는데, 이는 `createEncrypter()`의 "호출자가
  제공한 이 평문을 암호화해라" 모양과 다르므로, 그것을 `IAsymmetric`에
  억지로 끼우면 입력이 무시되는 `transform()` 호출을 뜻하게 됩니다 — 작은
  형제 인터페이스보다 나쁜 맞춤입니다. `IKem`은 그 한 가지 차이가 허용하는
  한 `IAsymmetric`의 모양을 가깝게 반영합니다. `builtIn(EKems)`,
  `keySizes()`, `generateKeyPair()`, `checkPrivateKey()`,
  `createPublicKey()`/`createPrivateKey()`(span과 `COctet` 오버로드), 그리고
  `createContext()`입니다. `IKemContext`는 `IAsymmetricContext`의 "인자로
  넘긴 것이 아니라 바인딩된 키에 대해 작동한다"는 관례를 따릅니다.
  `encapsulate(SByteSpan& ciphertext, SByteSpan& sharedSecret)`는 바인딩된
  *공개* 키에 대해 작동하고(상대의 것. 두 키를 받는 `keyPair(pub, nullptr)`
  오버로드로 바인딩합니다 — 호출자는 그 상대*에게* 캡슐화하는 것입니다),
  `decapsulate(SReadOnlyByteSpan ciphertext, SByteSpan& sharedSecret)`는
  바인딩된 *개인* 키에 대해 작동합니다.
  `sizeOfCiphertext()`/`sizeOfSharedSecret()`는
  `sizeOfSign()`/`sizeOfDigest()`가 쓰는 기존의 getter는 public, setter는
  protected 분리를 따릅니다.
- **`crypto/kems/mlkem.hpp` / `src/crypto/kems/mlkem.cpp`**는 ML-KEM
  (FIPS 203)과 그 아래의 K-PKE 스킴을 원시 바이트 span 위에 구현합니다.
  이것은 알고리즘 자체이고 키 객체나 컨텍스트에 대한 어떤 견해도 없으므로
  테스트 벡터에서 바로 구동할 수 있습니다. 위의 `IKem`/`IKemContext` 모양이
  배선된 뒤에는 대부분의 호출자가 그쪽을 선호해야 하며, 그것이 이 위에
  앉습니다. 헤더는 네 타입을 공개합니다.
  - `SMlKemPoly`. R_q = Z_q[X]/(X^256+1)의 원소 하나를 256개 `int16_t`
    계수로 담고, `COEFFICIENTS`/`MODULUS`/`ROOT_OF_UNITY`를 지닙니다. 같은
    배치가 NTT 영역 값도 담는데, 그것은 다항식이 아니라 1차 블록 128개입니다.
    FIPS 203도 자기 데이터 타입에서 둘을 구별하지 않으므로, 어떤 인스턴스가
    어느 쪽을 담고 있는지는 호출자가 추적할 일입니다.
  - `SMlKemParams`. FIPS 203 표 2의 세 파라미터 집합 중 하나를
    `{k, eta1, eta2, du, dv}`와 `mlKem512()`/`mlKem768()`/`mlKem1024()`로
    담습니다. 그 다섯 수치만 저장되고,
    `ekBytes()`/`dkBytes()`/`dkPkeBytes()`/`ciphertextBytes()`/
    `sharedSecretBytes()`/`seedBytes()`는 모두 그것들에서 유도되며,
    `tests/crypto/kems/kat_mlkem.cpp`가 유도된 결과를 발행된 표에 대해
    `static_assert`로 고정합니다. 잘못 타이핑한 키
    길이는 정확히 내부적으로 일관된 채로 남는 종류의 오류입니다 — 틀린 `ek`
    길이를 전체적으로 쓰는 구현도 자기 자신과는 여전히 왕복합니다 — 그래서
    그 크기들은 잘못 적어 둘 수 없게 만들어 두었습니다. `isValid()`는 그
    집합이 셋 중 하나인지 보고하고 `equals()`는 둘을 비교합니다. 모든
    `CMlKem` 진입점이 `isValid()`를 먼저 호출하고 아니면 거부합니다. 그것은
    까다로움이 아니라 메모리 안전성 요구입니다. `SMlKemParams`는 공개이므로
    호출자가 손으로 만든 집합을 건넬 수 있고, 구현은 고정 용량 버퍼 크기를
    `MAX_K`와 `maxCiphertextBytes()`에서 잡습니다.
  - `CMlKemSampler`. FIPS 203의 두 샘플러입니다. `sampleNtt()`(알고리즘 7.
    SHAKE128 스트림에서 균일한 NTT 영역 다항식을 거부 샘플링)와
    `samplePolyCbd()`(알고리즘 8. PRF 출력을 Module-LWE가 필요한 작은 계수의
    노이즈로 바꿉니다)입니다. `sampleNtt()`는 두 인덱스 바이트를 주어진
    순서대로 덧붙입니다. FIPS 203의 행렬 확장이 그것을
    `SampleNTT(rho || j || i)`로 호출하기 때문인데, 자연스러운 루프 순서에
    대해 전치되어 있고 표준 자신의 여백 주석이 그것을 표시합니다.
  - `CMlKem`. 스킴입니다.
    `generateKeyPair()`/`encapsulate()`/`decapsulate()`(알고리즘 16–18),
    `checkEncapsulationKey()`/`checkDecapsulationKey()`(FIPS 203 6.2의 입력
    검사), 그리고 `kpkeKeyGen()`/`kpkeEncrypt()`/`kpkeDecrypt()`(알고리즘
    13–15)입니다. `encapsulate()`는 32바이트 메시지를 뽑지 않고 명시적으로
    받으므로 벡터에서 재현 가능합니다 — 그 말은 테스트 밖의 호출자는 새
    CSPRNG 출력을 넘겨야 한다는 뜻입니다. 메시지를 재사용하면 공유 비밀을
    재사용하기 때문입니다.

  미묘함은 전부 `decapsulate()`에 있습니다. ML-KEM은 K-PKE 위의
  Fujisaki-Okamoto 변환이고, 이것이 IND-CPA 스킴을 IND-CCA2로 끌어올립니다.
  복호한 것을 다시 암호화해 자기가 받은 ciphertext와 비교하고, 불일치하면
  오류가 아니라 `J(z || ciphertext)` — 개인키 자신의 거부 시드에서 유도된
  비밀 — 을 반환합니다. 따라서 잘못된 ciphertext는 제대로 생긴, 그러나
  무관한 공유 비밀을 내놓고 호출자는 두 경우를 구별할 수 없습니다. 거기서
  실패를 보고하거나 재암호화를 건너뛰는 것은 이 변환이 존재해서 막으려는
  바로 그 복호 oracle을 건네주는 일입니다. 그래서 `decapsulate()`에는 나쁜
  ciphertext에 대한 실패 모드가 아예 없고, 구조적으로 크기가 틀린 것에
  대해서만 있습니다.

  "두 경우를 구별할 수 없다"는 타이밍에 대해서도 성립해야 하므로, 비교는
  `CSecure::equalsMask`이고 두 비밀 사이의 선택은 `CSecure::select`입니다 —
  `std::memcmp`는 재암호화가 얼마나 긴 접두사까지 일치했는지를 누출할 것이고,
  판정에 대한 삼항 연산자는 그 판정이라는 한 비트를 누출할 것입니다. 이 함수는
  탈출 지점이 하나이므로 오류 경로가 `CSecure::zero`를 건너뛸 수 없는데,
  그것이 거부 플래그가 반환 전에 파괴되어야 한다는 FIPS 203의 요구입니다.

  세 파라미터 집합 전부에 대해 NIST의 ACVP 벡터로 검증했으며, 그 거부 경로를
  거치는 `modified ciphertext` 케이스와
  `encapsulationKeyCheck`/`decapsulationKeyCheck` 음성 케이스를 포함합니다 —
  `tests/crypto/kems/kat_mlkem.cpp`를 보십시오. FIPS 203은 작업 예제를 전혀
  발행하지 않으므로 그 벡터들이 구할 수 있는 유일한 외부 oracle입니다.

  같은 헤더는 그 다음 **`MLKEM`**을 선언합니다. `IKem`의 유일한 구현이고,
  파라미터 집합을 생성자 상태로 삼아 한 클래스로 세 ML-KEM 파라미터 집합
  전부를 담당합니다 — `CEcdsa`가 자기 곡선들에 걸쳐 갖는 배치입니다. 자신은
  암호학적인 것을 아무것도 구현하지 않습니다. 위의 `CMlKem`이 알고리즘이고,
  이것은 키 객체들, `IKemContext`가 노출하는 크기 장부, 그리고 그 주변의
  CSPRNG 추출입니다.

  `keySizes()`는 인스턴스당 정확히 한 크기를 받아들이며, 그 크기는 모듈러스
  폭이나 주장되는 보안 강도가 아니라 파라미터 집합 자신의 수(512, 768,
  1024)입니다. ML-KEM에는 스케일하는 크기가 없습니다 — 집합들은 모듈 랭크
  `k`와 다른 네 파라미터에서 다르고, 그 세 숫자는 이름입니다. 그 이름을
  넘기면 `generateKeyPair()`가 라이브러리의 다른 모든 알고리즘과 같은 방식으로
  쓸 수 있게 유지되며, 뜻하지 않는 것을 뜻하는 것처럼 보이는 수치를 만들어
  내지 않아도 됩니다.

  키는 FIPS 203 자신의 인코딩으로만 직렬화됩니다. 공개키는 캡슐화 키,
  개인키는 디캡슐화 키입니다. 디캡슐화 키는 오프셋 `dkPkeBytes()`에 자기
  캡슐화 키를 품고 있으므로, `IKemPrivateKey::publicKey()`는 다시 계산하지
  않고 그것을 읽어 내고, `checkPrivateKey()`는 그렇다고 가정하는 대신 둘이
  일치하는지(더해서 품고 있는 `H(ek)`와 `ek`가 정규적인지)를 검증합니다.
  `createPublicKey()`/`createPrivateKey()`도 같은 검사를 적용하는데, 거기에
  도달한 키는 외부에서 온 것이기 때문입니다. 인증서가 필요한
  SubjectPublicKeyInfo 래핑은 여기가 아니라
  [`docs/pqc-review.ko.md`](pqc-review.ko.md)의 6단계입니다.

  이것은 또한 ML-KEM 구현에서 난수를 끌어오는 유일한 계층입니다.
  `CMlKem::generateKeyPair()`/`encapsulate()`는 테스트 벡터에서 구동될 수
  있도록 시드와 메시지를 파라미터로 받습니다.
  `IKemContext::encapsulate()`에는 그런 파라미터가 없으므로 `MLKEM`이
  `CRng`에서 채우며 — 그 말은 이 계층에서는 쓸 수 있는 기지 응답 테스트가
  없다는 뜻이기도 하고, `tests/crypto/kems/mlkem.cpp`는 알고리즘이 아니라
  래퍼가 추가하는 것을 다룹니다(여러 가지 중에서, 한 키에 대한 반복
  `encapsulate()` 호출이 서로 다르다는 것을 단정합니다. 키만의 함수인 공유
  비밀이라면 세션마다 재사용될 것이기 때문입니다).
- **`src/crypto/kems/mlkemring.hpp`/`.cpp`,
  `src/crypto/kems/mlkemcodec.hpp`/`.cpp`**는 `CMlKem`이 올라앉은 연산과 와이어
  인코딩을 담습니다. `MlKemRing`(R_q 위의 NTT, 역 NTT, 기본 경우 곱셈, 그리고
  나머지를 확인하기 위해서만 존재하는 schoolbook negacyclic 곱셈)과
  `MlKemCodec`(ByteEncode/ByteDecode, Compress/Decompress,
  `isCanonical12`)입니다. 둘 다 `src/`에 private으로 남습니다 — 평범한
  `PascalCase`이고 `CERTPP_API`가 없습니다 — ML-KEM 구현 밖의 무엇도 그것들에
  손을 뻗을 이유가 없고, `SMlKemPoly`가 그것들이 공개 헤더와 공유하는
  유일한 타입이기 때문입니다. export되지 않으므로
  `tests/crypto/kems/` 아래의 테스트가 그것들을 자기 실행 파일로 컴파일해
  넣습니다. [`docs/build.ko.md`](build.ko.md)를 보십시오.
- **`src/crypto/asyms/mldsaring.hpp`/`.cpp`**는 `MlDsaRing`을 정의합니다.
  q = 8380417인 ML-DSA의 환 R_q = Z_q[X]/(X^256 + 1)에서의 연산(FIPS 204 4)
  이며, ML-DSA의 첫 조각이고 역시 `src/`에 private입니다. `MlKemRing`의
  파라미터화가 아니라 의도적으로 별개 단위인데, 세 가지 차이가 상수보다
  깊기 때문입니다.
  - q = 2^23 - 2^13 + 1이므로 계수는 23비트와 `int32_t` 저장이 필요하고, 두
    계수의 곱은 약 7.0e13에 이릅니다 — `int32_t`를 네 자릿수만큼 넘치므로
    모든 중간값이 `int64_t`로 돌아갑니다. ML-KEM의 환에서는 같은 곱이
    `int32_t`에 여유 있게 들어갑니다. 그 습관을 그대로 가져오는 것은 조용한
    wraparound 버그가 될 것입니다. 트위들 테이블 생성기도 물리는데, 거기서
    `ZETA * acc`가 약 1.5e10에 이릅니다.
  - `ZETA = 1753`의 위수가 256이 아니라 정확히 **512**이므로 X^256 + 1이
    끝까지 256개 1차 인자로 쪼개지고 NTT가 **완전**합니다. 8단, 256개 독립
    평가점입니다. ML-KEM의 변환은 한 단 앞에서 멈추고 128개 1차 블록을
    남기는데, 그것들은 기본 경우 곱셈과 두 번째 트위들 테이블이 필요합니다.
    그래서 여기의 `multiplyNtt()`는 평범한 pointwise 곱셈이고, `gammas()`는
    아예 없습니다.
  - 인덱스 순열은 ML-KEM의 `bitRev7`에 대해 여덟 비트에 걸친 `bitRev8`입니다.

  변환 외에 `centered()`(FIPS 204의 `mod±`. (-q/2, q/2] 안의 대표원)와,
  ML-DSA의 서명 루프가 거부 기준으로 삼는 `infinityNorm()`을 제공하므로,
  후자는 호출자가 아니라 환에 속합니다. 아무것도 Montgomery 형태로 보관하지
  않습니다. FIPS 204 부록 A는 구현들이 보통 zetas 배열을 그렇게 저장한다고
  경고하는데, 그것이 거기서의 표현 불일치를 이 라이브러리가 전에 물린 적
  있는 바로 그 자기 일관적이지만-틀린 실패 양상으로 만들므로,
  `tests/crypto/asyms/mldsaring.cpp`는 그 테이블을 자신의 정의적 성질에
  대해서뿐 아니라 부록 B에 인쇄된 값에 대해서도 확인합니다.
- **`src/crypto/asyms/mldsarounding.hpp`/`.cpp`**는 `MlDsaRounding`을
  정의합니다. FIPS 204 7.4의 라운딩과 hint 기계입니다. `power2Round`,
  `decompose`, `highBits`/`lowBits`, `makeHint`, `useHint`이고 스칼라
  버전과 다항식별 버전이 있습니다. 역시 `src/`에 private입니다.

  hint 메커니즘이 이것이 존재하는 이유입니다. 서명은 w1 자체가 아니라 계수당
  한 비트를 담고, 검증자는 자기 근사와 그 비트들로
  `HighBits(w - c*s2 + c*t0)`를 재구성합니다 — 이는 `useHint()`가
  `makeHint()`를 정확히 역으로 돌릴 때만, 그리고 교란이 gamma2 안에 머무는
  동안만 동작하며, 그 경계를 강제하는 책임은 서명 루프에 있습니다. 테스트는
  그 항등식을 무작위 쌍에 대해, 그리고 별도로 버킷 경계와 예외 구간 전체에
  걸쳐 확인하는데, 무작위 샘플링은 거기에 사실상 절대 떨어지지 않습니다.

  두 가지 함정이 다시 발견되도록 남겨 두는 대신 헤더에 문서화되어 있습니다.
  - **`decompose()`의 `(q-1)` 예외는 점이 아니라 구간입니다.** 알고리즘 36은
    `r+ - r0 == q - 1`로 분기하는데, 이는 "r == q-1이라는 단일 값"처럼
    읽히지만 그렇지 않습니다. 그 조건은 폭 gamma2의 최상단 구간 전체에서
    성립합니다 — gamma2 = (q-1)/88에서 95,232개 값(q의 1.14%),
    (q-1)/32에서는 261,888개(3.1%)입니다. 점 비교로 단순화하는 당연해 보이는
    선택은 첫 경우에 95,231개 입력에 대해 틀리고, 외부 벡터만이 그것을 잡을
    수 있습니다.
  - **여기의 `mod±`는 `MlDsaRing::centered()`가 아닙니다.** 그쪽은 홀수인 q로
    축약하므로 분기점이 (q-1)/2에 있습니다. 이쪽은 둘 다 짝수인 2^d와
    2*gamma2로 축약하고, 범위는 (-m/2, m/2]이며 m/2 자체는 양수로 남습니다.
    같은 정의, 다른 모듈러스, 다른 경계 — 그래서 별도의 `modPm()`이 있습니다.
- **`src/crypto/asyms/mldsacodec.hpp`/`.cpp`**는 `MlDsaCodec`을 정의합니다.
  FIPS 204 7.1–7.2의 비트 패킹과 hint 인코딩 — ML-DSA의 키와 서명이 올라앉은
  와이어 포맷입니다. `simpleBitPack`/`simpleBitUnpack`은 [0, b]의 계수를
  다루고, `bitPack`/`bitUnpack`은 `b - w_i`를 인코드해 [-a, b]를 다루므로
  부호 있는 범위가 부호 없는 필드에 들어갑니다. 비트는 ML-KEM과 마찬가지로
  각 바이트 안에서 리틀엔디언으로 흐릅니다.

  **디코딩은 범위를 함의하지 않으며**, FIPS 204 자신이 알고리즘 17 아래에서
  그렇게 말합니다. 어떤 (a, b)에 대해서는 명목 범위 밖으로 디코드되는 바이트
  문자열이 존재하는데, 신뢰할 수 없는 입력에 대해 중요한 일입니다. 범위가 자기
  비트 폭을 정확히 채우는지에 달려 있고, ML-DSA의 용도들에 대해서는 깔끔하게
  갈립니다 — `t1`, `t0`, `z`는 안전합니다. `s1`/`s2`는 아닙니다(eta = 2에서
  3비트가 -5까지 디코드되고, eta = 4에서 4비트가 -11에 이릅니다). 그래서
  `skDecode`가 범위를 검사해야 합니다. 그리고 `w1`은 b = 43에서 안전하지
  않지만 인코드만 되고 받는 일이 없습니다. 필요한 경우를 위해 `inRange()`가
  있습니다. 이것은 ML-KEM의 `ByteDecode_12`와 같은 모양의 위험입니다.

  `hintBitUnpack()`은 표준에서 가장 날카로운 디코드 함정이고, 세 가지 *서로
  다른* 조건에서 거부합니다. 뒤로 가거나 omega를 넘는 누적 인덱스,
  **한 다항식 안에서** 엄격히 증가하지 않는 위치, 그리고 0이 아닌 남은
  바이트입니다. 각각이 이 인코딩을 단사로 만드는 것이고, 셋보다 적게
  구현하면 가변적인 서명을 수락합니다 — 그것이 ACVP의 "modified signature -
  hint" 36개 케이스가 테스트하는 것입니다. 한 다항식 안이라는 범위는 양방향
  모두에서 중요합니다. 위치는 다항식 경계를 넘을 때 정당하게 *감소*하므로,
  대신 배열 전체에 대해 단조성을 검사하면 유효한 서명을 거부합니다.
  거부된 디코드는 호출자의 다항식들을 반쯤 쓴 상태가 아니라 건드리지 않은
  상태로 남깁니다.
- **`src/crypto/asyms/mldsasampler.hpp`/`.cpp`**는 `MlDsaSampler`를
  정의합니다. FIPS 204 7.3의 의사난수 샘플링입니다. `sampleInBall`,
  `rejNttPoly`, `rejBoundedPoly`, 그리고 그것들 위의
  `expandA`/`expandS`/`expandMask` 절차입니다. 세 샘플러 모두 시드에 따라
  달라지는 양의 스트림을 소비하므로 `finish()`가 아니라 `squeeze()`로
  읽습니다 — 증분 스퀴징이 편의가 아니라 엄격한 선행 조건이었던 이유입니다.

  여기서 두 가지가 틀리기 쉽고 외부 벡터 없이는 보이지 않습니다. XOF는
  교체 가능하지 않습니다. `rejNttPoly`/`expandA`는 SHAKE128(표준의 `G`)을,
  그 외 모든 것은 SHAKE256(`H`)을 씁니다. 그리고 **`expandA`의 시드가
  전치되어 있습니다** — 항목 `A[r][s]`에 대해 `rho || s || r`로, 행 바이트
  앞에 열 바이트가 오며, ML-KEM의 `SampleNTT(rho || j || i)`와 정확히
  같습니다. 둘 다 완벽히 자기 일관적이면서 아무것과도 상호운용하지 않는
  스킴을 만들어 냅니다.
- **`src/crypto/asyms/mldsaparams.hpp`**는 `MlDsaParams`를 정의합니다.
  FIPS 204 표 1의 세 파라미터 집합이고, 모든 길이를 적어 두는 대신 그것들에서
  유도하며, `tests/crypto/asyms/mldsaparams.cpp`가 표 2에 대해
  `static_assert`합니다. 그 값 중 둘은 독자가 기대하는 대로 동작하지
  않습니다. **eta는 집합들에 걸쳐 단조가 아니고**
  (ML-DSA-44/65/87에 대해 2, 4, 2), **gamma1은 공유됩니다**(ML-DSA-65와
  -87이). 따라서 어느 쪽도 집합을 구별하는 데 쓸 수 없습니다.
- **`src/crypto/asyms/mldsascheme.hpp`/`.cpp`**는 `MlDsaScheme`을 정의합니다.
  원시 바이트 span 위의 ML-DSA 자체입니다. FIPS 204 7.2의 키와 서명 인코더
  (`pkEncode`/`pkDecode`, `skEncode`/`skDecode`, `sigEncode`/`sigDecode`,
  `w1Encode`), 그리고 내부(알고리즘 6–8)와 외부(알고리즘 2–3) 양쪽 형태의
  KeyGen/Sign/Verify입니다. xi와 rnd를 뽑지 않고 파라미터로 받는데, 그것이
  테스트 벡터에서 바로 구동될 수 있게 하는 요소입니다.

  ML-KEM의 `CMlKem`과 달리 `src/`에 private으로 남습니다. 모든 진입점이
  `MlDsaParams`로 파라미터화되어 있으므로, 그 시그니처를 export하는 것은
  이미 테스트된 그 private 헤더를 공개 API로 옮기거나 중복하는 것을 뜻할
  것이고, 호출자가 실제로 필요한 표면은 어차피 `IAsymmetric` 모양입니다.

  **메시지 관례가 둘 있고 서로 교체 가능하지 않습니다.** 내부 인터페이스는
  `M'`을 그대로 서명합니다. 외부 것은 먼저
  `IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx`를 앞에 붙이며,
  그것이 RFC 9881의 `id-ml-dsa-*` OID가 뜻하는 것입니다 — 그래서 X.509
  서명은 TBS 바이트만이 아니라 `0x00 || 0x00 || tbsCertificate`를 덮습니다.
  대신 원시 메시지를 서명하는 것은 자기 자신에 대해서는 완벽히 왕복하면서
  모든 진짜 인증서를 거부합니다. `tests/crypto/asyms/kat_mldsa.cpp`는 두
  인터페이스가 서로 다르며 각각 상대의 서명을 거부한다고 단정하므로, 그 구분이
  조용히 무너질 수 없습니다.

  `sign()`/`verify()`는 접두사와 메시지를 한 버퍼로 이어 붙이는 대신 mu를
  직접 계산해 내부 형태에 그것의 `externalMu`로 건넵니다. mu가
  `H(tr || M')`이고 `H`가 자기 부분들을 순서대로 흡수하므로 결과는 비트 단위로
  동일하되, 메시지가 복사되는 일이 없습니다 — 그것이 3 KiB TBSCertificate가
  아니라 문서일 때 중요한 일입니다. `tr`은 개인키의 고정 오프셋에 있으므로
  읽는 데 비용이 들지 않습니다. 같은 `externalMu` 파라미터가 ACVP의
  `externalMu: true` 그룹도 담당합니다.

  `skDecode`는 **s1/s2의 범위를 검사하며**, 이는 선택적이지 않습니다.
  `2*eta + 1`이 5 또는 9이고 둘 다 2의 거듭제곱이 아니므로, 그 필드는 범위가
  포함하지 않는 값을 인코드합니다(eta = 2에서 -5까지, eta = 4에서 -11까지).
  FIPS 204 알고리즘 25는 그런 키를 거부하고, 그것을 디코드하는 모든 진입점도
  그렇게 합니다 — 저장소에서 온 개인키나 상대에게서 온 개인키는 신뢰할 수 없는
  입력이고, 범위를 벗어난 s1으로 서명하는 것은 짝이 되는 공개키에 대해서는
  여전히 검증되면서 스킴의 안전성 논증 밖에 떨어집니다.

  서명은 **aborts 있는 거부 루프**입니다. 각 반복이 새 마스킹 벡터를 뽑고 네
  경계 중 하나라도 실패하면 시도 전체를 버리므로, 반복 횟수가 키와 메시지에
  의존합니다. 들려줄 constant-time 이야기가 없고 FIPS 204도 그런 것을
  제시하지 않습니다. [`docs/pqc-review.ko.md`](pqc-review.ko.md)를 보십시오.
  작업 집합은 스택이 아니라 힙에 할당됩니다(`TArray<Poly>`). ML-DSA-87의
  것이 크기 때문입니다 — A-hat만으로도 8x7 다항식, 56 KiB이고, 그 옆에
  십여 개의 벡터가 더 있습니다.

  pure 변형만 구현되어 있습니다. HashML-DSA는 자기만의 별도
  `id-hash-ml-dsa-*` OID를 가지고, 이 라이브러리가 읽으려는 어떤 인증서에도
  나타나지 않으며, 현재 호출자가 없는데도 해시 OID 테이블을 끌어들일 것입니다.
- **`crypto/asyms/mldsa.hpp` / `src/crypto/asyms/mldsa.cpp`**는 `CMlDsa`를
  정의합니다. `IAsymmetric`으로서의 ML-DSA이고 파라미터 집합당 인스턴스
  하나입니다 — `CEcdsa`가 자기 곡선들에 걸쳐 갖는 것과 같은 배치이며,
  `IAsymmetric::builtIn(EASYM_MLDSA44 | EASYM_MLDSA65 | EASYM_MLDSA87)`로
  도달합니다. 서명/검증만 합니다.
  `createEncrypter()`/`createDecrypter()`와 `deriveSharedSecret()`은 모두
  `ERET_NOTSUP`을 보고합니다.

  **`sign()`/`verify()`의 `digest` 파라미터는 메시지이고 그것의 해시가
  아닙니다.** ML-DSA에는 외부에서 제공되는 digest가 없습니다 — 메시지를
  내부적으로, 서로 다른 도메인 분리로 두 번 해싱하고, 고정 폭 digest가 아니라
  격자 commitment를 서명합니다. 미리 계산한 SHA-256 값을 넘기면 *그 32바이트
  문자열에 대한* 유효한 ML-DSA 서명이 나오는데, 다른 어떤 구현도 만들거나
  확인하지 않을 것입니다. Ed25519/Ed448이 같은 이유로 그 파라미터를 같은
  방식으로 읽고, `CDnssecKeys::hasherOf()`가 반대쪽에서 같은 사실을
  진술합니다. 호출자에게 주는 신호는
  `sizeOfDigest()`이며, 바인딩된 ML-DSA 키에 대해 0으로 남습니다. 0은
  "계산할 digest가 없으니 메시지를 넘기라"는 뜻입니다. 파라미터는 인터페이스
  이름을 유지합니다. 구현별로 이름을 바꾸면 override 관계를 명확히 하기보다
  흐릴 것이기 때문입니다.

  `keySizes()`는 모듈러스 폭이나 보안 강도가 아니라 파라미터 집합 자신의
  수(44, 65, 87)를 받아들이며, `MLKEM`이 512/768/1024로 하는 것과 정확히
  같습니다 — ML-DSA에는 스케일할 수 있는 크기가 없고 그 숫자들은 이름입니다.
  키는 FIPS 204 자신의 인코딩으로만 직렬화되는데, 이 OID들에 대해
  `SubjectPublicKeyInfo` BIT STRING이 담는 것과 정확히 같은 것이기도 합니다
  (RFC 9881은 내부 `OCTET STRING` 없이 원시 공개키를 거기 두고 `parameters`를
  부재로 둡니다). 그래서 `CCert`는 DSA의 분리된 `Dss-Parms`가 요구하는 식의
  재구성 단계가 필요 없습니다. 개인키는 자기 공개키를 품고 있지 않으므로
  `IPrivateKey::publicKey()`는 키 자신의 rho/s1/s2에서 다시 유도하고 그 결과를
  저장된 `tr`(즉 `H(pk)`)에 대조해 확인합니다 — ML-DSA 개인키가 허용하는
  하나뿐인 내부 일관성 검사입니다.

  여기도 난수가 들어오는 곳이고, 들어오는 유일한 곳입니다. 서명은
  **hedged**입니다. 서명마다 새 32바이트 rnd이고 FIPS 204의 권장
  기본값이므로, 같은 메시지에 대한 두 서명이 다르며 기지 응답 테스트는 대신
  rnd = 0으로 `MlDsaScheme`을 거쳐야 합니다. 그것은 테스트용 편법이
  아닙니다 — 결정론적 서명은 표준 자신의 변형이고, ACVP의
  `deterministic: true` 그룹이 쓰는 것입니다.

  세 파라미터 집합 전부에 대해 NIST의 ACVP 벡터로 검증했습니다.
  `tests/crypto/asyms/kat_mldsa.cpp`(keyGen과 sigGen. 결정론적과 hedged,
  내부와 외부), `tests/crypto/asyms/kat_mldsaver.cpp`(sigVer. 네 가지 음성
  사유 — 변형된 메시지, commitment, hint, z — 전부 포함), 그리고 래퍼에
  대해서는 `tests/crypto/asyms/mldsa.cpp`입니다. 수락 테스트는
  `tests/x509/realcerts.cpp`이고, 거기서 실제 IdenTrust ML-DSA-87 파일럿
  루트가 자기 서명을 검증합니다.
- **`crypto/hmac.hpp` / `src/crypto/hmac.cpp`**는 `CHmac`을 정의합니다.
  여기의 임의의 고정 출력 hasher 위의 RFC 2104이며, `IHasher`의 스트리밍
  모양에 더해 일괄 `compute()`와 constant-time `verify()`가 있습니다.
  `IHasher`가 아닙니다. HMAC은 키를 받고 `IHasher::create()`에는 키를 둘 곳이
  없기 때문입니다. 인스턴스를 재키잉하면 바탕 hasher를 재사용하므로, HKDF의
  expand 루프가 블록마다 할당하지 않습니다. RFC 2104의 블록 크기는
  `IHasher`(`byteWidth()`만 노출합니다)가 아니라 여기에 있는데, 인터페이스에
  두면 그 생성자와 모든 구현을 바꾸는 것을 뜻하기 때문입니다. 그 대가로,
  나중에 추가되는 hasher는 `blockBytesOf()`가 확장될 때까지 지원되지
  않으며, 틀린 tag를 계산하는 대신 `reset()`에서 큰 소리로 실패합니다.
  SHAKE는 거부됩니다 — RFC 2104는 고정 출력 해시 위에 정의되어 있습니다.
  BLAKE2s의 항목은 SHA-256이 쓰는 것과 같은 64바이트 블록입니다. BLAKE2s
  위의 HMAC은 잘 정의되어 있고 BLAKE2 자신의 키 모드(`CBlake2sMac`)와
  구별됩니다.
- **`crypto/hashers/blake2s.hpp` / `src/crypto/hashers/blake2s.cpp`**는
  `BLAKE2s`, RFC 7693을 `EHASH_BLAKE2S`로 정의합니다. WireGuard의
  핸드셰이크(그 `HASH()`, `MAC()`, HKDF가 모두 이것을 씁니다)를 위해
  추가되었지만 `EHashers` 계열의 평범한 멤버입니다. SHA-2 계열이 빅엔디언인
  자리에서 전체가 리틀엔디언이고, Merkle-Damgard가 아니라 HAIFA
  구성입니다. 길이 padding 블록이 없고 바이트 카운터와 마무리 플래그가 마지막
  압축에 바로 들어가므로, 뒤의 바이트가 그것이 마지막이 아님을 증명할 때까지
  블록 하나를 붙들어 둡니다. digest 길이(1–32)가 파라미터 블록에 묶이므로
  `BLAKE2s(16)`은 `BLAKE2s(32)`의 앞 16바이트와 다른 함수입니다 — 생성자는
  파라미터 블록이 기술할 수 없는 인스턴스를 만드는 대신 범위를 벗어난 길이를
  32로 접습니다. 상태 기계는
  `src/crypto/hashers/blake2score.hpp`(`Blake2sCore`)에 있고
  `CBlake2sMac`과 공유되며, 각 공개 클래스가 자기 헤더에 자기 컨텍스트를
  선언하도록 원시 배열에 대한 독립 연산으로 두는 `Sha3Core`의 패턴을
  따릅니다.
- **`crypto/blake2smac.hpp` / `src/crypto/blake2smac.cpp`**는
  `CBlake2sMac`을 정의합니다. BLAKE2의 *고유* 키 모드(RFC 7693 2.9/3.3)이고,
  WireGuard의 `MAC()`이 바로 그것입니다. 키는 0으로 채운 첫 블록 하나이고 그
  길이가 파라미터 블록에 들어갑니다. ipad/opad가 없고 두 번째 패스도 없습니다.
  이것은 HMAC-BLAKE2s가 **아니며**, 그쪽은 `EHASH_BLAKE2S`를 쓰는 `CHmac`이고
  WireGuard의 HKDF가 쓰는 것입니다 — 둘은 같은 입력에서 서로 다른 tag를
  만들어 내므로, 혼동하면 상호운용성이 조용히 실패합니다. `BLAKE2s`에 키를
  받는 `reset()`을 두는 대신 별개 클래스인 이유는 `IHasher::reset()`이 인자를
  받지 않기 때문입니다. 키를 받는 hasher는 다형적 reset에서 키를 잃거나
  `IHasherPtr` 뒤에서 평범한 해시로 위장할 것이고, 이는 `CPoly1305`를 hasher
  계층 밖에 두는 것과 같은 논리입니다. `CPoly1305`와 달리 키는 메시지들에
  걸쳐 재사용 가능하고, `finish()`는 반복 가능한 조회입니다.
- **`crypto/hkdf.hpp` / `src/crypto/hkdf.cpp`**는 `CHkdf`를 정의합니다.
  RFC 5869의 extract-then-expand KDF이고, `extract()`/`expand()`/`derive()`로
  되어 있습니다. `IKdf` 계열의 한 구현이 아니라 구체적인 유틸리티이며
  `CRng`의 선례를 따릅니다. HKDF의 2단계 모양은 어느 쪽에도 잘 맞지 않는
  인터페이스 없이는 비밀번호 기반 KDF로 일반화되지 않습니다. 그 뒤
  `CPbkdf2`가 도착했지만 인터페이스는 여전히 생기지 않았는데, 그 예측이
  유효했기 때문입니다 — 둘이 공유하는 것은 "span을 받는 정적 `derive()`"
  뿐이고, 그것은 모양이지 추상이 아닙니다.
- **`crypto/pbkdf2.hpp` / `src/crypto/pbkdf2.cpp`**는 `CPbkdf2`를 정의합니다.
  RFC 8018 5.2절의 반복 비밀번호 기반 KDF이며, `derive()` 하나와
  `maxDeriveBytes()`입니다. 그것을 필요로 한 유일한 호출자(`CPfxFormat`)
  안이 아니라 `CHkdf` 옆에 있는데, 비밀번호 KDF가 범용 프리미티브이기
  때문입니다. 그리고 둘은 단호히 **교체 가능하지 않습니다**. HKDF는 입력이
  이미 완전한 엔트로피를 가졌기 때문에 저렴하도록 만들어졌고, 바로 그것이
  비밀번호에 대해 쓸모없게 만드는 요소입니다. 가지고 다닐 만한 구현 메모:
  `T(i)`는 마지막 것이 아니라 *모든* `U(j)`의 XOR입니다(XOR을 빼면 계산
  비용은 같은데 아무것과도 일치하지 않으며, 그것이 RFC 6070의
  벡터가 그것을 잡는 유일하게 저렴한 방법인 이유입니다). salt를 보는 것은
  `U(1)`뿐입니다. `INT(i)`는 1부터 시작하는 빅엔디언 4바이트이고, 출력이
  digest 하나를 넘어갈 때에만 드러납니다. 반복 횟수 0은 "늘리지 않음"이
  아니라 `ERET_BADREQ`인데, 컨테이너에서 파싱된 0 횟수가 공짜 유도가 되어서는
  안 되기 때문입니다. 그리고 출력은 `(2^32 - 1) * hLen`으로 경계가 지어지는데,
  그것을 넘으면 카운터가 wrap되어 키스트림이 반복되기 때문입니다.
  `tests/crypto/pbkdf2.cpp`가 RFC 6070의 HMAC-SHA1 벡터와 RFC 7914 11절의
  HMAC-SHA256 것들에 대해 확인하고, 16777216 반복 케이스를 빼 둔 이유를
  설명합니다.
- **`crypto/poly1305.hpp` / `src/crypto/poly1305.cpp`**는 `CPoly1305`를
  정의합니다. RFC 8439 2.5의 일회용 인증자입니다. `finish()`는
  `IHasher::finish()`처럼 반복 가능한 조회가 아니라 상태를 *소비*하는데,
  Poly1305가 구성상 일회용이기 때문입니다 — 한 키로 두 메시지를 처리하면
  공격자가 `r`을 풀어 마음대로 위조할 수 있습니다 — 그래서 인스턴스를 쓸 수
  있는 상태로 남기는 것은 그것을 깨뜨리는 오용을 초대하는 일입니다.
  `CHmac`과 의도적으로 어떤 인터페이스도 공유하지 않습니다. HMAC은 키를 받고
  재사용 가능하지만 이것은 둘 다 아니며, 서로 바꿔 쓸 수 있게 하면 그 차이가
  호출 지점에서 보이지 않게 됩니다. `padToBlock()`이 이름 붙은 연산인
  이유는 RFC 8439 2.8의 `pad16`이 메시지를 늘리는 것이 아니라 부분 블록을
  닫는 것이고, 0을 밀어 넣는 것으로는 그것을 표현할 수 없기 때문입니다.
- **`crypto/siphash.hpp` / `src/crypto/siphash.cpp`**는 `CSipHash`를
  정의합니다. SipHash-2-4(Aumasson과 Bernstein)이고, RFC 9018 2.2가 DNS 서버
  쿠키용으로 명시하는 128비트 키/64비트 출력의 키 PRF입니다. `CPoly1305`의
  모양을 취하되 — `reset(key)`/`push()`/`finish(out)`와 일괄 `compute()` —
  그 수명 주기는 의도적으로 *취하지 않습니다*. SipHash는 재사용 가능한
  PRF이므로 `reset()`을 몇 번이든 호출할 수 있고, 이미 설치된 키로 메시지를
  다시 시작하는 인자 없는 `reset()`이 있으며, `finish()`는 키를 소비하지 않고
  (`IHasher::finish()`가 하듯 상태의 사본을 마무리하는) 반복 가능한 조회입니다.
  그 차이는 각 프리미티브의 보안 모델이 드러난 것이고, 각 클래스의 doc 주석이
  그것을 말합니다. 그러지 않으면 두 클래스가 서로 바꿔 쓸 수 있는 것처럼
  보이기 때문입니다. `IHasher`도 아닙니다. `IHasher`는 키가 없고 16바이트
  이상의 digest를 내지만 이것은 키를 받고 8바이트 출력을 내며, 64비트는
  충돌 탐색을 버티기에 한참 짧습니다 — `IHasher` 뒤에 두는 것은 그것이
  지원할 수 없는 바로 그 사용을 초대하는 일입니다. padding이 미묘한
  부분입니다. 비었거나 블록에 정렬된 메시지에 대해서도 항상 마지막 블록이
  존재하고, 그 블록은 어떤 `0x80` 표시나 비트 수 대신 최상위 바이트에 메시지
  길이 mod 256을 담습니다. 그래서 짧은 블록을 0으로만 채우는 구현은 자기
  일관적이면서 임의의 메시지와 그것의 0 확장에 같은 출력을 줍니다 — 빈
  메시지와 `0x00` 한 바이트가 그런 쌍 중 가장 작은 것이고, 이를 위한 테스트가
  쓰는 것이 바로 그것입니다.
- **`crypto/aeads/chacha20poly1305.hpp` /
  `src/crypto/aeads/chacha20poly1305.cpp`**는 `CChaCha20Poly1305`,
  RFC 8439 2.8을 정의합니다. 인스턴스 하나가 키 컨텍스트입니다 — 키마다
  생성하고, 레코드마다 nonce만 바꿔 `seal()`/`open()`을 호출합니다 — 그리고
  두 연산 모두 할당하지 않습니다. `out`은 `in`과 같은 것을 가리켜도 되며,
  그것이 수신자가 레코드를 이미 있는 자리에서 복호할 수 있게 해 줍니다.

  `open()`은 평문을 하나도 쓰기 *전에* tag를 검증합니다. tag가 ciphertext를
  덮으므로 입력이 온전한 동안 확인할 수 있고 — 그리고 `out`이 `in`을 가리킬 수
  있으므로, 복호-다음-검증 순서는 위조를 알아차리기 전에 호출자의 유일한
  ciphertext 사본을 인증되지 않은 평문으로 덮어쓸 것입니다. 비교는 `memcmp`가
  아니라 `CSecure::equalsMask`를 거칩니다.
- **`crypto/aeads/xchacha20poly1305.hpp` /
  `src/crypto/aeads/xchacha20poly1305.cpp`**는 `CXChaCha20Poly1305`를
  정의합니다. draft-irtf-cfrg-xchacha의 확장 nonce 변종이고, WireGuard와
  libsodium이 쓰는 것입니다. 두 번째 AEAD가 아니라 얇은 래퍼입니다.
  `subkey = HChaCha20(key, nonce[0:16])`, 그 다음 96비트 nonce
  `00000000 || nonce[16:24]`로 그 부분키 아래의 `CChaCha20Poly1305`입니다.
  API와 모든 계약(제자리 연산, 호출마다 할당 없음, constant-time
  검증-먼저-쓰기-나중)은 `CChaCha20Poly1305`의 것이며, 다시 진술하는 대신
  위임으로 물려받습니다.

  192비트 nonce가 요점 전부입니다. 96비트는 무작위로 고르기에 너무 짧은데,
  한 키 아래 대략 2^48개 레코드 뒤에 생일 충돌이 유력해지므로 RFC 8439가
  사실상 카운터를 요구합니다 — 그리고 카운터는 재시작을 넘어 살아남고 보내는
  주체들 사이에 공유되지 않는 상태를 요구합니다. 192비트에서는 무작위
  nonce가 현실적인 어떤 레코드 수에도 안전하므로, 카운터를 전혀 조율할 수
  없는 당사자들이 하나의 키를 쓸 수 있습니다. 비용은 레코드당 ChaCha20
  permutation 한 번입니다.

  부분키가 nonce에 의존하므로 호출들 사이에 캐시할 수 있는 것이 없습니다.
  그래서 레코드별 부분키와 내부 nonce는 스택 구조체(`.cpp`의 `Inner`)에
  살며, 그것이 스택의 `CChaCha20Poly1305`에 키를 설정하고 자기 소멸자에서
  부분키를 영으로 지웁니다. 이는 `mutable` 멤버나 const가 아닌 `seal()` 없이
  할당 없음 계약을 유지합니다.
- **`crypto/aeads/aesgcm.hpp` / `src/crypto/aeads/aesgcm.cpp`**는 `CAesGcm`을
  정의합니다. NIST SP 800-38D이고 AES-128/192/256과 96비트 IV를 씁니다.
  `CChaCha20Poly1305`의 모양을 의도적으로 맞춥니다 — 키 컨텍스트, 레코드마다
  `seal()`/`open()`, 호출마다 할당 없음, `out`이 `in`을 가리킬 수 있음, 그리고
  `open()`이 평문 한 바이트를 쓰기 전에 검증함 — 같은 소비자(IKEv2)가 협상으로
  둘 중 하나를 고르고, 그 선택에 맞춰 구조를 바꿔야 할 이유가 없기
  때문입니다. 차이는 알고리즘이 강제하는 것들입니다. tag를 절단할 수 있고
  (SP 800-38D 5.2.1.2가 128/120/112/104 또는 96비트를 허용하는데, 이는
  `MIN_TAG_BYTES`부터 `TAG_BYTES`까지의 모든 바이트 길이이고 그보다 짧은 것은
  없습니다), 키가 하나가 아니라 세 길이 중 어느 것이든 될 수 있습니다.

  **96비트 IV만 받아들입니다.** SP 800-38D는 임의 길이를 허용하지만, 그 외의
  것은 초기 카운터 블록을 IV를 GHASH에 통과시켜 유도하며
  그것을 직접 쓰지 않습니다 — 미묘하게 틀릴 자기만의 방식을 가진 두 번째
  코드 경로이고, 그것을 필요로 하는 호출자가 없습니다. IKEv2(RFC 4106/5282),
  TLS, SSH 모두 정확히 96비트를 쓰며, SP 800-38D 8.2가 권장하는 것도 그것입니다.

  `deriveSubkey()`가 `H = E_K(0^128)`을 노출하는 이유는
  `CChaCha20Poly1305::deriveOneTimeKey()`가 존재하는 이유와 같습니다. GCM
  명세가 테스트 케이스마다 `H`를 발행하고, 그것이 "키 스케줄이 틀렸다"와
  "해시가 틀렸다"를 가르는 하나뿐인 중간값입니다.
- **`src/crypto/aeads/ghash.hpp`/`.cpp`**는 `Ghash`를 정의합니다.
  GHASH(SP 800-38D 6.4)와 GCM의 `GF(2^128)` 곱셈입니다. PCLMULQDQ로 가속된
  곱셈이 있어 당연한 재사용처럼 보일 `CGf2m` 위에 구현되어 있지 **않으며**,
  서로 독립적인 세 가지 이유가 있습니다.

  - GCM의 체는 **비트 반전**되어 있습니다. 블록 첫 바이트의 최상위 비트가
    `x^0` 계수(SP 800-38D 6.3)인데, 이는 `CGf2m`과 라이브러리의 나머지가 쓰는
    다항식 기저 관례의 반대입니다. `CGf2m`에 바이트를 도착한 그대로 건네면
    모든 대수적 측면에서 자기 일관적이면서 GHASH가 아닌 곱이 나옵니다 —
    이것을 틀리는 전형적인 방식이고, 발행된 벡터만이 잡을 수 있는 것입니다.
  - `H`는 **비밀**이므로 곱셈이 constant-time이어야 합니다. `CGf2m`은 자기가
    그렇지 않다고 문서화하고 있는데, 그것은 ECDSA의 공개 곡선 연산에는 맞는
    교환이고 MAC 키에는 틀린 교환입니다.
  - `CGf2m`은 다른 체들에 맞춰 크기가 잡혀 있습니다. 9 limb와 18 limb 곱에
    대한 일반적인 오항식 축약인데, GHASH는 메시지 16바이트당 한 번, 고정
    모듈러스 하나를 쓰는 64비트 워드 두 개입니다.

  이식 가능한 곱셈은 SP 800-38D 자신의 알고리즘 1이고 모든 분기를 mask로
  바꾸었으며 테이블이 없습니다 — 흔한 windowed GHASH의 키 의존 인덱스가
  캐시를 통해 `H`를 누출하는 것입니다. 가속 경로
  (PCLMULQDQ. `CGf2m`의 것과 정확히 같이 `CERTPP_DISABLE_HWACCEL_SIMD`와
  런타임 CPUID 검사 뒤에 있습니다)는 반전된 관례에서 곱셈을 **하지
  않습니다**. 열두 개쯤의 SSE2 명령으로 두 피연산자를 평범한 관례로 변환하고,
  거기서 축약은 교과서적인 `x^128 = x^7 + x^2 + x + 1`입니다. 정확성을 눈으로
  확인할 수 없는 1비트 시프트 더하기 거울상 상수 수법을 들고 다니지 않습니다.

  발행된 벡터는 두 경로를 구별할 수 없습니다 — 이 CPU가 택하는 쪽이 그
  벡터들이 도달하는 유일한 경로입니다 — 그래서
  `tests/crypto/aeads/ghash.cpp`는 수천 개의 무작위·구조화된 피연산자에 대해
  둘을 직접 비교하고, 비트 순서를 못 박는 체 항등식들을 확인합니다(곱셈
  항등원은 `00 ... 00 01`이 아니라 `80 00 ... 00` 블록입니다). `Ghash`는
  공개 헤더도 `CERTPP_API`도 없으므로, 그 테스트는
  `CERTPP_TEST_PRIVATE_SOURCES`를 통해 `ghash.cpp`를 자기 안으로 컴파일해
  넣습니다.
- **`src/crypto/syms/aescore.hpp`/`.cpp`**는 `AesCore`를 정의합니다. AES의 키
  스케줄과 단일 블록 암복호(AES-NI 경로는 `CERTPP_DISABLE_HWACCEL_AES` 뒤에
  있습니다)이고, GCM이 공유할 수 있도록 `aes.cpp`에서 분리한 것입니다 —
  `DesCore`와 `ChaCha20Core`가 이미 갖는 배치입니다. GCM은
  `ISymmetricContext`가 표현할 수 있는 모드가 아닙니다. 임의의 카운터 블록에서,
  *그리고* (H를 위해) 전부 0인 블록에서 원시 정방향 블록 함수가 필요하고,
  역암호는 전혀 쓰지 않습니다.
- **`src/crypto/syms/chacha20core.hpp`/`.cpp`**는 `ChaCha20Core`, 즉 블록
  함수를 정의합니다. AEAD가 공유할 수 있도록 스트림 암호에서 분리한
  것이고 — `DesCore`와 `KeccakCore`가 이미 갖는 배치입니다. AEAD는 그것을
  `ISymmetric`이 표현할 수 없는 두 카운터에서 필요로 합니다. Poly1305 키
  유도를 위한 0, 그리고 페이로드를 위한 1 이후입니다.
  `xorStream()`은 네 블록 SSE2 키스트림 경로
  (`xorStream4()`. `CERTPP_DISABLE_HWACCEL_SIMD` 뒤)를 지닙니다. 열여섯 개
  상태 워드 각각이 연속된 네 카운터에 대한 그 워드를 담은 `__m128i`가 되므로,
  20라운드 한 번으로 256바이트가 나오고, 그 다음 블록 우선 바이트 순서로
  돌아오기 위해 네 워드 그룹마다 4x4 전치를 합니다. 블록들은 구성상
  독립적이므로 직렬화해야 할 것이 없습니다. `CBigNum`의 ADX/BMI2와
  `CGf2m`의 PCLMULQDQ 경로와 달리 **런타임 CPUID 검사가 없습니다**. SSE2가
  x86-64 ABI의 일부이기 때문입니다 — 관문은 아키텍처와 빌드 옵션뿐입니다.
  네 블록 그룹 전체가 그것을 거치고 나머지는 스칼라 루프로 떨어지며, 그
  루프가 x86-64가 아닌 모든 타깃도 담당합니다. 스칼라 키스트림 속도의
  1.93배로 측정되어, 64 KiB `seal()`을 331에서 대략 560 MiB/s로 올렸습니다.
  RFC 8439 자신의 벡터는 이것을 전혀 확인할 수 없습니다 — 가장 큰 것이
  114바이트이므로 그 전부가 스칼라 루프만으로 처리됩니다 — 그래서
  `tests/crypto/syms/chacha20.cpp`는 RFC 8439 2.3의 두 번째 독립 구현을 담고
  0부터 600까지의 모든 길이에 1 KiB/4 KiB/16 KiB/64 KiB를 더해 그것에
  대조해 훑습니다. lane별 카운터 feed-forward를 의도적으로 깨뜨리면 RFC 벡터
  케이스 일곱 개는 모두 통과하고 그 둘만 실패합니다.

  `hchacha20()`이 여기 있는 이유는 블록 함수가 여기 있는 이유와 같습니다 —
  같은 20라운드입니다 — 그리고 `block()`과 두 가지에서 다른데, 틀렸을 때 각각
  자기 일관적입니다. 128비트 nonce가 워드 12부터 15까지를 채우고(카운터가
  없습니다), **feed-forward가 없으므로** 라운드의 출력이 그대로, 워드 0–3
  다음 워드 12–15로 나갑니다. 그것에 `block()`을 재사용하면 자기 자신에
  대해서는 왕복하고 다른 어떤 구현과도 일치하지 않는 부분키가 나오는데,
  그래서 기존 함수의 플래그가 아니라 별개 함수입니다.
- **`crypto/rng.hpp` / `src/crypto/rng.cpp`**는 `CRng`, CSPRNG 유틸리티를
  정의합니다. `fill(const SByteSpan&) -> ERetCode`는 제3자 라이브러리가
  아니라 운영체제의 CSPRNG로 직접 뒷받침됩니다 — Windows에서는
  `BCryptGenRandom`(Windows CNG. `bcrypt.lib`로 링크), Linux에서는
  `getrandom(2)` 시스템 콜(Linux 3.17+. `EINTR`/짧은 읽기를 넘어 반복하고,
  ENOSYS나 노골적인 시스템 콜 실패에 대해서는 `/dev/urandom` 대체), 그 외
  POSIX 플랫폼에서는 `/dev/urandom` 직접입니다 — 그리고
  OS API가 실패하고 *그리고* `CERTPP_RNG_FALLBACK` CMake 옵션(기본 `OFF` —
  `std::random_device`가 모든 표준 라이브러리에서 암호학적으로 안전함이
  보장되지 않으므로, 기본으로 켜 둘 것이 아니라 OS 수준 CSPRNG가 진짜로 없는
  환경을 위한 임시 조치입니다)이 켜져 있을 때에만 `std::random_device`로
  대체합니다. 꺼 두면 대체 경로가 완전히 컴파일에서 빠지고 `fill()`은 대신
  `ERET_NOTSUP`을 반환합니다. `fillNonZero(const SByteSpan&)`은 `fill()` 위의
  거부 샘플링으로 버퍼를 무작위 *0이 아닌* 바이트로 채우며, 0 바이트를
  금지하는 padding 스킴(RSAES-PKCS1-v1_5)을 위한 것입니다. 어떤 `asyms/`
  구현이든 존재하게 되면 키 생성(`IAsymmetric::generateKeyPair()`)과 암호화
  padding이 필요로 합니다.
- **`crypto/asym.hpp`**은 `IAsymmetric`, `IAsymmetricContext`,
  `IAsymmetricTransformer`를 정의합니다. `IAsymmetric`은 키 재료를 보유하지
  않습니다. `keySizes()`는 알고리즘이 무엇을 받아들이는지 기술하고,
  `generateKeyPair(keySize, out)`/`createPublicKey()`/`createPrivateKey()`는
  키를 만들거나 파싱하며, `createContext()`(`IStream::createMemory()`의 팩토리
  패턴을 인스턴스 메서드로 둔 것)는 키가 없는 `IAsymmetricContext`를
  반환합니다.

  `generateKeyPair()`는 이전 버전이 쓰던 실패-시-빈-`SKeyPair` 관례가 아니라
  `ERetCode`로 결과를 보고하므로(반환값이 아니라 out 파라미터
  `SKeyPair& out`), 호출자가 생성이 *왜* 실패했는지 구별할 수 있습니다 —
  특히 `ERET_AGAIN`은 갓 생성된 키가 `checkPrivateKey()`의 검증에 실패했고
  (아래 참고) 호출자가 그냥 `generateKeyPair()`를 다시 호출하면 된다는 것을
  구체적으로 뜻하며, 다시 시도해도 고쳐지지 않을 구조적
  실패(지원되지 않는 `keySize`에 대한 `ERET_KEY_SIZE`, RNG/연산 실패에 대한
  `ERET_UNKNOWN`)와 대비됩니다. 모든 구체 구현은 검증 실패 시 내부에서
  루프를 돌리는 대신, 갓 만든 자기 키를 반환하기 전에
  `checkPrivateKey()`로 검증합니다 — 루프는 호출자의 결정이고
  `generateKeyPair()` 안에 숨겨질 것이 아닙니다. 중요한 점으로,
  `checkPrivateKey()` 자신의 진단 코드는 절대 그대로 전달되지 않습니다 —
  `generateKeyPair()`는 `ERET_OK`가 아닌 결과를 항상 `ERET_AGAIN`으로
  번역합니다. 새 후보의 *구체적인* 거부 사유는 어차피 다시 시도할 호출자에게
  행동으로 이어지지 않고, 둘을 뒤섞으면 역직화된 키를 직접 검증하는
  호출자(아래 `checkPrivateKey()` 참고. 거기서는 재시도가 애초에 일관된
  대응이 아닙니다)에게 `ERET_AGAIN`이 모호해지기 때문입니다.

  `checkPrivateKey(key)`는 개인키의 구조를 검증합니다 — 갓 생성된 것(위에서처럼
  `generateKeyPair()`가 내부적으로 호출)과 `createPrivateKey()`를 통해 신뢰할
  수 없는 저장소에서 파싱된 것(직접 호출) 둘 다입니다. 후자의 경우에는
  재시도가 일관되지 않으므로, `ERET_AGAIN` 대신 검증이 *왜* 실패했는지
  보고합니다. `key`가 이 알고리즘 인스턴스가 만든 것이 아니면(구체 타입이
  틀림) `ERET_KEY_FORMAT`, `key`가 내부적으로 일관되지 않으면(예: 연결된
  공개키가 없거나 타입이 틀림) `ERET_KEY_ERROR`, 자기 파라미터/유도값에 대한
  구조 검사가 실패하면 `ERET_KEY_PARAM`입니다. 같은 3분법(없음 대 타입 틀림 대
  값 틀림)이 `sign()`/`verify()`/`deriveSharedSecret()`에도 전반적으로
  적용됩니다. 각각 먼저 컨텍스트에 바인딩된 키가 아예 있는지
  확인하고(없으면 `ERET_KEY_EMPTY`), 그 다음 그것이 이 알고리즘 자신의 구체
  키 타입인지 확인합니다(아니면 `ERET_KEY_FORMAT`) — "아무것도 바인딩되지
  않음"과 "다른 알고리즘의 키 쌍이 이 컨텍스트에 바인딩됨"을
  구별합니다(`IAsymmetricContext::keyPair()` 자체는 건네받은 것의 타입을
  검사하지 않습니다).

  타원 곡선 알고리즘들(`CEcdsa`/`CEcdsa2`/`Ed25519`/`Ed448`)에 대해서는, 이는
  키의 유도된 공개점 Q에 대한 고전적인 네 가지 검사(무한점, 체 범위, 곡선
  방정식, 올바른 위수의 부분군: `n*Q`가 항등원으로 축약되어야 함)와, 더해서
  (`CEcdsa`/`CEcdsa2`에만 — 아래 참고) 개인 스칼라 자신의 범위
  `d in [1, n-1]`을 뜻합니다 — 그리고 여기의 모든 알고리즘이 곡선 계열과
  무관하게 적용하는 다섯 번째 검사가 있습니다. Q가 단지 *어떤* 제대로 생긴
  점이 아니라 *이 키 자신의* 점이라는 것입니다. `CEcdsa`/`CEcdsa2`는
  `d*G`(`scalarMulBase()`)를 다시 계산해 Q와 직접 비교합니다.
  `Ed25519`/`Ed448`은 저장된 시드에서 스칼라 `s`를 다시
  유도하고(서명 자신이 쓰는 같은 `deriveFromSeed()`) `s*B`를 Q와 비교합니다.
  `RSA`/`DSA`(아래 참고)와 `X25519`는 같은 생각을 자기 모양에 적용합니다 —
  이것이 없으면 개인 스칼라가 무관하지만 독립적으로 제대로 생긴
  공개키/점과 짝지어진 채로도 다른 모든 검사를 통과할 수 있습니다.
  `X25519`(Montgomery 곡선, u 좌표만, cofactor 8, 설계상 twist에 안전)는
  대신 RFC 7748에 맞는 유사 검사를 씁니다. 체 범위, 전부 0인 유도된 공개키
  거부(RFC 7748 6.1 자신의 규칙을 ECDH 출력이 아니라 키 생성에 적용),
  그리고 낮은 위수/twist torsion 공개키 거부 — 하드코딩된 상수 목록과
  대조하는 대신 `8*u`를 직접 계산해 탐지합니다(`u`의 위수가 cofactor를 나눌
  때에만 항등원으로 축약됩니다). 곡선 방정식 검사는 의도적으로 없는데,
  X25519가 설계상 곡선 또는 그 2차 twist 어느 쪽의 u 좌표든 받아들이기
  때문입니다. `Ed25519`/`Ed448`은 `CEcdsa`/`CEcdsa2`가 갖는 스칼라 범위 검사를
  건너뜁니다. RFC 8032 5.1.5/5.2.5의 clamp된 스칼라는 ECDSA의 `d`와 달리
  군 위수보다 작도록 의도된 것이 *아닙니다*(clamping이 그것을 고정된 상위
  비트 범위에 못 박습니다). `RSA`/`DSA`(타원 곡선 알고리즘이 아닙니다)는
  네 가지 EC 점 검사 대신 자기만의 유사한 구조 검사를 구현합니다. RSA는
  `p`/`q`가 서로 다른 유력 소수인지, `n == p*q`인지, `e`가 `phi(n)`과
  서로소인지, `d`가 `phi(n)`에 대한 `e`의 모듈러 역원인지, 그리고 CRT
  파라미터(`dp`/`dq`/`qInv`)가 `d`/`p`/`q`와 일관된지 검증합니다. DSA는
  `p`/`q`가 유력 소수인지, `q`가 `p-1`을 나누는지, `g`의 위수가 `q`인지,
  `x`가 `[1, q-1]`에 있는지, 그리고 `y == g^x mod p`인지 검증합니다 — 둘 다
  먼저 자기 `IPrivateKey::publicKey()`를 dynamic_cast하기도 합니다(그것이
  실패하면 `ERET_KEY_ERROR`), 그리고 그것이 저장한 필드(RSA는 `n`/`e`, DSA는
  `p`/`q`/`g`/`y`)가 개인키 자신의 것과 일치하는지 확인하는데, 위에서
  EC/EdDSA 알고리즘들이 `d*G`/`s*B`로 적용하는 "Q는 단지 *어떤* 점이 아니라
  *이 키의* 점"이라는 같은 생각입니다. `X25519`의 `checkPrivateKey()`는
  저장된 원시 스칼라에서 `u`를 다시 유도하고 그 리틀엔디언 인코딩을 연결된
  공개키의 저장된 바이트와 비교하는 유사한 일을 합니다.

  `IAsymmetricContext`는 바인딩된 키 쌍을 보유하고(`keyPair()`. `reset()`으로
  지웁니다. 둘 다 `protected` `onReset()` 훅에 알리므로 파생 클래스가 키에서
  유도한 무엇이든 무효화할 수 있습니다) 그것에 직접 작용합니다.
  `sign()`/`verify()`는 `ERetCode`를 반환하고(`bool`이 아니므로 "맞지 않음"을
  `ERET_NOTSUP`/오류와 구별할 수 있습니다) 기본값이 `ERET_NOTSUP`인데,
  `IStream`의 모든-구현이-이것을-지원하지는-않는다 패턴입니다.
  `deriveSharedSecret(peerPublicKey, out)`도 같은 선택적 능력 관용구를
  따르며, Diffie-Hellman 식 키 합의(`X25519`, 그리고 소수 곡선 ECDH를 위한
  `CEcdsa`)를 위한 것입니다. 컨텍스트 자신의 바인딩된 개인키를 명시적으로
  넘겨진 상대 공개키와 결합하는데, 바인딩된 키(들)에만 작용하는 여기의 다른
  모든 메서드와 다릅니다 — 단일 바인딩 키 쌍을 중심으로 만들어진 인터페이스에
  두 당사자 연산을 끼우기 위한 최소한의 추가입니다.

  소수 곡선 ECDH가 별도의 `CEcdh`가 아니라 `CEcdsa`의 컨텍스트에 있는 이유는,
  소수 곡선 위의 ECDH 키 쌍이 ECDSA 키 쌍*이기* 때문입니다 — 같은 곡선 OID를
  쓰는 RFC 5480의 `id-ecPublicKey` `SubjectPublicKeyInfo`가 둘 다를
  담당합니다 — 그래서 별도 알고리즘은 하나의 인코드된 키를 기술하는 두 번째
  `EAsymmetrics` enumerator를 뜻했을 것이고, `IKeyBase::algorithm()`이 바로
  그 OID를 고르기 위해 존재합니다. 하나의 컨텍스트가 이미
  `createEncrypter()`/`createDecrypter()`와 함께 서명/검증을 지닌 `RSA`와도
  맞습니다. 따라서 생성된 키 쌍 하나가 컨텍스트 하나에 바인딩되어 둘 다
  합니다. 공유 비밀은 `d*Q`의 x 좌표 하나뿐이고
  `CEcCurve::fieldByteLen()`으로 왼쪽을 채웁니다(RFC 5903 7절 — 점 전체도,
  그것의 해시도 아닙니다). 호출자는 그것을 `CHkdf`에 통과시킵니다. 상대의
  점은 상대의 키 객체가 담고 있는 곡선을 믿는 대신 *바인딩된 키 자신의*
  곡선에 대해 다시 검증되며(무한점 아님, `0 <= x, y < p`, 곡선 위에 있음),
  그것이 invalid-curve 공격을 막는 것입니다. 작은 부분군 검사는 의도적으로
  없는데, 모든 `CEcCurve` 소수 곡선이 cofactor 1이고 이는 `X25519`의
  cofactor 8의 반대이기 때문입니다. **constant-time이 아닙니다** —
  `CEcCurve::scalarMul()` 자신의 설명과 `EcContext::deriveSharedSecret()`의
  doc 주석을 보십시오.

  `sign()`/`deriveSharedSecret()`의 `out` 파라미터는 증가 가능한
  `TArray<uint8_t>&`가 아니라 고정된, 호출자가 할당한 `SByteSpan&`입니다.
  호출자가 먼저 `sizeOfSign()`을 질의하고 최소한 그만큼 큰 버퍼를 할당해
  넘깁니다. 구현은 `out.data`에 쓰고 반환 전에 `out`을 실제로 만들어 낸
  바이트로 좁히거나(`out = SByteSpan(out.data, actualLen)`), 호출자의 버퍼가
  너무 작았다면 아무것도 쓰지 않고 앞에서 `ERET_NOSPC`를 반환합니다.
  `sizeOfSign()`/`sizeOfDigest()`(getter는 public, setter는 `protected` —
  `IAsymmetric::keySizes()`가 이미 쓰는 같은 분할 접근 패턴)는 각 구체
  컨텍스트의 `onReset()`에서 바인딩된 키가 무엇이든 그것으로부터
  계산됩니다(개인키 먼저, 그 다음 공개키. 그래서 검증 전용 컨텍스트도
  의미 있는 `sizeOfSign()`을 보고합니다). `sizeOfSign()`은 최대 서명
  크기입니다(RSA/Ed25519/Ed448의 고정 형식 서명에는 정확하고,
  DSA/ECDSA/ECDSA2의 DER 인코드된 것에는 안전한 상한입니다. 후자는 실무에서
  자주 1–2바이트 더 짧습니다 — 정확한 DER 크기 공식은 해당 모듈들의 항목을
  보십시오). `sign()`이 아예 지원되지 않는 곳(`X25519`)에서는 0입니다.
  `sizeOfDigest()`는 알고리즘의 연산이 실제로 소비하는 가장 긴 digest
  길이입니다(DSA/ECDSA/ECDSA2에 대해서는 체/부분군 바이트 길이. 더 긴
  digest는 어차피 정확히 그만큼의 비트로 절단되기 때문입니다) — RSA에
  대해서는 0이고(해시 알고리즘에 따라 서로 무관한 여섯 개 이산 길이 중
  하나를 받아들이며 단일 "최대"가 아닙니다), Ed25519/Ed448/X25519에
  대해서도 0입니다(digest 개념이 아예 없습니다. EdDSA의 `sign()` "digest"
  파라미터는 원시 메시지입니다).

  `createEncrypter()`/`createDecrypter()`는 대신 순수 가상인데, 비대칭
  암호화는 한 번에 한 블록만 다루기 때문입니다 — 임의 길이 호출 하나가 아니라,
  호출자가 `transform()`(한 chunk씩 반복)을 거친 뒤
  `transformFinal()`로 구동할 `IAsymmetricTransformer`(같은 키에
  바인딩된)를 돌려줍니다.
  `transform()`/`transformFinal()`은 `sign()`과 같은 고정
  `SReadOnlyByteSpan`/`SByteSpan&` 모양을 받습니다.
  `IAsymmetricTransformer::blockSize()`(getter는 public, setter는
  `protected`)는 그 변환기 연산의 자연스러운 블록 크기를 보고합니다 —
  `RsaTransformer`에 대해서는 RSA 모듈러스 바이트 길이(ciphertext 블록
  크기입니다. PKCS#1 v1.5의 평문 블록은 최대 11바이트 더 작고, 두 번째
  필드로 추적하지 않습니다).
- **`crypto/asyms/rsa.hpp` / `src/crypto/asyms/rsa.cpp`**는 `RSA`
  (RFC 8017)를 정의합니다. 첫 구체 `IAsymmetric`입니다. 키는 `CDer`를 통해
  PKCS#1 DER(`RSAPublicKey`/`RSAPrivateKey`. 두 소수 형태만)로 직렬화됩니다.
  `sign()`/`verify()`는 EMSA-PKCS1-v1_5를 구현합니다. `IAsymmetricContext`는
  자기가 받은 digest를 어떤 해시가 만들었는지 듣지 못하므로, DigestInfo의
  해시 `AlgorithmIdentifier`는 digest의 바이트 길이에서
  추론합니다(16/20/28/32/48/64로 MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512를
  덮습니다 — 가변 길이 SHAKE256과 MD4를 제외한, 이 라이브러리가 담고 있는
  모든 hasher입니다). MD4가 그 매핑에서 하나뿐인 충돌인데, 그것도 16바이트
  폭이기 때문입니다. 16바이트 digest는 MD5로 읽히는데,
  `md5WithRSAEncryption`은 (낡았지만) 실재하는 X.509 서명 알고리즘이고
  `md4WithRSAEncryption`은 사실상 보이는 일이 없기 때문입니다. MD4는 서명이
  아니라 NTLM/EAP-MSCHAPv2의 NT 해시를 위해 여기 있으므로 그 방향이 옳습니다 —
  그러나 그것이
  digest 길이 추론이 또 다른 16바이트 해시를 흡수할 수 없는 이유이고, MD4-with-RSA가
  진짜로 필요한 호출자에게는 대신 알고리즘 이름을 명시하는 경로를 주어야 하는
  이유입니다. `signPss()`/`verifyPss()`(`IAsymmetricContext` 자신에
  선언되어 있고, RSA만 override하므로 거기서는 기본값이 `ERET_NOTSUP`입니다)는
  대신 RSASSA-PSS(RFC 8017 9.1)를 구현합니다. EMSA-PSS-ENCODE/-VERIFY에 더해,
  digest 길이 추론이 아니라 호출자가 이름 지은 `EHashers`로 만든 MGF1 mask를
  씁니다 — PSS 자신의 `AlgorithmIdentifier`가 해시/MGF/salt 길이를 명시적으로
  담으므로, 평범한 `sign()`/`verify()`가 해결해야 하는 모호성이 없습니다.
  `createEncrypter()`/`createDecrypter()`는 RSAES-PKCS1-v1_5를 구현하고, 그
  padding에 `CRng::fillNonZero()`를 씁니다. private
  `RsaPublicKey`/`RsaPrivateKey`/`RsaContext`/`RsaTransformer` 클래스가 각각
  공개 `IPublicKey`/`IPrivateKey`/`IAsymmetricContext`/`IAsymmetricTransformer`
  인터페이스를 뒷받침하며, `MemStream`이 `IStream`을 뒷받침하는 것과 같은
  패턴입니다.

  모든 개인키 연산(`sign()`, `signPss()`, `decryptBlock()`)은
  `RsaContext::privateExp()`를 거치는데, 그것은 전체 모듈러스 하나에 대한
  `modExp(x, d, n)` 대신 CRT(Garner의 공식)를 씁니다. `m1 = x^dp mod p`,
  `m2 = x^dq mod q`를 계산하고(각각 `n`의 비트 길이 대략 절반인 모듈러스에
  대한 모듈러 거듭제곱이므로 각각이 전체 폭 버전보다 개별적으로 약 4배
  저렴하고, 둘은 서로 독립적입니다), 그 다음
  `h = qInv*(m1 - m2) mod p; m = m2 + h*q`로 결합합니다. 이것은
  `p`/`q`/`dp`/`dq`/`qInv` 전부가 키에 있을 때에만 돌아갑니다(이 라이브러리
  자신의 `generateKeyPair()`가 만든 어떤 것에 대해서도 참이지만, `n`/`d`만
  채워진 채 `createPrivateKey()`로 들여온 키에 대해서는 보장되지 않습니다) —
  CRT 파라미터 중 하나라도 없으면 `privateExp()`는 평범한
  `modExp(x, d, n)`으로 돌아갑니다. CRT 파라미터가 있을 때에도 결과를 그대로
  반환하는 일은 없습니다. `privateExp()`는 항상 그것을 다시
  암호화해(`modExp(m, e, n) == x?`) 확인한 뒤 돌려주고, 불일치하면 평범한
  `modExp`로 돌아갑니다. 이 검사는 표준적인 Lenstra/Bellcore 결함 공격
  대응책(CRT 계산 중 비트 하나가 뒤집히면 — 하드웨어 결함에서든 손상되거나
  일관되지 않은 키에서든 — 결함 있는 서명이 나오고, RSA에 특히 그것은
  `gcd(x - m^e, n)`을 통해 `n`의 인자를 누출하므로 이 검사를 건너뛰는 것은
  선택지가 아닙니다)이면서, 동시에 CRT 파라미터가
  `checkPrivateKey()`로 독립적으로 검증된 적 없는 들여온 키에 대해서도 CRT를
  쓰는 것이 올바르도록 만들어 주는 안전망입니다.

  `decryptBlock()`의 EME-PKCS1-v1_5 unpadding(RFC 8017 7.2.2)은 복호된
  블록에서 `0x00`/`0x02` 선두 바이트와 `0x00` 구분자를 constant-time으로
  스캔합니다. 구분자 탐색은 항상 `keyBytes - 2`회 전체를 돌고(첫 `0x00`에서
  멈추지 않습니다), 모든 검사 — 선두 바이트, 구분자 발견 여부, 최소 8바이트
  padding 길이 — 는 이른 반환 분기의 연쇄가 아니라 비트 AND/OR로 하나의
  비트마스크에 접힙니다. `CbcTransformer`의 PKCS#7 검사가 이미 적용하는
  같은 규율입니다(아래 그 자체의 doc 주석을 보십시오). 원래 버전의 데이터
  의존 길이 스캔에 더해 선두 바이트/구분자 위치에 대한 이른 반환 분기는
  교과서적인 Bleichenbacher oracle 모양이었습니다. 모든 실패 경로가 이미 같은
  `ERET_BADREQ`를 반환했지만, 거기 도달하는 데 *걸린 시간*이 여전히 어느
  검사가 어디서 실패했는지를 누출했습니다.
- **`crypto/asyms/dsa.hpp` / `src/crypto/asyms/dsa.cpp`**는 `DSA`
  (FIPS 186-4)를 정의하고, 서명/검증만 합니다 — DSA에는 암호화 연산이
  없으므로 그
  `DsaContext::createEncrypter()`/`createDecrypter()`는 무조건
  `ERET_NOTSUP`을 반환합니다. `keySizes()`는 FIPS 186-4의 (L, N) 쌍 정확히
  세 개(1024/160, 2048/256, 3072/256)를 받아들이고 L만으로 선택합니다.
  `generateKeyPair()`는 도메인 파라미터(p, q, g)를 따로 제공받기를 요구하는
  대신 스스로 새로 생성합니다(FIPS 186-4 A.1.1.2의 유력 소수 구성이며,
  나중에 파라미터 집합의 출처를 다시 검증하는 데 필요한 seed/counter 장부는
  빼 두었습니다). 이 라이브러리에는 그것들을 공유할 별도의 도메인 파라미터
  타입이 없기 때문입니다. 개인키는 전통적인(OpenSSL 호환) `DSAPrivateKey`
  DER 배치로 직렬화되고, 공개키는 이 라이브러리 자신의
  `SEQUENCE { p, q, g, y }`로 직렬화됩니다(똑같이 단순한 전통적 단일 blob
  공개키 포맷이 없습니다 — OpenSSL의 것은 도메인 파라미터를
  `SubjectPublicKeyInfo`의 `AlgorithmIdentifier`로 쪼개는데, 이 라이브러리는
  아직 그것을 모델링하지 않습니다). 서명은 표준
  `Dss-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`(RFC 3279)로
  직렬화됩니다.

  `sign()`의 `g^k mod p` 항은 `DsaPrivateKey::fixedBaseModExpG()`로
  계산합니다. 지연 생성되어 인스턴스별로 캐시되는 `g^0..g^15 mod p` 테이블에
  대한 좌에서 우로의 windowed 거듭제곱이며 — `CEcCurve::scalarMulBase()`가
  고정 기저 EC 서명에 이미 쓰는 것과 같은 "16항목 window" 모양(그 모듈의
  doc 주석 참고)을 점 덧셈/배가에서 모듈러 곱셈/제곱으로 옮긴 것입니다.
  이로써 거듭제곱이 평범한 `modExp()`의 평균 `bitLength/2`회 곱셈을 쓰는
  square-and-multiply 대신 `bitLength/4`회 제곱에 4비트당 정확히 한 번의
  window 곱셈이 됩니다. 테이블은 서명별 nonce `k`가 아니라 이 키의 고정된
  `(g, p)`만으로 결정되므로, 한 번 만들어져 이 키가 하는 모든
  `sign()` 호출(그리고 재시도)에 걸쳐 분산됩니다.
- **`crypto/eccurve.hpp` / `src/crypto/eccurve.cpp`**는
  `CEcCurve`/`SEcPoint`를 정의합니다. 아핀 좌표의 short-Weierstrass 타원
  곡선(`y^2 = x^3 + a*x + b mod p`)입니다. `CBigNum`과 같은 이유로 `src/`
  전용 구현 세부가 아니라 공개입니다. 군 연산이 어느 한 알고리즘에 묶여
  있지 않기 때문입니다. `add()`/`doublePoint()`는 군 법칙을 아핀 형태로 직접
  구현합니다(각각 호출당 모듈러 역원 하나) — 일회성 군 연산 하나에는 여전히
  가장 단순한 길이고,
  `isOnCurve()`/`encodePoint()`/`decodePoint()`와 이 라이브러리의 알려진
  곡선 자체 검사들이 그 위에 올라앉습니다. `scalarMul()`(임의의 점 곱하기
  임의의 스칼라)과 `scalarMulBase()`(`g` 곱하기 스칼라. 예컨대 모든
  sign()/verify() 호출의 `k*g`/`u1*g` 항)는 대신 내부적으로 Jacobian
  좌표(`ECPointJac`. `eccurve.cpp`의 익명 네임스페이스 — `X/Z^2, Y/Z^3`,
  무한점은 `Z == 0`)에서 작동합니다. 분기 없는 R0/R1
  ladder(`condSwapJac()`가 더할지 말지로 분기하는 대신 스칼라의 비트에 따라
  어느 레지스터가 어느 값을 담는지를 swap합니다)이며, 비트당 하나가 아니라
  맨 마지막에 정확히 한 번의 모듈러 역원 비용만 치르고
  (`toAffineFromJac()`), 좌표를 **Montgomery 형태**로 보유합니다
  (`CMontgomery`. 위의 `utils/montgomery.hpp` 참고). 그래서 스칼라 곱이
  수행하는 수천 번의 체 곱셈이 각각 긴 나눗셈이 아니라 limb 단위
  곱셈-누산 패스의 비용을 치릅니다. 모듈러스별 컨텍스트는 `CEcCurve`
  인스턴스에 캐시되지 않고 `scalarMul()`/`scalarMulBase()`의 앞머리에서
  만들어져 아래로 전달됩니다. `p`/`a`/`b`가 공개 가변 필드이므로 캐시된
  컨텍스트는 호출자가 그중 하나에 쓸 때마다 무효화가 필요할 것이고, 그
  두 번의 나눗셈은 뒤따르는 스칼라 곱 옆에서는 측정되지 않습니다.
  `toJacobian()`/`toAffineFromJac()`이 양방향 변환 경계이므로 Montgomery
  형태의 값이 그 다섯 함수를 벗어나는 일이 없습니다. 아핀
  `add()`/`doublePoint()`/`isOnCurve()`는 의도적으로 `CBigNum`의 일반 경로에
  남는데, 군 연산 하나는 그 한 번의 모듈러 역원이 지배하고 컨텍스트를 분산시킬
  대상이 없기 때문입니다. `scalarMulBase()`는 추가로 `g`의 작은 배수들을 담은
  지연 생성·인스턴스별 캐시 테이블(`_baseTable`. 4비트 window, 16항목)을 써서
  덧셈 횟수를 비트당 하나에서 4비트당 하나로 줄입니다.
  `doublePointJac()`/`addJac()`(Bernstein/Lange의
  `dbl-2007-bl`/`add-2007-bl`. 일반 `a`)과 `ec2curve.cpp`의 Lopez-Dahab
  대응물들은, 어떤 피연산자의 현재 값이 이후에 다시 읽히지 않을 때마다 그것을
  새 변수로 먼저 복사하지 않고 제자리에서 변경하도록 작성되어 있습니다(그런
  지점마다 어느 읽기가 그 피연산자의 마지막인지 이름을 댄 주석이 있습니다) —
  `CBigNum`/`CGf2m` 자신의 메서드들이 따르는 것과 같은
  복사보다-제자리 규율(위의 그들 doc 주석 참고)을 이 자유 함수들의 지역
  변수에까지 이어 간 것입니다. `CBigNum`처럼 여기에도 여전히 constant-time
  하드닝이 없습니다(ladder의 swap들도 constant-time이 아닙니다) — 완전한
  부채널 저항보다 정확성/감사 가능성이 이 라이브러리의 입장으로 남아 있습니다.
  `EEcKnownCurves`(`ECURVE_P192`/`ECURVE_P224`/`ECURVE_P256`/`ECURVE_P384`/
  `ECURVE_P521`/`ECURVE_SECP256K1`, 더해서 Brainpool 곡선들을 위한 14개
  `ECURVE_BPOOLxxxR1`/`ECURVE_BPOOLxxxT1` 값)가 이 라이브러리의 내장 곡선들을
  지칭합니다. `CEcCurve::knownCurves(which, out)`이 private `_knownCurves`
  배열에서 하나를 조회하고, 그 배열은 `eccurve.cpp`에 각 곡선의 표준 도메인
  파라미터(NIST 곡선은 FIPS 186-4, secp256k1은 SEC 2, Brainpool은
  RFC 5639 — R1 곡선들의 `a`/`b`는 무작위이고, 각 T1 곡선은 `a = -3 mod p`인
  R1의 동형 "twisted" 대응물로 같은 `p`/`n`을 공유합니다)와 함께
  `EEcKnownCurves` 순서로 정의되어 있습니다(16진 숫자 하나가 틀리면 이
  라이브러리 자신의 자기 일관성 테스트는 여전히 통과하는, 안전하지 않고
  비표준인 곡선이 얼마나 조용히 만들어지는지를 감안해 하드코딩 전에 두 번째
  출처에 대해 독립적으로 검증했습니다 — 개발 중 실제로 두 번 일어났고 두 번
  모두 `verify()` 실패로 곧바로 잡혔습니다. 그 이후 추가된 모든 곡선은 대신
  바로 그 부류의 실수를 출하 전에 잡기 위해 하드코딩 전에 프로그램으로
  확인합니다 — 곡선 방정식과 비트 길이 자기 일관성, 그리고 두 번째 출처
  교차 확인).
- **`crypto/asyms/ecdsa.hpp` / `src/crypto/asyms/ecdsa.cpp`**는 `CEcdsa`를
  정의합니다. 생성자로 선택한 임의의 `EEcKnownCurves` 값 위의
  ECDSA(FIPS 186-4)이며(`CEcdsa(ECURVE_P256)` 등), 곡선마다 별개 구체
  클래스를 두는 대신 한 클래스입니다. 그것들 사이의 유일한 차이가
  `keySizes()`/`generateKeyPair()`/서명/검증이 어느 도메인 파라미터를
  쓰는지뿐이기 때문입니다. `CEcdsa`는 자기 `CEcCurve`를 한 번
  조회하고(`knownCurves()`로) 평범한 값 멤버로 자기 사본을 유지합니다.
  private `EcPublicKey`/`EcPrivateKey` 클래스들도 마찬가지로 `CEcdsa`의 것을
  가리키는 포인터/참조가 아니라 각각 자기 `CEcCurve` 사본을 유지하는데,
  생성된 키가 그것이 나온 `IAsymmetric` 인스턴스보다 오래 살 수 있기
  때문입니다(예:
  `IAsymmetric::builtIn(EASYM_P256)->generateKeyPair(256)`을 한 줄로) —
  초기 버전은 거기에 원시 `const CEcCurve*`를 저장했는데, 정확히 그 패턴에서
  매달린 포인터가 되어 크래시했습니다. 개인키는 이 라이브러리 자신의
  `SEQUENCE { version INTEGER (0), d INTEGER, publicKey OCTET STRING }`으로
  직렬화되고(아직 `SubjectPublicKeyInfo`/곡선 OID 모델링이 없습니다),
  공개키는 벌거벗은 SEC1 비압축 점으로 직렬화됩니다. 서명은 표준
  `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`(RFC 3279/SEC 1)로
  직렬화됩니다. `keySizes()`는 정확히 한 크기, 선택된 곡선의 고정 체
  폭(곡선에 따라 160/192/224/256/320/384/512/521비트)을 받아들입니다.
- **`crypto/ec2curve.hpp` / `src/crypto/ec2curve.cpp`**는
  `CEc2Curve`/`SEc2Point`를 정의합니다. 아핀 좌표의 이진 곡선
  (GF(2^m) 위의 `y^2 + x*y = x^3 + a*x^2 + b`)이고 — `CEcCurve`의 이진체
  대응물이며, 공개이고 아핀/non-constant-time인 이유도 같지만, 체 연산에
  `CBigNum` 대신 `CGf2m`을 쓰는 완전히 다른 군 법칙입니다(`CEcCurve`와
  공유하는 공식이 하나도 없습니다). `add()`/`doublePoint()`는 아핀으로
  남습니다(각각 체 역원 하나). `scalarMul()`/`scalarMulBase()`는
  `CEcCurve`의 Jacobian 경로와 같은
  분기-없는-ladder/캐시된-고정-기저-테이블/안전할-때-제자리-변경 접근
  (위의 그 doc 주석 참고)으로 내부적으로 Lopez-Dahab
  좌표(`EC2PointLD`: `X/Z, Y/Z^2`, 무한점은 `Z == 0`)에서 작동합니다 —
  `doublePointLD()`/`addLD()`의 공식은 이 파일 자신의 아핀 공식에서 유도했고,
  이 모듈의 정착된 상수 검증 규율(아래 `_knownCurves` 참고)에 따라 여기
  하드코딩하기 전에 독립 Python GF(2^163) 구현으로 그것들에 대해 독립적으로
  교차 확인했습니다(무작위 시행 2,000회 이상에 경계 케이스들, 그리고 종단 간
  ladder 실행 한 번). `field`는
  소유하는 값이 아니라 소유하지 않는 `const SGf2mField*`이고, `CGf2m` 자신의
  체 포인터를 반영합니다. 항상 `CGf2m`의 다섯 공유 정적 싱글턴 중
  하나이기 때문입니다(같은 크기의 "B" 곡선과 "K" 곡선이 같은 체를 씁니다) —
  이것이 `CEcCurve`가 자기 `CBigNum` 값들을 직접 소유하는 것과 왜 다른지는
  `CGf2m`의 doc 주석을 보십시오.
  `EEc2KnownCurves`(`ECURVE2_B163`/`ECURVE2_K163` ..
  `ECURVE2_B571`/`ECURVE2_K571`)가 내장 열 개 곡선을 지칭합니다.
  `CEc2Curve::knownCurves()`가 private `_knownCurves` 배열에서 하나를
  조회하고, 그 배열은 `ec2curve.cpp`에 각 곡선의 표준 도메인
  파라미터(FIPS 186-4 부록 D / SEC 2. 두 번째 출처에 교차 확인)와 함께
  `EEc2KnownCurves` 순서로 정의되어 있습니다. 모든 기준점/위수는 하드코딩
  전에 두 가지 방식으로 독립 검증했습니다 — 곡선 위에 있음을
  확인(`isOnCurve()`) *그리고* 정확히 명시된 위수를 가짐을
  확인(`scalarMul(g, n)`이 무한점으로 축약됨) — 이 라이브러리가 Ed448의
  대수적으로 유도된 기준점에 썼던 것과 같은 두 성질 검사이고, 어느 한
  성질만보다 훨씬 강합니다. 점 인코딩은 SEC1 비압축(`0x04 || X || Y`)
  뿐입니다. 압축 점 복원(`CGf2m`이 구현하지 않는 GF(2^m) 2차 방정식 풀이가
  필요합니다)은 ECDSA 서명/검증이 필요로 하지 않으므로 미뤄 두었습니다.
- **`crypto/asyms/ecdsa2.hpp` / `src/crypto/asyms/ecdsa2.cpp`**는
  `CEcdsa2`를 정의합니다. 임의의 `EEc2KnownCurves` 값 위의 ECDSA이며 —
  `CEcdsa`의 이진 곡선 대응물로, 같은 생성자가-곡선을-고르는 모양이고
  private `Ec2PublicKey`/`Ec2PrivateKey` 클래스에서 같은 값 소유 방식을
  씁니다(`CEcdsa` 자신의 doc 주석이 설명하는 것과 동일한 매달린 포인터
  이유로). ECDSA 연산 자체(부분군 위수 `n`으로 축약된 `r`/`s`)는 `CEcdsa`의
  것과 변하지 않습니다. 곡선 계열과 무관하게 `n`이 `CBigNum`으로 남기
  때문입니다. 서명되는 점의 x 좌표만 먼저 GF(2^m) 원소에서 정수로 변환하면
  되는데, FIPS 186-4 부록 C.2가 이진 곡선에 대해 정의하는 체 원소-정수
  규칙을 씁니다(체 원소의 `m`비트 다항식 기저 표현을 부호 없는 정수로 그대로
  재해석 — `CGf2m::toBigEndian()`/`CBigNum::fromBigEndian()`이 이미 합의하고
  있는 같은 바이트입니다). `keySizes()`는 정확히 한 크기, 선택된 곡선의 체
  차수 `m`(163/233/283/409/571비트)을 받아들입니다. 직렬화 형식은 모양이
  `CEcdsa`의 것과 동일합니다.
- **`crypto/asyms/ed25519.hpp` / `src/crypto/asyms/ed25519.cpp`**는
  `Ed25519`(edwards25519 위의 EdDSA, RFC 8032)를 정의합니다. 그 체/점 연산은
  `CEcCurve`를 거치지 않고 이 곡선 하나에 전용입니다(`CEcCurve`는
  short-Weierstrass 곡선만 모델링합니다. edwards25519는 twisted Edwards
  곡선이고, 다르고 무조건 완전한 덧셈 법칙을 가집니다 —
  `CEcCurve::add()`/`doublePoint()`와 달리 공식 하나가 점 덧셈과 배가 둘 다를
  다룹니다).

  **모듈러스 둘, 타입 둘.** Ed25519는 점 좌표에 대해서는 체 소수
  `p = 2^255 - 19`로, 스칼라에 대해서는 군 위수
  `L = 2^252 + 0x14DEF9DEA2F79CD65812631A5CF5D3ED`로 작동하며, 그 둘은 규율이
  아니라 타입 시스템으로 떨어져 있습니다. 좌표는
  `Fe25519`(`src/crypto/asyms/fe25519.hpp`. `X25519`와 공유)이고 `p`만
  구현합니다. 스칼라 — clamp된 개인 스칼라, 서명의 nonce `r`, 축약된 해시
  `k`, 서명의 `S` — 는 `groupOrder()`로 축약된 `CBigNum`입니다.
  `EdPoint`/`EdPointProj`는 `Fe25519` 외에 아무것도 보유하지 않고,
  `Fe25519`에는 `CBigNum`과의 변환이 없습니다(유일한 외부 표현이 32바이트
  입니다). 그래서 스칼라가 체 연산에 도달하거나 좌표가 mod-`L` 연산에
  도달하려면 컴파일되지 않는 코드가 필요합니다. 이 구분이 중요한 이유는
  스칼라를 `p`로 축약하면 자기 자신에 대해서는 검증되고 세상의 다른 어떤
  것에 대해서도 검증되지 않는 서명이 나오기 때문입니다 — 어떤 자기 일관성
  테스트도 볼 수 없는 실패이고, 그래서 RFC 8032 7.1절의 바이트 단위 벡터
  다섯 개 전부를 확인합니다.

  모든 곡선 상수(방정식 파라미터 `d = -121665/121666 mod p`, 기준점)는
  255비트 리터럴로 하드코딩되지 않고 최초 사용 시 작은 정수에서
  *유도*됩니다. 더 단순한 닫힌 형태가 없는 군 위수의 덧수
  (`0x14DEF9DEA2F79CD65812631A5CF5D3ED`. 두 번째 출처에 독립적으로 확인)만
  예외입니다 — 옮겨 적는 대신 유도하는 것이 위의 NIST 곡선 상수들이 두 번
  겪은 바로 그 부류의 실수를 비켜 갑니다. `sign()`/`verify()`의 "digest"
  파라미터는 특이하게 해시가 아니라 *원시 메시지*입니다. pure EdDSA는 자기
  입력을 내부적으로 해싱하므로 받아들일 호출자 제공 digest가 없는데, 이
  라이브러리의 다른 모든 알고리즘과 다릅니다. 키와 서명은 DER 구조 없이
  RFC 8032 자신의 원시 바이트 인코딩(32/32/64바이트)으로 직렬화됩니다.
  이미 그 포맷 자체이기 때문입니다. RFC 8032 7.1절의 기지 응답 벡터 다섯
  개(빈 메시지, 1, 2, 64, 1023바이트) 전부에 대해 검증했습니다 — EdDSA
  서명은 결정론적이므로(서명별 난수가 없습니다) 정확한 서명 바이트 일치가
  자기 일관성 왕복 하나만으로는 할 수 없는 정도로 파이프라인
  전체(연산, 유도된 상수, clamping, 그리고 서명 알고리즘 자체)를 훨씬 강하게
  검증합니다.

  `pointAdd()`(아핀)은 단일 연산 경우의 참조 구현으로 남습니다.
  `scalarMul()`(임의의 점)과 `scalarMulBase()`(구체적으로 기준점 `B`. 예컨대
  모든 sign()/verify() 호출의 `B*r`/`B*s` 항)는 `CEcCurve::scalarMul()`이
  쓰는 것과 같은 분기 없는 R0/R1 ladder
  모양(`crypto/eccurve.hpp`의 doc 주석)으로 내부적으로 확장 투영
  좌표(`EdPointProj`: Hisil/Wong/Carter/Dawson의 `X/Z, Y/Z, T=XY/Z`,
  "Twisted Edwards Curves Revisited")에서 작동합니다. 여기서는 더 단순한데,
  `pointAddProj()`가 무조건 완전해서(`P+P`와 항등원을 특수 처리 없이
  다루므로 ladder에 별도 배가 단계가 필요 없습니다) 비트당 하나가 아니라
  맨 마지막에 정확히 한 번의 모듈러 역원 비용만 치릅니다.
  `scalarMulBase()`는 추가로 `B`의 작은 배수들을 담은, 지연 생성되어 프로세스
  수명 동안 캐시되는 테이블을
  씁니다(`baseTable()`. 4비트 window) — `CEcCurve`의 `CEcCurve` 인스턴스별
  테이블과 달리, 이 파일의 기준점은 하나의 고정된 파일 스코프 상수이므로
  프로세스 전체에 테이블 하나로 충분합니다. 둘 다 스칼라를
  `CBigNum::bitLength()`가 아니라 고정된 256비트에 걸쳐 읽으므로, 반복 횟수가
  비밀 스칼라가 얼마나 큰지에 의존하지 않습니다. `CBigNum::testBit()`는
  최상위 limb를 넘어서면 false를 돌려주고, 선행 0 비트는 항등원을 더하며
  ladder의 불변식을 그대로 유지합니다.
- **`crypto/asyms/ed448.hpp` / `src/crypto/asyms/ed448.cpp`**는
  `Ed448`(edwards448/"Ed448-Goldilocks" 위의 EdDSA, RFC 8032)을 정의합니다 —
  구조적으로 `Ed25519`의 쌍둥이이고, 자기만의 체/점 연산(다른 소수이고,
  twisted가 아니라 untwisted Edwards 덧셈이므로 공유 코드가 아닙니다)과
  자기만의 private `EdPublicKey`/`EdPrivateKey`/`EdContext` 클래스를 갖되,
  모든 해시가 SHA-512가 아니라 SHAKE256(114바이트 출력)이고, 각각 RFC 8032
  5.2의 `dom4(F, C)` 문자열이 앞에 붙습니다(여기서는 `F = 0`, 빈 `C`로
  고정: `"SigEd448" || 0x00 || 0x00` — context 문자열은 지원하지 않습니다).
  그 기준점은 직접 옮겨 적으려는 모든 시도를 버틴 하나뿐인 상수입니다.
  x/y 좌표에 대한 "권위 있는" 출처를 반복해서 가져올 때마다 매번 *다른*,
  실제 곡선과 자기 일관되지 않은 값이 나왔습니다(하나는 아예 비트 길이가
  틀렸습니다). 결국 대신 유도했습니다 — `B = [s^-1 mod L] * A`이고, 여기서
  `A`는 RFC 8032 TEST 1의 정확함이 알려진 공개키 점, `s`는 그것의 산술적으로
  유도된 clamp된 스칼라입니다 — 그리고 그것으로부터 바로 그 공개키를 다시
  만들어 내는 것과, 위수가 정확히 `L`인지 확인하는 것으로 독립 확인했습니다
  (둘 다 극히 식별력이 높은 성질이고, 특히 후자가 그렇습니다. edwards448의
  cofactor 4는 대부분의 곡선 점이 애초에 위수 `L`을 갖지 않는다는 뜻입니다).
  키/서명은 RFC 8032의 원시 바이트 인코딩(57/57/114바이트)으로 직렬화됩니다.
  `Ed25519`와 같은 이유로 RFC 8032 자신의 TEST 1 벡터에 대해 검증했습니다.

  `scalarMul()`/`scalarMulBase()`는 `Ed25519`와 같은
  확장-투영-좌표/분기-없는-ladder/고정-기저-테이블 접근(위의 그 doc 주석
  참고)을 쓰지만, edwards448은 *untwisted*이므로(`a = 1`. edwards25519의
  `a = -1`에 대해) 여기의 `pointAddProj()`는 `Ed25519`의 `a = -1` 특화
  법칙이 아니라 일반 `a` 파라미터화 덧셈 법칙을 씁니다 — 이 모양에 대한
  널리 알려진 이름 붙은 공식이 `a = -1`에 특화되어 있으므로, 참조에서 옮겨
  적지 않고 아핀 덧셈 법칙에서 직접 유도했습니다(`ed448.cpp`의 이 함수
  자체 주석 참고). `EdPointProj`의 네 좌표는 `CEcCurve`의 `ECPointJac`이
  그런 것과 같은 이유로 **Montgomery 형태**로 보유되며
  (`CMontgomery`. 위의 `utils/montgomery.hpp` 참고),
  `toProjective()`/`toAffine()`이 변환 경계입니다. `CEcCurve`와 달리 여기의
  컨텍스트는 `fieldPrime()` 옆의 최초 사용 시 생성 싱글턴인데, edwards448에는
  체 소수가 정확히 하나이고 그것이 가변 공개 필드가 아니기 때문입니다. `d`는
  그 옆에 Montgomery 형태로 캐시되고(`curveDMont()`), `fieldSqrt()`의
  `x2^((p+1)/4)`는 `CMontgomery::modExp()`를 거칩니다 — 디코드된 점마다, 즉
  `verify()`마다 한 번씩, 전에는 각각 뒤에 긴 나눗셈이 따라붙던 약 446회
  제곱과 약 223회 곱셈입니다.
- **`crypto/asyms/x25519.hpp` / `src/crypto/asyms/x25519.cpp`**는
  `X25519`(Curve25519 위의 Diffie-Hellman 키 합의, RFC 7748)를 정의합니다 —
  `Ed25519`와 같은 체 소수(`2^255 - 19`)이고, 사실 같은 체 *구현*
  (`Fe25519`, `src/crypto/asyms/fe25519.hpp`)이지만, twisted Edwards가 아니라
  Montgomery 형태 곡선 연산입니다. X25519는 완전한 아핀 점 덧셈이 아니라
  u 좌표 Montgomery ladder(RFC 7748 5)만 필요하기 때문입니다.
  `sign()`/`verify()`는 `IAsymmetricContext`의 `ERET_NOTSUP` 기본값으로
  남아 있습니다(서명 연산이 존재하지 않습니다). `deriveSharedSecret()`만
  override됩니다. 개인키의 원시 32바이트는 clamp되지 않은 채로 저장되고
  각 스칼라 곱 호출 지점에서 clamp됩니다(RFC 7748 5 자신이 권장하는 책임
  분할). 그래서 `serialize()`/`createPrivateKey()`가 항상 호출자의 원래
  바이트를 정확히 왕복합니다. `deriveSharedSecret()`은 계산된 비밀이 전부
  0이면 예측 가능한 출력을 반환하는 대신 거부합니다(RFC 7748 6.1 — 낮은
  위수의 상대 점, 예컨대 `u = 0`). 키는 DER 없이 RFC 7748의 원시 32바이트
  u 좌표/스칼라 인코딩으로 직렬화됩니다. RFC 7748 5.2의 Diffie-Hellman과
  반복 스칼라 곱 기지 응답 벡터에 대해 검증했으며, 이 모듈의 정착된 상수
  검증 규율과 일관되게 한 번 가져온 것을 그대로 옮긴 것이 아니라 하드코딩
  전에 같은 ladder의 독립 Python 구현으로 재유도했습니다.
- **`crypto/transform.hpp`**은 `ITransformer`를 정의합니다. 범용 스트리밍
  변환 인터페이스(`blockSize()`, `transform()`, `transformFinal()`)이고,
  `IAsymmetricTransformer`(RSA로 한 번에 한 블록씩 암복호)와
  `ISymmetricTransformer`(아래) 둘 다 이것에서 파생됩니다.
- **`crypto/sym.hpp`**은 `ISymmetric`, `ISymmetricContext`,
  `ISymmetricTransformer`를 정의합니다 — `asym.hpp`의
  `IAsymmetric`/`IAsymmetricContext`/`IAsymmetricTransformer`에 대응하는
  대칭 암호 쪽이며, 구조적 차이가 하나 있습니다.
  `ISymmetric::createContext(key)`가 키를 즉시 바인딩하고
  (`IAsymmetricContext::keyPair()`와 달리 나중에 채울 키 없는 컨텍스트가
  없습니다), IV는 `createContext()` 자신이 IV를 받지 않으므로
  `ISymmetricContext::key(key, iv)`(같은 메서드를 다시 호출)로 따로
  설정합니다. `ISymmetric::builtIn(which)`은
  `ESymmetrics`(`ESYM_AES`/`ESYM_DES`/`ESYM_3DES`/`ESYM_CHACHA20`) 팩토리이고
  `IAsymmetric::builtIn()`을 반영합니다.
- **`crypto/syms/aes.hpp`/`des.hpp`/`des3.hpp` /
  `src/crypto/syms/aes.cpp`/`des.cpp`/`des3.cpp`**는 `AES`(FIPS-197.
  128/192/256비트 키), `DES`(FIPS 46-3. 레거시/상호운용 전용), 그리고
  `TripleDES`(2키 또는 3키 EDE. 같은 DES 블록 코어 위에 직접 구현)를
  정의합니다. 세 `ISymmetricContext` 모두 CBC 모드로 작동하며 — 이
  라이브러리의 `ISymmetric` 블록 암호들이 구현하는 유일한 모드입니다 —
  공유 `src/crypto/syms/cbctransformer.hpp`/`.cpp`(`CbcTransformer`. 공개
  API의 일부가 아닙니다)를 통해서입니다. 버퍼링, CBC 체이닝, padding
  추가/제거를 알고리즘마다 중복하지 않고 한 번만 빼냈고, 블록별 암복호
  콜백과 블록 크기로 파라미터화됩니다. 복호는 가장 최근에 완성된 블록을
  곧바로 내놓지 않고 항상 붙들어 두는데, 그것이 마지막(padding된) 블록으로
  드러날 수 있기 때문입니다.

  padding은 기본적으로 PKCS#7(RFC 5652 6.3)이고 요청 시 `ESYMPAD_NONE`이며,
  `ISymmetricContext::padding()`을 통해 컨텍스트별로 선택되어 변환기가
  생성될 때 읽힙니다. padding 없는 CBC는 스스로 padding하는 프로토콜을 위해
  존재합니다 — IKEv2(RFC 7296 3.14)는 pad 길이로 끝나는 padding을 페이로드에
  넣으므로, 그 아래의 PKCS#7 블록은 두 번째, 예상되지 않은 padding이 될
  것입니다. padding이 없으면 제거할 것도 없고 마지막 블록이 특별할 것도
  없으므로, 모든 완전한 블록이 완성되는 대로 나가고 붙들려 있는 블록이
  없습니다. `transformFinal()`은 아무것도 만들어 내지 않고, 부분 블록이
  남아 있으면 길이를 조용히 올려 맞추는 대신 `ERET_BADREQ`를 반환합니다.
  `padding()`은 키, IV, 블록 크기와 달리 `reset()`이나 `key()`가 의도적으로
  지우지 **않습니다**. 키 재료가 아니라 모드 선택이고, 지우면
  `padding(ESYMPAD_NONE)` 다음 `key(...)`가 조용히 PKCS#7로 되돌아갈
  것인데 그것은 상대가 거부하는 ciphertext를 내놓는 아주 조용한 방식입니다.
  padding 검증(`transformFinal()`의 복호 경로)은 첫 불일치에서 이른 탈출
  없이, 그리고 pad 값 자체에 대한 분기 없이 모든 바이트 비교를 무조건
  수행하도록 작성되어 있습니다. 적대자가 적응적으로 고른 ciphertext에 대한
  여러 복호 시도를 관측할 수 있게 하는 호출자에 대해
  Vaudenay 식 CBC padding oracle(POODLE/Lucky13 뒤의 바로 그 부류의 버그)을
  피하기 위한 것입니다 — 이 모듈에서 타이밍 부채널 하드닝이 범위 밖이
  아니라 중요한 것으로 취급되는 유일한 곳입니다(`crypto/`의 다른 곳에 있는
  `CEcCurve`/`CBigNum` 자신의 constant-time보다-정확성 입장과 대비됩니다).
  `AesCore`(공유 private `aescore.hpp`/`.cpp`. `aes.cpp`와
  `aeads/aesgcm.cpp` 둘 다 사용), `DesCore`(공유 private
  `descore.hpp`/`.cpp`. `des.cpp`와 `des3.cpp` 둘 다 사용),
  `TripleDesCore`(`des3.cpp`)가 각 알고리즘 자신의 블록 암호 연산을 담고
  있으며, 모듈 밖의 무엇도 그것들을 필요로 하지 않으므로 private으로
  유지됩니다(`SymRawKey`. 길이 외에는 검증하지 않는 자명한 원시 바이트
  `ISymmetricKey`도 `src/crypto/syms/symkey.hpp`를 통해 같은 방식으로
  공유됩니다).

  `AesCore`에는 추가로 하드웨어 가속 경로가 있습니다(x86-64 전용이고
  `CERTPP_DISABLE_HWACCEL_AES`가 설정되지 않았을 때만). 위의
  `SHA1`/`Sha2_32Core::transform`의 SHA-NI 디스패치와 같은 모양입니다.
  `encryptBlock()`/`decryptBlock()`은 얇은 디스패처이고, 런타임 CPUID
  검사(`hasAesNi()`. leaf 1, ECX 비트 25)가 통과하면
  `encryptBlockAccelerated()`/`decryptBlockAccelerated()`를 호출하며, 아니면
  `encryptBlockPortable()`/`decryptBlockPortable()`(원래의 라운드별 구현)로
  돌아갑니다. 가속 경로는 Intel이 발행한
  `AESENC`/`AESENCLAST`/`AESDEC`/`AESDECLAST`/`AESIMC` intrinsic
  수열입니다(`<wmmintrin.h>`). 암호화는 `expandKey()`의 기존 정방향 라운드
  키에 대해 표준 암호를 직접 돌립니다(AES-NI 자신의 키 스케줄이 만들어 낼
  것과 바이트 단위로 동일하므로 별도 하드웨어 키 확장이 필요 없습니다).
  복호는 진짜 역 키 스케줄을 다시 유도하는 대신 "Equivalent Inverse Cipher"
  구성을 씁니다 — 정방향 라운드 키를 역순으로, 첫째와 마지막을 제외한
  각각을 `AESIMC`에 통과시킵니다. `DES`/`TripleDES`에는 대응물이 없습니다.
  DES/3DES의 Feistel 네트워크를 위한 주류 x86 하드웨어 확장이 없습니다.
  ChaCha20의 ARX 라운드에도 전용 확장이 없지만 블록들에 걸쳐 벡터화되므로,
  `CERTPP_DISABLE_HWACCEL_SIMD` 아래의 자기만의 SSE2 경로가 있습니다 —
  위의 `src/crypto/syms/chacha20core.hpp` 항목을 보십시오.
  이 모듈이 이미 돌리는 같은 SP 800-38A/FIPS-46/RFC 8439 기지 응답 벡터로
  검증합니다 — AES-NI를 지원하는 CPU에서는 그것들이 가속 경로를 자동으로
  거치며, 명시적 비교를 위해 이식 가능 경로를 강제할 수 있도록
  `CERTPP_DISABLE_HWACCEL_AES`가 있습니다.
- **`crypto/syms/chacha20.hpp` / `src/crypto/syms/chacha20.cpp`**는
  `ChaCha20`(RFC 8439)을 정의합니다. 256비트 키, 96비트 nonce(`iv()`),
  그리고 내부 32비트 블록 카운터(항상 0에서 시작)가 입력과 XOR되는 키스트림으로
  확장됩니다 — 암호화와 복호화가 동일한 연산이므로 `createDecrypter()`는
  `createEncrypter()` 모양의 변환기를 하나 더 반환하기만 합니다. 스트림
  암호이므로 padding이 필요 없고 입력 길이에 블록 정렬 요구를 두지 않습니다.
  `sizeOfBlock()`(키가 바인딩되면 64)은 정렬 요구가 아니라 암호의 내부
  키스트림 생성 단위만 보고합니다. RFC 8439 부록 A.1의 블록 함수 기지 응답
  벡터에 대해 검증했습니다.
- **`x509/ext.hpp` / `src/x509/ext.cpp`**는 `IExtension`을 정의합니다.
  디코드된 모든 X.509 확장의 구체적인(`I` 접두사에도 불구하고 순수 가상이
  아닙니다 — 이 라이브러리가 더 모델링하지 않는 OID에 대해 그 자체로 완전히
  쓸 수 있습니다) 기반입니다. `oid()`(점 구분 10진 텍스트) +
  `value()`(원시, 아직 DER로 인코드된 `extnValue` 옥텟) +
  `critical()`(`Extension.critical`, RFC 5280 4.2. 기본값 `false`이고,
  부재 필드에 대한 DER 자신의 기본값과 일치합니다), 그리고
  `IExtensionPtr`과 정적 `IExtension::create(oid, value)` 팩토리입니다.
  `create()`는 OID로 `x509/exts/` 아래의 맞는 구체 클래스에
  디스패치하고(아래 참고), 이 라이브러리가 온전히 모델링하지 않는 OID에
  대해서는 private `UnknownExtension`(`ext.cpp`에 정의되어 있고 공개 API의
  일부가 아닙니다)으로 돌아갑니다 — 그래서
  `CCert::extensionOf()`/`extension<T>()`(아래 `cert.hpp` 참고)는 존재하는
  확장에 대해 그 구체 타입이 인식되는지와 무관하게 항상 *무언가*를 반환하고
  null을 반환하는 일이 없습니다. `critical()`에는 공개 setter가
  있습니다(oid/value만 받는 각 구체 하위 클래스의 생성자에 모두 엮어 넣지
  않았습니다). 그래서 `CCert::parseExtensions()`가 파싱된 인증서의
  `Extension.critical` 필드에서 읽은 값을
  `create()`가 반환한 뒤 별도 단계로 기록할 수 있고, `IExtensionBuilder`가
  자기가 만든 확장을 `CCertBuilder::extensions`에 추가하기 전에 critical로
  설정할 수 있습니다(`CCertBuilder::build()`는 false일 때 `critical`
  BOOLEAN을 DER 정규적으로 생략하고 true일 때만 씁니다). 이 라이브러리는
  `critical()`을 파싱하고 보존합니다. RFC 5280의 "인식되지 않는 critical
  확장을 가진 인증서를 거부하라" 규칙을 어디에서도 스스로 강제하지는
  않습니다 — `CCert`에는 체인 검증 엔진이 아예 없으므로(이 문서 자신의 범위
  설명 참고), 그 정책 결정은 `CCert`의 파싱된 확장을 소비하며 그 위에 검증기를
  만드는 코드에 맡겨져 있습니다.
- **`x509/generalname.hpp` / `src/x509/generalname.cpp`**는 `CGeneralName`을
  정의합니다. `GeneralName` 하나(RFC 5280 4.2.1.6)이고 9지 CHOICE
  (`EGeneralNameType`. context-specific 태그 0–8)이며 서로 다른 네 확장이
  씁니다(`SubjectAltName`, `AuthorityKeyIdentifier`의
  `authorityCertIssuer`, `CRLDistributionPoints`의 `fullName`,
  `AuthorityInformationAccess`의 `accessLocation`, 그리고
  `NameConstraints`의 `GeneralSubtree.base`) — 각각에 9지 CHOICE 디코더를
  중복하는 대신 여기 한 번만 빼냈습니다. 상용 인증서에서 현실적으로 보이는
  대안만 타입별 접근자를 얻습니다
  (`rfc822Name`/`dNSName`/`uniformResourceIdentifier`/`registeredID`에
  대해서는 `text()`, `directoryName` 대안에 대해서는 `directoryName()`).
  `otherName`/`x400Address`/`ediPartyName`은 그 드문 모양들을 온전히
  모델링하는 대신 원시, 아직 DER로 인코드된 내용(`raw()`)만 유지합니다.
  `decode()`의 `directoryName` 경우는 내부 `RDNSequence`에 도달하기 전에
  TLV 계층을 하나 더 벗깁니다. `directoryName [4]`가 EXPLICIT이어야
  하기 때문입니다(`Name` 자체가 CHOICE이고, ASN.1은 그것에 암묵적 태그를
  붙이는 것을 금지합니다) — 여기의 IMPLICIT인 다른 모든 대안과 다릅니다.
  `decodeList()`는 `GeneralNames` `SEQUENCE OF GeneralName` 전체를
  디코드하며, 개별 원소의 `decode()`가 파싱할 수 없는 것은 중단하지 않고
  건너뜁니다. 이 모듈의 정착된 최선 노력 철학과 일치합니다(아래 `cert.hpp`
  참고). `CGeneralSubtree`(`NameConstraints`의 `GeneralSubtree`: `base`
  `GeneralName`과 선택적 `minimum`/`maximum` 거리 경계)는 바로 이 파일
  `CGeneralName` 바로 아래에 있습니다. 그것 외에는 자기 정체성이 없는
  `GeneralName` 모양의 값이기 때문입니다.
- **`x509/access.hpp` / `src/x509/access.cpp`**는
  `CAccessDescription`(`AuthorityInformationAccess`의 `AccessDescription`:
  접근 방법 OID + `CGeneralName` 위치)과, 그 아래에 `ECrlReasons` +
  `CDistributionPoint`(`CRLDistributionPoints`의 `DistributionPoint`:
  `fullName`/`nameRelativeToCrlIssuer` CHOICE, 선택적 `reasons` 비트 플래그,
  선택적 `crlIssuer`)를 정의합니다. `ECrlReasons`의 비트 위치는
  `ReasonFlags` BIT STRING 자신의 RFC 5280 4.2.1.13 명명 비트 번호와 직접
  대응합니다(비트 1 = `keyCompromise` .. 비트 8 = `aACompromise`).
  `exts/ku.hpp`의 `EKeyUsages`(아래 참고)와 다릅니다 — 여기에는 보존해야 할
  기존의, 테스트된 비트 배치가 없으므로, `EKeyUsages`의 역사적 반전을
  무관한 새 코드에 전파하는 대신 자연스러운 RFC 번호를 그대로 씁니다.
  `CDistributionPoint::decode()`의 `distributionPoint [0]` 경우는
  `CGeneralName`의 `directoryName` 경우와 같은 EXPLICIT-CHOICE 이유로 TLV
  계층을 하나 더 벗깁니다(`DistributionPointName`이 CHOICE입니다). 두 클래스
  모두 각각이 뒷받침하는 단일 확장 클래스 옆에 있지 않고 이 파일 하나로
  묶여 있는데, 미래의 호출자가
  `CCdpExtension`/`CAiaExtension`과 독립적으로 그것들을 생성/비교하고 싶을
  수 있기 때문입니다.
- **`x509/policy.hpp`**은 `CPolicyInformation`(`CertificatePolicies`의
  `PolicyInformation`: 정책 OID + `policyQualifiersRaw()`)을 정의합니다.
  `policyQualifiers` `SEQUENCE OF PolicyQualifierInfo`는
  `PolicyQualifierInfo` 자신의 `CPSuri`/`UserNotice` CHOICE를 온전히
  모델링하는 대신 의도적으로 원시, 아직 DER로 인코드된 내용으로 유지합니다 —
  호출자는 압도적으로 `policyIdentifier()` 자체만 필요하므로(예:
  `OID_ANY_POLICY` 같은 특정 CA/Browser 포럼 정책 OID를 확인하기 위해),
  추가 파싱 복잡도가 아직 값을 하지 않습니다. 전부 인라인이므로 짝이 되는
  `.cpp`가 없습니다.
- **`x509/exts/`**는 이 라이브러리가 모델링하는 RFC 5280 확장당 구체
  `IExtension` 하위 클래스 하나를 담고 있으며, 이름은 온전히 적는 대신 통용
  약칭으로 붙였습니다(`bc.hpp` = `CBasicConstraintsExtension`,
  `ku.hpp` = `CKeyUsagesExtension`(+ `EKeyUsages`), `eku.hpp` =
  `CEkuExtension`, `san.hpp` = `CSanExtension`, `ski.hpp` =
  `CSkiExtension`, `aki.hpp` = `CAkiExtension`, `cdp.hpp` =
  `CCdpExtension`, `aia.hpp` = `CAiaExtension`, `cp.hpp` =
  `CPoliciesExtension`, `nc.hpp` = `CNameConstraintsExtension`).
  전부 같은 모양을 따릅니다. 자기 확장 OID를 지칭하는
  `public static constexpr const char* OID`(`ext.cpp`의 디스패치 테이블이
  대조합니다), 원시 `extnValue` 옥텟을 받아 최선 노력으로 파싱하는 생성자
  하나(잘못된 필드는 확장 전체를 실패시키는 대신 안전한 기본값으로 남습니다.
  아래 `CCert::importDer()` 자신의 철학을 반영합니다), 그리고 디코드된 결과에
  대한 읽기 전용 접근자들입니다. 각각 인코딩 방향을 위해
  `IExtension::encodeValue(CBuffer&)`와 순수 가상
  `IExtensionBuilder::build()`(`x509/ext.hpp`) 위의 짝이 되는
  `C<Name>ExtensionBuilder`도 가집니다 — 열 개 parse/build 쌍 전부가
  존재하므로 확장을 왕복할 수 있고, `CCertBuilder::extensions`가 그 빌더들을
  받습니다. `EKeyUsages`(`ku.hpp`)가 "자연스러운 RFC 비트 순서"의 하나뿐인
  예외입니다. 그 비트 위치는 `KeyUsage` BIT STRING 자신의 명명 비트 번호에서
  역사적으로 반전되어 있으며, 위의 `ECrlReasons`의 RFC 직접 관례에 맞추도록
  "바로잡는" 대신 `CCert`가 원래 정의한 그대로(그리고 기존 테스트가 이미
  단정하는 그대로) 정확히 보존됩니다. 이미 테스트된 공개 enum의 값을 바꾸는
  것은 고치는 변경이 아니라 깨뜨리는 변경이기 때문입니다. `eku.hpp`는
  추가로 널리 알려진 `KeyPurposeId` OID 상수들
  (`OID_SERVER_AUTH`, `OID_CLIENT_AUTH`, ...)과 `has(oid)` 편의 조회를
  정의합니다. `cdp.hpp`/`aia.hpp`/`cp.hpp`/`nc.hpp`는 각각 얇은
  확장 수준 래퍼(OID + 디코드된 항목들의 `TArray`)이고, 위의 그 파일들
  항목에 따라 `x509/access.hpp`/`x509/policy.hpp`/`x509/generalname.hpp`가
  실제로 정의하는 값 타입들을 둘러쌉니다.
- **`x509/cert.hpp` / `src/x509/cert.cpp`**는 `CCert`를 정의합니다. DER
  X.509 `Certificate`를 파싱해(`importDer(data)`) subject/issuer
  (`CDistinguishedName`), 유효 기간(`SDateTime`), 일련번호, 키/서명 알고리즘
  식별자, 원시 `SubjectPublicKeyInfo`, 그리고 모든 확장으로 만듭니다. 이
  클래스가 getter를 노출하는 필드만 유지됩니다 —
  `issuerUniqueID`/`subjectUniqueID`와 TBSCertificate에 박힌 서명 알고리즘
  사본은 읽고 지나가되 버립니다. 파싱은 하나의 일관된 최선 노력 계약을
  따릅니다. `importDer()`는 모든 필드를 먼저 지역 변수에 만들고 맨 마지막에만
  `*this`에 반영하므로(중간에 실패해도 객체를 반쯤 채워진 상태로 두는 일이
  없습니다), 그러나 인식하지 못하는 *알고리즘*(목록에 없는 키/서명/곡선
  OID)은 그 자체로 파싱 실패가 되는 일이 절대 없습니다 —
  `keyAlgo()`/`signAlgo()`가 OID 자신의 점 구분 10진 텍스트로 돌아가고,
  `publicKey()`/`createHasher()`는 단지 null을 반환합니다. 이 라이브러리가
  인증서의 암호 알고리즘에 대해 행동할 수 없을 때에도 나머지 데이터는
  여전히 의미가 있기 때문입니다. 세 private 정적 테이블
  `KEY_ALGOS`/`SIG_ALGOS`/`EC_CURVES`(각각 `{oid, name, which}`)가 그 해석을
  구동합니다. DSA 키의 쪼개진 `SubjectPublicKeyInfo` 표현
  (`Dss-Parms {p, q, g}` + 벌거벗은 `INTEGER y`)은
  `buildDsaPublicKeyBlob()`를 통해 `DSA::createPublicKey()`가 기대하는 독립
  `SEQUENCE {p, q, g, y}` blob으로 재조립되며, 이 추가 단계를 필요로 하는
  유일한 알고리즘입니다.

  `signatureAlgorithm`의 `parameters` 필드는 정확히 한 알고리즘,
  id-RSASSA-PSS(1.2.840.113549.1.1.10, RFC 4055)에 대해서만 읽힙니다 —
  OID 자신이 digest를 지칭하지 않으므로, 여기서 파라미터가 NULL 자리표시가
  아니라 검증자가 필요한 정보를 담는 유일한 서명 알고리즘입니다.
  `parseRsaPssParams()`(`buildRsaPssParams()`의 역)가 `RSASSA-PSS-params`를
  `SRsaPssParams`로 읽고 `rsaPssParams(out)`가 그것을 노출하며, 그 다음
  `_sigHashAlgo`가 그 `hashAlgorithm`에서 설정되므로 `createHasher()`와
  `verifyBy()`가 다른 모든 알고리즘에 대해서처럼 동작합니다. 네 필드 전부가
  `DEFAULT`이고 DER는 기본값과 같은 필드를 생략하므로, 파싱은 바로 그
  기본값들(SHA-1, MGF1-SHA-1, salt 20, `trailerFieldBC`)을 담고 있는
  `SRsaPssParams` 자신의 생성자에서 시작하며, 부재 필드는 "부재"가 아니라 그
  기본값으로 보고됩니다. DER 아래에서 그 둘은 같은 진술이기 때문입니다.
  파싱되지 *않는* 파라미터는 해석되지 않은 OID와 같은 최선 노력 계약을
  따릅니다. `signAlgo()`는 여전히 `rsassaPss`로 읽히지만 `_sigHashAlgo`는
  `EHASH_UNKNOWN`으로 남으므로, `verifyBy()`는 그 SHA-1 기본값으로
  돌아가는 대신 `ERET_NOTSUP`을 보고합니다 — 그렇게 돌아가는 것은 서명이
  무엇을 덮는지에 대한 추측이 될 것입니다.

  `publicKey()`/`privateKey()`는 진짜로 지연 평가됩니다.
  `_cachedPub`/`_cachedPvt`(`mutable`)는 `importDer()`가 지우기만 하고(다시
  만들지 않습니다) 각 접근자가 처음 호출될 때에만 실제로 생성됩니다 — 키를
  한 번도 요청하지 않는 호출자는 그것에 아무 비용도 치르지 않습니다.
  `privateKey(IPrivateKeyPtr&)`(setter)는 들어오는 키가 진짜로 이 인증서
  자신의 것인지, 그것의 유도된 공개키를 `publicKey()`와 비교해
  (`IKeyBase::compare()`) 받아들이기 전에 검증합니다. `createHasher()`는
  *서명* 알고리즘 자신의 digest를 해석합니다(`_sigHashAlgo`. `importDer()`
  중에 `signAlgo()`의 OID에서 설정됩니다) — `thumbprint()`와는 무관하며,
  그쪽은 인증서의 실제 서명 알고리즘과 무관하게 무조건 원시 인증서 전체의
  SHA-1 digest입니다. 대부분의 도구에서 인증서 "지문"의 통상적 의미와
  일치합니다.

  확장들은 `std::vector<IExtensionPtr>`(`_extensions`)로 보유되며,
  `IExtension::create()`를 통해 private `parseExtensions()`가 한 번
  채웁니다. 그것은 각 확장의 `critical()` 플래그도 기록하고, RFC 5280이
  금지하는 중복 쌍을 쌓는 대신 반복된 OID를 건너뜁니다 — 첫 등장만
  유지합니다. 그러지 않으면 `extensionOf()`의 첫 일치 조회와 `_extensions`를
  직접 순회하는 호출자가 서로 다른 답을 낼 수 있습니다. 조회는
  `extensionOf(oid, out)`(선형 탐색 — 실제 인증서의 확장 수는 항상 작으므로
  map이 필요 없습니다)으로 하거나, 더 흔하게는 공개
  `template<typename TExtension> extension<TExtension>()` 보조 함수로
  하는데, 그것은 `TExtension::OID`를 조회하고 결과를
  `dynamic_pointer_cast`합니다 — 예컨대
  `cert.extension<CBasicConstraintsExtension>()`입니다. `keyUsages()`,
  `subjectKeyIdentifier()`, `authorityKeyIdentifier()`는 모두 각각
  `exts/ku.hpp`/`ski.hpp`/`aki.hpp` 위의 `extension<T>()`를 부르는 얇은
  호출자이고, 거의 모든 소비자가 필요로 하는 세 확장이므로 (모든 호출자가
  `extension<CKeyUsagesExtension>()` 등을 직접 적어야 하게 하는 대신) 자기
  이름을 가진 메서드로 유지합니다.

  `verifyBy(issuer)`는 "이 발급자가 이 인증서에 서명했는가?"에 답합니다 —
  자기 서명된 것에는 `*this`를 넘기십시오. `tbsCertificate()`(파싱된 필드를
  다시 인코드한 것이 아니라 `rawData()`에 나타나는 원래 TBS TLV. 서명이
  발급자의 바이트를 덮으므로, 다시 인코드하면 그것이 담고 있는 어떤 특이점도
  조용히 "고쳐" 버릴 것입니다)를 해싱하고 발급자의 공개키로 `signature()`에
  대조해 확인합니다. 해싱을 할지 말지는 `_sigHashAlgo == EHASH_UNKNOWN`이
  아니라 *발급자 키* 자신의 알고리즘에서 결정됩니다. 그 값이 모호하기
  때문입니다 — `resolveSigAlgo()`는 등록되지 않은 OID에 대해 그것을 건드리지
  않고 두는데, 이는 EdDSA의 정당한 "별도 해시 없음"과 구별되지 않으며,
  그것을 EdDSA로 읽으면 원시 TBS 바이트를 digest인 것처럼 ECDSA/DSA 검증에
  건네게 됩니다.

  그 결정이 `CCert::signsMessageDirectly(which)`이고, 각 지점에서 반복되는
  술어가 아니라 함수 하나입니다 — Ed25519, Ed448, 그리고 세 ML-DSA
  파라미터 집합이 메시지 자체를 서명합니다. 네 곳이 그것에 대해 의견이
  일치해야 하고(`CCert::verifyBy()`, `CCrlReader::verifyBy()`, 그리고 두 OCSP
  `verifySignature()`), 항목 하나를 놓친 지점은 컴파일에 실패하지도, 큰 소리로
  실패하지도 않습니다. 원시 TBS 바이트를 hash-then-sign 검증에 건네거나,
  digest를 ML-DSA에 건네 메시지 대신 그 32바이트 문자열을 서명합니다. 둘 다
  여기서 실제 버그였고, 어느 쪽도 자기 서명 왕복에는 보이지 않습니다.

  자기 해싱 알고리즘에 대해서는 서명 BIT STRING의 내용이 통째로 전달됩니다.
  ML-DSA의 서명은 ECDSA의 `SEQUENCE { r, s }`와 달리 EdDSA의 `R || S`와 정확히
  같이 내부 ASN.1이 없는 불투명한 blob 하나(`c-tilde || z || h`)입니다 —
  ECDSA 쪽은 `verifyBy()`가 아니라 EC 구현이 스스로 풀어냅니다.

  `verifyBy()`는 *링크 하나*에 대한 검사입니다. 이름 연결도, 유효 기간도,
  제약 강제도 없습니다. RSASSA-PSS로 서명된 인증서는 PKCS#1 v1.5의
  `verify()`가 아니라, 자신의 `RSASSA-PSS-params`가 명시하는 해시와 salt
  길이로 `IAsymmetricContext::verifyPss()`를 거쳐 갑니다. 인코드할 수는
  있지만 지원되지 않는 두 경우는 근사되지 않고 `ERET_NOTSUP`으로 닫히며
  실패합니다. `maskGenAlgorithm`이 `hashAlgorithm`과 다른 해시를 지칭하는
  경우(이 라이브러리의 `verifyPss()`는 해시 알고리즘 하나를 받아 둘 다에
  쓰는데, 그것이 RFC 8017이 권장하는 유일한 짝입니다)와, `trailerField`가
  `trailerFieldBC`가 아닌 경우입니다. 틀린 MGF1 해시로 검증하면 모든 유효한
  서명을 거부할 것이고, 호출자는 그것을 위조와 구별할 수 없습니다.

  `importDer()`는 없을 때 악용 가능했던 몇 가지 DER 규칙을 강제하며, 각각
  `tests/x509/malformed.cpp`가 덮습니다. `Certificate` SEQUENCE가 입력
  전체여야 합니다(뒤에 붙은 것은 `_rawData`에 그대로 유지되므로, 그것을
  받아들이면 인증서 하나에 무한히 많은 `thumbprint()` 값이 생기고
  `exportDer()`가 DER가 아닌 바이트를 다시 내놓게 됩니다). `extensions [3]`
  래퍼가 constructed여야 하고 파싱되어야 합니다. 잘못된 것을 "확장 없음"으로
  취급하면 제약이 걸린 인증서가 제약 없는 인증서로 바뀌면서도 import는
  성공했기 때문입니다. `TBSCertificate.signature`가
  `Certificate.signatureAlgorithm`과 같은 알고리즘을 지칭해야 합니다
  (RFC 5280 4.1.1.2 — 내부 사본은 서명되고 외부는 아닌데, 검증을 구동하는
  것은 외부입니다). 그리고 `signatureValue`의 BIT STRING이 사용하지 않는
  비트를 0으로 선언해야 합니다. `SubjectPublicKeyInfo` 쪽이 이미 그래야 했던
  것처럼요.

  실재하고 현재 유효한 상용 인증서들(`openssl s_client`/crt.sh로 가져온
  것)이 `tests/x509/certs/implemented/`에 `.der` 파일로 체크인되어
  있습니다(작은 `readCertFile()` 테스트 보조 함수로 읽고, 모든 테스트
  타깃이 받는 범용 `CERTPP_TEST_DIR` 컴파일 정의로 위치를 찾습니다 —
  `CMakeLists.txt`의 테스트 등록 루프 참고). `certs/unimplemented/`
  디렉터리는 더 이상 없습니다. 거기에는 RSASSA-PSS 중간 인증서와 ML-DSA
  루트, 둘이 있었고 이제 둘 다 import되고 파싱되고 검증되므로 둘 다
  옮겨졌습니다. RSASSA-PSS 쪽은 애초에 거기 잘못 분류되어 있었습니다.
  RSA-PSS *알고리즘*은 `crypto/asyms/rsa.cpp`의 `signPss()`/`verifyPss()`
  이후로 구현되어 있었습니다. 없던 것은 그것에 이르는 인증서 경로였고, 그
  import는 서명 알고리즘을 읽기도 전에 subject `Name`의 인식되지 않는
  `organizationIdentifier`에서 실제로 실패했습니다. 미래의 인증서가 실제
  공백을 드러내면 그 디렉터리를 다시 만드십시오 — 그 구분이 "이것은 알려진
  공백이다"를 "아무도 보지 않았다"와 구별되게 해 주는 것입니다.
  구현된 것 중 하나는 나머지와 다르게 자기 무게를 합니다.
  `identrust-mldsa-root.der`은 실재하는 "IdenTrust Pilot Root TLS ML-DSA
  CA 1"(OID 2.16.840.1.101.3.4.3.19이고 이는 **id-ml-dsa-87**입니다. arc가
  ML-DSA-44/65/87에 대해 .17/.18/.19로 흐르고, 인증서 자신의 2592바이트 키와
  4627바이트 서명이 어느 것인지 확인해 줍니다)이며, 자기 서명되어 있으므로
  그것에 대한 `cert.verifyBy(cert)`는 종단 간으로 검증되는 진짜 제3자
  포스트 양자 서명입니다. ML-DSA 구현이 일관되게 틀린 상태로는 통과할 수
  없는, 이 테스트 모음에서 유일한 검사입니다 — 자기 자신에 대한 서명/검증
  왕복은 전치된 `expandA`, 모양이 잘못된 `Decompose` 예외, 또는 외부
  인터페이스가 와야 할 자리에 쓰인 내부 서명 인터페이스를 모두 살려
  둡니다. 동반 테스트 케이스가 TBS에서, 서명에서, 공개키에서 한 비트씩
  뒤집고 각각 실패해야 한다고 요구합니다.
- **`x509/crl.hpp` / `src/x509/crl.cpp`**는 CRL(RFC 5280 5) 쪽을 정의하며,
  읽기/쓰기 클래스 하나가 아니라 세 타입으로 나뉩니다.
  `CCrlRevokationInfo`는 `revokedCertificates` 항목 하나입니다
  (`serialNumber()`, `timestamp()`, `reason()`, 더해서 인증서에 대해 그것을
  시험하는 `isFor(cert)`와 자기 TLV를 위한 `encode()`/`decode()`).
  `CCrlReader`는 `CertificateList`를 파싱하고(`decode()`, 그 다음
  `version()`/`issuer()`/`thisUpdate()`/`nextUpdate()`/`revokations()`)
  호출자가 실제로 가진 두 질문에 답합니다 — 일치하는 항목을 위한
  `find(cert, out)`과 폐기됨/안 됨 판정만을 위한 `check(cert)`입니다.
  그리고 `CCrlWriter`가 하나를 만듭니다
  (`add(cert, when, reason)`/`remove(cert)`, 그 다음 발급자의 키로 서명하는
  `build(issuer, out)`). reader/writer 분리는 `CCert`의 단일
  import/export 클래스가 아니라 `asn1` 자신의 `CReader`/`CWriter`를
  반영하는데, CRL이 자연스럽게 서로 다른 당사자에 의해 생산되고 소비되기
  때문입니다.
  `ECrlReasons`(`x509/access.hpp`)는 CRLDistributionPoints 확장과
  공유됩니다. RFC 5280 5.3.1의 `CRLReason` 와이어 값과 그 플래그 비트
  사이의 ENUMERATED-플래그 매핑은 의도적으로 1:1이 아니므로
  (`ReasonFlags` 비트 7/8 대 ENUMERATED 9/10, 그리고 ENUMERATED 8
  `removeFromCRL`은 플래그가 아예 없습니다), 호출 지점마다 직접 적는 대신
  자기만의 private `CrlReasonCodec`(`src/x509/crlreason.hpp`)에 있습니다.
  `verifyBy(issuer)`/`tbsCertList()`/`signature()`는 `CCert` 자신의 셋을
  정확히 반영하며, 발급자 키의 알고리즘에서 해시 여부를 결정하는 것까지
  같습니다 — 그 이유는 해당 항목을 보십시오.
  범위 설명 둘: `check()`는 인증서가 그 목록에 나타나는지만 보고합니다 —
  자기 서명은 전혀 검증하지 않으며(`verifyBy()`를 따로 호출하십시오), 그 CRL이
  인증서 자신의 발급자가 발행한 것인지도 확인하지 않으므로, 일련번호가 충돌하는
  무관한 CA의 CRL도 여전히 판정을 내놓을 것입니다 — 그리고 `CCrlWriter`는
  `crlExtensions`를 내놓지 않으므로, RFC 5280 5.1.2가 기대하는
  `CRLNumber`/`AuthorityKeyIdentifier`가 그것이 만든 CRL에는 없습니다.
- **`x509/ocsp.hpp` / `src/x509/ocsp.cpp`**는 OCSP(RFC 6960) 요청/응답 쌍을
  정의합니다. `x509/`에서 서명 *검증*이 존재하는 유일한 곳입니다.
  `COcspCertId`는 호출자가 고른 `hashAlgo()`(기본 SHA-1. 배포된 responder들이
  기대하는 것입니다) 아래에서 발급자 이름 해시, 발급자 키 해시, 일련번호로
  인증서를 식별하는 `CertID`입니다. `COcspEntry`는 `SingleResponse`
  하나입니다(`certId()`, `status()`, `reason()`,
  `thisUpdate()`/`nextUpdate()`/`revocationTime()`).
  `COcspRequest`/`COcspRequestBuilder`와
  `COcspResponse`/`COcspResponseBuilder`는 그 다음 CRL 타입들과 같은
  파싱 쪽/빌드 쪽 분리를 따릅니다. 빌더는 인증서를
  받고(`add(cert, issuer, hashAlgo)`), nonce를 생성하고(`generateNonce()`),
  DER를 `build()`합니다. 파싱 쪽은 `decode()`, 디코드된 항목들, 그리고 —
  `CCert`/`CCrlReader`와 달리 — 진짜 `verifySignature(responderCert)`를
  노출합니다. `EOcspStatus`가 최상위 `responseStatus`를 담고, 문법상
  `EOCSP_OK`만이 그 이상의 무엇을 담으므로, `COcspResponse::status()`를 먼저
  확인해야 다른 어떤 접근자든 의미를 가집니다. `find()`/`check()`는
  `CCrlReader`의 것을 반영합니다. 양쪽이 모두 필요한 공유 와이어 보조
  함수들(nonce와 basic-response OID, 단일 확장 목록 인코딩,
  `GeneralizedTime` 포매팅)은 private
  `OcspCodec`(`src/x509/ocspcodec.hpp`)에 있습니다.
- **`x509/csr.hpp` / `src/x509/csr.cpp`**는 PKCS#10(RFC 2986) 인증 요청 쌍
  `CCertRequest`/`CCertRequestBuilder`를 정의하며,
  `COcspRequest`/`COcspRequestBuilder`를 따라 이름 지었습니다 — 가장 가까운
  선례인데, CSR도 마찬가지로 한 당사자가 생산하고 다른 당사자가 소비하는
  객체 하나이기 때문입니다. 파싱 쪽은 `CCert`의 표면을 반영합니다
  (같은 `ECertFormat`을 쓰는 `importDer()`/`importPem()`/`importFrom()`,
  `exportDer()`/`exportPem()`/`exportAs()`, `subject()`,
  `keyAlgo()`/`signAlgo()`, `rawPublicKey()`/`publicKey()`, `signature()`,
  `rsaPssParams()`, `extensionOf()`/`extension<T>()`), 더해서
  `certificationRequestInfo()` — `CCert::tbsCertificate()`와 같은
  원래-바이트이지-다시-인코드한-것이-아니라는 의미에서 정확히 서명된
  바이트입니다.

  PKCS#10에 특정하고 알아 둘 만한 것이 셋 있습니다.

  1. **import가 자기 서명을 검증하고, 그것 없이는 실패합니다.** CSR의 모든
     필드는 그것을 만든 쪽의 인증되지 않은 주장입니다. 자기 서명이 요청이
     증명하는 유일한 것(`subjectPKInfo`의 개인 절반을 보유하고 있음)이므로,
     `importDer()`는 그것이 확인되기 전에는 `ERET_OK`를 보고하기를 거부하고,
     이 라이브러리가 검증할 수 없는 알고리즘으로 서명된 요청은 확인 없이
     import되는 대신 거부됩니다. 그것은 `CCert::importDer()`의 의도적인
     관대함과 반대이고, 이유가 있습니다. 인증서의 필드는 발급자의 키에
     도달할 수 없는 호출자에게도 여전히 의미가 있지만, 요청의 필드는 그렇지
     않습니다. 손으로 다시 확인하기 위해 `verify()`도 공개되어 있습니다.
  2. **`attributes [0] IMPLICIT Attributes`는 OPTIONAL이 아닙니다.** 담을 것이
     없는 요청도 존재하지만 빈 SET(`A0 00`)을 쓰며, 그 필드를 생략한 요청은
     거부됩니다 — OpenSSL 자신은 그런 요청을 받아들이므로, 이 검사는
     명시적이어야 합니다. `SCertRequestAttribute`는 속성 하나의 타입 OID와
     그 `values SET OF` 내용을 그대로 보유하고, 양방향에서 같은 의미를
     가지므로 파싱된 속성이 빌더로 바로 되돌아갑니다. PKCS#9의
     `extensionRequest`(`CCertRequest::OID_EXTENSION_REQUEST`)가 더 디코드되는
     하나뿐인 속성입니다. 그 `Extensions` 값이
     `CCert::parseExtensions()`를 거치므로, 요청된 SubjectAlternativeName이
     인증서 자신의 것과 같은 `CSanExtension`으로 드러납니다.
  3. **키는 `SKeyPair` 전체로 제공되고 그 외에는 없습니다.**
     `CCertRequestBuilder`에는 서명하는 개인키와 별도로 공개키를 지정할
     방법이 없고, `build()`가 공개 절반을 다시 유도해 비교합니다 — 그래서
     서명되지 않은 요청으로 가는 길도, 요청자가 증명할 수 없는 키를 요구하는
     요청으로 가는 길도 없습니다. `build()`는 자기 출력을
     `CCertRequest::importDer()`에 건네므로, 방금 만들어 낸 서명이 쓰인 그
     바이트에 대해 다시 검증됩니다.

  CA 쪽 절반은 **`CCertBuilder::subjectFrom(request)`**이며, 요청의 subject
  이름과 공개키를 인증서 빌더로 복사하고 의도적으로 그 외에는 아무것도 하지
  않습니다. 요청의 요청된 확장을 복사하는 메서드는 없는데, 그것이 바로 CA가
  요청자가 요구했다는 이유로 CA 인증서를, 또는 요청자가 통제하지 않는 도메인에
  대한 인증서를 발급하게 되는 방식이기 때문입니다. 하나를 허용하고 싶은 CA는
  그 특정 확장을 읽고(`request.extension<CSanExtension>()`) 자기 정책에
  대조해 확인한 뒤 스스로 `extensions`에 밀어 넣습니다.

  DER 작업의 거의 전부가 중복되지 않고 `CCert`와 공유됩니다.
  `encodeName()`, `encodeAlgorithmIdentifier()`,
  `encodeSubjectPublicKeyInfo()`/`decodeSubjectPublicKeyInfo()`,
  `makePublicKey()`, `encodeExtensions()`, `parseExtensions()`,
  `resolveSigAlgoForSigning()`/`resolveSigAlgo()`/`parseRsaPssParams()`,
  `signTbs()`, `verifySignedBlob()`이 모두 friend를 통해 도달하는 `CCert`의
  static이고, 그중 여럿은 바로 이것을 위해 `CCertBuilder::build()`의 본문에서
  빼낸 것입니다. `signTbs()`/`verifySignedBlob()`가 가장 중요합니다.
  hash-then-sign과 메시지-서명 중 어느 것인지(`signsMessageDirectly()`를
  통해), 그리고 PKCS#1 v1.5와 PSS 중 어느 것인지를 결정하는 단 하나의
  장소이므로, CSR의 자기 서명이 인증서의 것과 미묘하게 다른 규칙으로
  확인될 수 없습니다.
- **`x509/chain.hpp` / `src/x509/chain.cpp`**는 `SCertEntry`(인증서, 선택적
  개인키, 그리고 PKCS#12 bag이 담는 PKCS#9 `friendlyName`/`localKeyId`),
  `CCertCollection`(인증서 집합을 누가 누구에게 발급했는지로 정렬하는 조회들과
  `buildChain()` — 경로 검증이 *아닙니다*. 범위 설명 참고), 그리고 컨테이너
  포맷이 구현하는 인터페이스 `IChainFormat`을 정의합니다.
  `IChainFormat::builtIn()`이 어떤 포맷이 존재하는지 알아야 하는 유일한
  곳이므로, 포맷을 추가하는 것은 거기서의 변경이고 다른 어디에서도
  아닙니다. `detect()`는 첫 바이트로 PEM과 PFX를 가립니다.
- **`x509/chain/pem.hpp` / `src/x509/chain/pem.cpp`**는
  `CPemChainFormat`을, 그리고 그와 함께 이 라이브러리의 PEM 처리 **전부**를
  정의합니다. 다중 블록 스캔, 캡슐화 경계, 레이블, base64 프레이밍, 그리고
  "이 파일은 개인키도 담고 있다"는 컨테이너의 관심사이므로, 원래 형태가
  DER인 `CCert`가 아니라 여기 있습니다.
  `CCert::importPem()`/`exportPem()`/`detectCertFormat()`은 얇은 위임이고,
  파일 하나에 인증서 하나가 흔한 경우이므로 유지합니다. `load()`는
  추가(append)하며 파일 전체가 파싱되기 전까지 아무것도 반영하지 않으므로,
  중간에 깨지는 컨테이너는 컬렉션을 있던 그대로 둡니다. 키 블록은 위치가
  아니라 `CCert::privateKey()` 자신의 공개키 비교로 인증서와 짝지어지므로,
  파일 안의 뒤바뀐 키나 남의 키가 잘못 짝지어질 수 없습니다. 이 라이브러리가
  구현하지 않는 알고리즘을 쓰는 인증서는 버려지지 않고 적재되고(파싱됩니다.
  그 키만 쓸 수 없습니다), 구조적으로 깨진 블록은 컨테이너 전체를
  `ERET_BADREQ`로 만들며, 비밀번호로 암호화된 키 블록 —
  `ENCRYPTED PRIVATE KEY`, 또는 RFC 1421의 `Proc-Type: 4,ENCRYPTED` — 은
  `ERET_NOTSUP`입니다. PEM에는 그것을 열 비밀번호가 없기 때문입니다.
  **PEM에는 기밀성이 전혀 없습니다**. `needsPassword()`는 false이고,
  `password` 인자는 곧바로 무시되며, 써 내보낸 개인키는 평문으로 디스크에
  갑니다 — 그래서 그것을 쓰는 것이 선택적(opt-in)이고
  (`CPemChainFormat(true)`. `CCert::exportPem(out, true)`가 만드는 것입니다)
  `builtIn()`은 인증서 전용 형태를 반환합니다. PKCS#9 속성은 openssl 자신의
  `Bag Attributes` 모양으로 경계 밖에 타고 가며, RFC 7468 5.2가 명시적으로
  허용하고 다른 어떤 reader든 건너뜁니다.
- **`x509/chain/pfx.hpp` / `src/x509/chain/pfx.cpp`**는 `CPfxFormat`,
  `IChainFormat`으로서의 PKCS#12/PFX(RFC 7292)를 정의합니다. 그것이 쓰는
  구조는 AuthenticatedSafe가 인증서 bag들을 `pkcs7-encryptedData`로, 키
  bag들을 각각 `pkcs8ShroudedKeyBag` 하나를 담은 `pkcs7-data`로 보유하고,
  AuthenticatedSafe 전체에 대한 `MacData` HMAC을 가진 v3 PFX입니다. 기록할
  만한 결정들:

  - **암호화는 PBES2만**입니다(PBKDF2-HMAC-SHA256 + AES-256-CBC. 암호화되는
    부분마다 새 salt와 IV). 레거시 PKCS#12 PBES1 암호
    (RC2-40-CBC, `pbeWithSHAAnd3-KeyTripleDES-CBC`)는 쓰지도 읽지도
    않습니다. 그런 컨테이너는 `ERET_NOTSUP`으로 돌아오는데, 깨진 암호로
    복호하거나 잘못된 것으로 보고하는 대신 "나는 이것을 읽을 수 없다"고
    말하는 것입니다. 이것은 OpenSSL 3이 기본으로 쓰는 것이기도 하므로,
    레거시 암호를 거부하는 데 실무상 비용이 없습니다.
  - **MAC은 HMAC-SHA-256**입니다. RFC 7292의 예제와 2021년쯤까지의 모든
    도구는 SHA-1을 썼습니다. SHA-1 MAC은 읽을 때 여전히 *검증*되는데,
    그것을 거부하는 것은 현존하는 대부분의 컨테이너를 거부하는 것을
    뜻하기 때문입니다.
  - **`MacData`의 키는 PBKDF2가 아니라 RFC 7292 부록 B 자신의 KDF에서
    purpose 바이트 3으로 나오며**, 이는 선택이 아닙니다. RFC 7292 4절이
    그 유도를 명시하므로, 실재하는 어떤 컨테이너를 읽든 그것이 필요합니다.
    그 사용은 정확히 그 키 하나에 국한되며 — 어떤 PBES1 키나 IV도 그것으로
    유도되는 일이 없습니다 — `crypto/`의 무엇이 아니라 `pfx.cpp`의 파일 지역
    보조 함수입니다. `CPbkdf2`와 달리 다른 무엇도 손을 뻗어서는 안 되는
    레거시 PKCS#12 전용 구성이기 때문입니다. PBKDF2가 MAC 키를 유도하게
    해 주는 RFC 9579의 PBMAC1은 구현되어 있지 않습니다.
  - **비밀번호가 같은 파일 안에서 서로 다른 두 방식으로 인코드되며**, 이것이
    다른 어떤 도구도 읽을 수 없는 컨테이너의 가장 유력한 단일 원인입니다.
    PBES2는 PKCS#5이고 비밀번호 바이트를 주어진 대로 받습니다. 부록 B의
    KDF는 PKCS#12 자신의 것이고 그것을 NUL로 끝나는 빅엔디언 UTF-16
    BMPString으로 받습니다. `CPfxFormat`은 그 변환을 하기 위해 `password`
    span을 UTF-8로 읽으며, OpenSSL 3과 일치합니다(그쪽은 UTF-8을
    변환하는데, 더 오래된 `OPENSSL_asc2uni`는 각 바이트를 Latin-1 식으로
    0 확장했습니다). ASCII 비밀번호에 대해서는 둘이 일치하므로, 비-ASCII
    비밀번호로 다른 곳에서 쓰인 컨테이너만이 실제로 그것을 못 박습니다 —
    `fixtures/openssl-utf8-password.p12`가 그것을 위해, 그리고 그것만을 위해
    있습니다.
  - **안쪽의 무엇이든 복호되거나 파싱되기 전에 MAC이 검증됩니다.** 그것이
    통과하기 전까지 AuthenticatedSafe는 공격자가 통제하는 바이트입니다.
    먼저 복호하면 이 클래스가 padding oracle이 될 것이고, 먼저 파싱하면
    아무도 보증하지 않은 입력에 ASN.1 reader를 노출시킬 것입니다.
    `MacData`가 아예 없는 컨테이너도 같은 방식으로 거부되는데, RFC 7292가
    그것을 OPTIONAL로 둔 것은 ASN.1에 대한 진술이고 인증되지 않은 blob을
    믿으라는 허락이 아니기 때문입니다. 비교는 `CSecure::equals()`를 거치고,
    틀린 비밀번호, 실패한 MAC, 없는 MAC이 모두 `ERET_KEY_ERROR`를
    반환합니다 — 의도적으로 구별되지 않습니다. "틀린 비밀번호"를 "손상된
    파일"과 구분하는 구현은 공격자에게 어느 쪽을 계속 시도해야 하는지
    알려 준 것이기 때문입니다.
  - **`MAX_MAC_ITERATIONS`가 하나뿐인 인증되지 않은 계산에 상한을 둡니다.**
    MAC을 확인할 수 있기 전에 MAC 키가 유도되어야 하므로, `MacData`의 반복
    횟수는 이 포맷에서 쓴 쪽이 아니라 파일을 제공한 쪽이 고르는 유일한
    횟수이고 — 20억 번을 주장하는 200바이트 컨테이너는 그것을 여는 쪽에게
    몇 분의 CPU입니다. 상한은 10,000,000이고 RFC 7292의 1024, OpenSSL의
    2048, 또는 이 라이브러리 자신의 600,000보다 한참 위이므로 상호운용성
    비용이 없습니다. 피해를 경계 짓는 것이고 강도에 대한 판단이 아니며,
    읽히는 컨테이너의 횟수에는 의도적으로 *하한*이 없습니다.
  - **`DEFAULT_ITERATIONS`는 600,000**이고, PBKDF2-HMAC-SHA256에 대한
    OWASP의 2023년 수치이며, 여기 release 빌드에서 유도당 대략 0.3초로
    측정되었습니다. 정당화가 필요한 숫자는 이것이 아니라 대안들입니다.
    RFC 7292의 예제는 1024라고 하고 OpenSSL은 아직 2048을 기본으로 씁니다.
    컨테이너는 한 번 쓰이고 수년간 공격받으므로, 비용은 쓰는 쪽에
    속합니다. *읽기*에 대한 하한이 아닙니다 — 컨테이너는 그것이 담고 있는
    횟수가 무엇이든 그대로 읽힙니다.
  - **`save()`는 빈 비밀번호를 거부합니다**(`ERET_BADREQ`).
    `IChainFormat::needsPassword()`에 따른 것입니다. 개인키는 있지만
    `localKeyId`가 없는 항목에는 하나를 부여합니다 — 인증서의 SHA-1
    지문이고, OpenSSL이 쓰는 것입니다 — 그 속성이 들어오는 길에 키 bag을
    자기 인증서 bag과 짝지어 주는 유일한 것이기 때문입니다.
  - 키는 `CCert::exportPkcs8PrivateKey()` / `importPkcs8PrivateKey()`를
    통해 PKCS#8로 오갑니다. 그것들은 두 번 쓰이는 대신 `CCert`의 기존 PEM 쪽
    PKCS#8 처리에서 빼낸 것입니다. 각 알고리즘이 `privateKey` OCTET STRING
    안에 무엇을 넣는지는 `cert.hpp` 자신의 doc 주석을 보시고, PKCS#8 DSA
    키는 `y`를 담고 있지 않으므로 그것을 읽는 데 `g^x mod p` 비용이 든다는
    점에 유의하십시오.
- **`certpp.hpp`**은 소비자를 위한 단일 포함 지점입니다. `include/certpp/`
  아래에 새 공개 헤더를 추가하면 그 `#include`를 여기 추가하십시오.
  선택적 `utils/json.hpp` include는 `CERTPP_WITHOUT_JSON`으로 가드되며,
  JSON을 비활성화하면 CMake가 이 정의를 소비자에게도 전파합니다. 그 밖에
  의도적으로 포함하지 않는 공개 헤더는 둘입니다. `crypto/kem.hpp`(뒤에 구현이
  아직 없습니다 — 그 자체 항목 참고)와, 빈 자리표시인 `io/base64.hpp`
  (`CBase64`는 `utils/base64.hpp`에 있습니다)입니다.
- **`tests/`**는 모든 테스트 케이스를 담고 있고, `CERTPP_BUILD_TESTS`(기본
  `ON`)로 소스 파일당 실행 파일 하나로 빌드되어 CTest에 등록됩니다. 파일
  배치/이름 관례는
  [coding-conventions.ko.md](coding-conventions.ko.md#테스트)를, 빌드하고
  돌리는 방법은 [build.ko.md](build.ko.md#테스트)를 보십시오. 둘 다 이
  파일들이 쓰는 벤더링된 `doctest` 프레임워크를 다룹니다.

### `dnssec`

`x509`의 일부가 아니라 별개 모듈인데, DNSSEC이 X.509의 인코딩을 하나도 공유하지
않기 때문입니다. 인증서가 공개키를 `SubjectPublicKeyInfo`로, ECDSA 서명을 DER
`SEQUENCE { r, s }`로 담는 자리에서, DNSSEC은 벌거벗은 키 재료와 벌거벗은
이어 붙임 `r | s`를 씁니다. 그래서 DNSKEY를 `IAsymmetric::createPublicKey()`에
건넬 수 없고 RRSIG 서명을 `verify()`에 건넬 수 없습니다. 중간에서 무언가가 다시
인코드해야 하며, 그것이 이 모듈의 목적 전부입니다.

- **`dnssec/name.hpp` / `src/dnssec/name.cpp`**는 `CDnsName`을 정의합니다.
  `toWire()`는 항상 ASCII 대문자를 소문자로 접고, API는 의도적으로 호출자에게
  그에 대한 선택권을 주지 않습니다. DS digest가 소유자 이름 다음 DNSKEY
  RDATA에 대해 취해지므로, 접히지 않은 채 digest에 도달하는 이름은 발행된 모든
  DS와 어긋나는 DS를 만들어 내고, 접기를 건너뛰는 옵션은 그것을 우연히 도달
  가능하게만 만들 것입니다. 압축 포인터(RFC 1035 4.1.4)는 해결되는 대신
  거부되는데, DNSSEC이 서명된 이름에서 그것을 금지하고 그것을 담고 있는
  이름은 메시지의 나머지 없이 정규화될 수 없기 때문입니다.
  `fromWirePrefix()`는 RRSIG RDATA를 위해 존재하며, 거기서는 서명자의 이름
  뒤에 아무 구분 없이 서명이 곧바로 따라옵니다.
- **`dnssec/records.hpp` / `src/dnssec/records.cpp`**는 `SDnskey`,
  `SDsRecord`, `SRrsig`를 정의합니다. 키 태그는 저장되는 대신 요청 시
  유도되는데, 그것이 식별자가 아니라 RDATA 전체에 대한 체크섬이기
  때문입니다. 필드로 보유하면 그것이 지칭하는 키와 어긋날 수 있게 됩니다.
  `SRrsig::toSignedPrefix()`는 서명 필드를 생략한 RDATA를 내놓으며, 그것이
  해시에 가장 먼저 먹여지는 것입니다(RFC 4034 3.1.8.1). 그 뒤에 오는 정규
  RRset을 조립하는 일은 호출자에게 맡겨져 있습니다. 이 라이브러리는 DNS
  RRset을 모델링하지 않기 때문입니다. 공개키는 여기서 DNS 인코딩으로
  남아 있고 `CDnssecKeys`만이 변환하는데, 그 둘이 독립적으로 실패할 수 있기
  때문입니다 — RDATA가 완벽히 제대로 생긴 채로도 이 라이브러리가 구현을 갖지
  않은 알고리즘의 키를 담고 있을 수 있고, 키 태그와 DS digest는 어느 쪽이든
  원시 RDATA에 대해 계산됩니다.
- **`dnssec/keys.hpp` / `src/dnssec/keys.cpp`**는 `CDnssecKeys`를 정의하고,
  그것이 재인코딩 계층입니다. RSA(RFC 3110)는 지수 길이, 지수, 그 다음
  모듈러스를 쓰는데, 이 라이브러리는 DER
  `SEQUENCE { INTEGER modulus, INTEGER exponent }`를 원합니다 — 두 피연산자가
  순서마저 반대로 나타난다는 점에 유의하십시오. ECDSA(RFC 6605)는 `x | y`를
  쓰는데, 그것은 `0x04` 접두사를 뺀 SEC1 비압축 점입니다. EdDSA(RFC 8080)는
  이미 올바른 형태이고, default가 아니라 명시적 case로 처리되므로 아무도
  구현하지 않은 알고리즘이 조용히 원시로 취급되는 대신 거부됩니다. 서명도
  같은 길을 가며, ECDSA 방향이 조심해야 하는 쪽입니다. DER `INTEGER`는 선행
  0 옥텟을 담지 않으므로, `r`과 `s`를 각각 곡선의 체 크기로 왼쪽을 채우지
  않고 다시 써 내보내면 `r`이 짧았던 만큼 `s`가 밀리고, RFC 6605 2는 고정
  폭을 요구합니다.

`fromPublicKey()`는 DNSSEC 알고리즘 번호를 추론하는 대신 받아야 하는데,
여러 번호가 하나의 키 타입을 공유하기 때문입니다. RSA/SHA-1, RSA/SHA-256,
RSA/SHA-512가 모두 같은 RSA 키를 담고 해시만 다릅니다. `hasherOf()`는
Ed25519와 Ed448에 대해 true를 반환하면서도 `EHASH_UNKNOWN`을 보고하는데,
그것들은 서명 스킴의 일부로 내부적으로 해싱하므로 호출자가 먼저 적용할 외부
해시가 없기 때문입니다.

이 모듈이 하지 *않는* 것은 RRset을 검증하는 일입니다. 레코드와 키를 변환하고,
키 태그와 DS digest를 계산하고, 호출자에게 서명되는 접두사를 건넵니다. 정규
RRset 구성과 검증 호출 자체는 그 밖입니다.

## 빌드 모델

CMake는 하나의 타깃 `certpp`(별칭 `certpp::certpp`)를 빌드하며, shared
라이브러리(기본)이거나 `-DCERTPP_BUILD_SHARED=OFF`를 통한 static
라이브러리입니다. `__COMPILES_LIBCERTPP__` 정의는 `PRIVATE`이고(라이브러리
자신의 번역 단위만 dllexport를 받습니다), `__SHARED_LIBCERTPP__`는
`PUBLIC`이므로 shared 빌드에 링크하는 소비자가 자동으로 dllimport로 표시된
선언을 받습니다. 명령은 [build.ko.md](build.ko.md)를 보십시오.

하드웨어 가속은 그것이 끌어오는 서로 무관한 명령어 집합 계열에 맞춰 독립적인
세 빌드 옵션으로 나뉩니다 — 하나를 끄는 것이 다른 것들에 영향을 주는 일은
없습니다.

- `CERTPP_DISABLE_HWACCEL_SIMD`(기본 `OFF`)는
  `CGf2m::mul()`/`CBigNum::mul()`이, 그 함수들이 그러지 않으면 쓸 수 있는
  하드웨어 명령(PCLMULQDQ, BMI2/ADX)을 지원하는 CPU에서도 항상 자기 이식
  가능 schoolbook 구현을 쓰게 강제합니다 — 각 가속 경로가 무엇을 하고 어떻게
  관문이 걸려 있는지는 이 파일의 모듈별 책임 절에 있는 그 두 클래스 자신의
  doc 주석을 보십시오. 모든 비대칭 알고리즘(`crypto::asyms::*`)이
  `CBigNum`/`CGf2m` 위에 구현되어 있으므로, 이 옵션 하나가
  RSA/DSA/ECDSA/Ed25519/Ed448/X25519/ECDH의 모듈러 거듭제곱과 체 연산을
  간접적으로 덮습니다 — 그중 어느 것도 관문을 걸 자기만의 별도 가속을 갖지
  않습니다.
- `CERTPP_DISABLE_HWACCEL_SHA`(기본 `OFF`)는
  `SHA1::transform()`/`SHA256::transform()`
  (`src/crypto/hashers/sha1.cpp`, `src/crypto/hashers/sha256.cpp`)이 x86 SHA
  확장(각각 SHA1RNDS4/SHA1NEXTE/SHA1MSG1/SHA1MSG2와
  SHA256RNDS2/SHA256MSG1/SHA256MSG2) 대신 항상 자기 이식 가능 압축 루프를
  쓰게 강제합니다. `CBigNum`/`CGf2m`의 경로가 자기 CPUID 비트에 관문을
  거는 것과 같은 방식으로 런타임 CPUID 검사(`hasSha()`. CPUID leaf 7
  sub-leaf 0, EBX 비트 29) 뒤에 있습니다.
  `MD5`/`SHA384`/`SHA512`/`SHA3-256`/`SHA3-512`/`SHAKE128`/`SHAKE256`에는
  가속 경로가 없고 이 옵션의 영향을 받지 않습니다 — MD5나 Keccak을 위한
  주류 x86 하드웨어 확장이 없고, SHA-1/SHA-256에 있는 식으로 널리 배포된
  x86 SHA-512 확장도 없습니다.
- `CERTPP_DISABLE_HWACCEL_AES`(기본 `OFF`)는 `AesCore`의 블록
  함수들(`src/crypto/syms/aes.cpp`)이 AES-NI
  명령(AESENC/AESENCLAST/AESDEC/AESDECLAST/AESIMC) 대신 항상 이식 가능 라운드
  루프를 쓰게 강제하며, 자기 런타임 CPUID 검사(`hasAesNi()`. leaf 1, ECX
  비트 25)에 관문이 걸려 있습니다. `DES`/`TripleDES`에는 가속 경로가 없고
  영향을 받지 않습니다. `ChaCha20`에는 있지만 그것은 AES 확장이 아니라
  SSE2이므로 대신 `CERTPP_DISABLE_HWACCEL_SIMD`에 응답합니다 — 복호 쪽이 쓰는
  Equivalent Inverse Cipher 구성은 위의 `crypto/syms/aes.hpp` 항목을
  보십시오.

세 설정 모두의 가속 경로와 이식 가능 경로는 바이트 단위로 동일한 결과를
만들어 낼 것으로 기대되며, 어느 경로든 변경이 끝났다고 보기 전에 전체 테스트
모음에 대해 검증합니다. 이 옵션들은 — 위의 `CERTPP_RNG_FALLBACK`과
마찬가지로 — 변경 시 `certpp` 자체의 전체 재빌드를 강제하는
`target_compile_definitions` 스위치이므로, 토글할 때마다 라이브러리 전체를
다시 빌드하지 않고 가속 구성과 이식 가능 전용 구성을 동시에 빌드해 두려면
별도 빌드 디렉터리(예: `build_noaccel/`)가 편리한 방법입니다.

## 이것이 자라날 곳

`third-party/`는 이제 첫 의존성을 벤더링합니다. `doctest`(단일 헤더,
`third-party/doctest/` 아래)이고 `tests/`만 씁니다. 그
`third-party/CMakeLists.txt`가 벤더링된 각 의존성을 자기 CMake
타깃으로 노출합니다(오늘은 `doctest`뿐입니다). 루트 `CMakeLists.txt`는
`tests/` 밖의 무엇도 그것을 필요로 하지 않으므로
`CERTPP_BUILD_TESTS=ON`일 때만 `add_subdirectory(third-party)`합니다.
라이브러리 자신이 하는 모든 것은 밑바닥부터 구현되어 있고 의존성이 전혀
필요 없습니다. 해시들
(`MD4`/`MD5`/`SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512`/`SHAKE128`/`SHAKE256`),
대칭 암호들, 비대칭 알고리즘들, 그리고 그 아래의 큰 수와 이진체 연산입니다.
따라서 아직 테스트 외 의존성이 없고 그것의 구체적인 후보도 없습니다. 미래의
어떤 작업이 진짜로 하나를 필요로 하게 되면, 같은 패턴을 따릅니다 — 자기
`third-party/<name>/` 디렉터리 아래에 벤더링하고
`third-party/CMakeLists.txt`에 짝이 되는 타깃을 추가하되,
`CERTPP_BUILD_TESTS` 뒤에 관문을 걸지 않고 `certpp` 자신에서 링크합니다.

이 라이브러리가 만들려고 했던 모든 구체 `IAsymmetric` 구현 — RSA, DSA,
P-192/P-224/P-256/P-384/P-521/secp256k1/14개 Brainpool 곡선/10개
이진-Koblitz 곡선 위의 ECDSA, Ed25519, Ed448, X25519 — 이 이제
`include/certpp/crypto/asyms/`와 `src/crypto/asyms/` 아래에 존재하며, 구체
`IHasher` 구현들이 `hasher.hpp` 자신의 옆이 아니라 `crypto/hashers/` 아래에
있는 방식을 반영합니다. 단수인 `asym.hpp`/`hasher.hpp` 파일이 인터페이스를
정의하고, 복수인 `asyms/`/`hashers/` 디렉터리가 구체 알고리즘당 파일 하나를
담습니다. 새 `asyms/` 구현의 테스트는 오늘 `tests/crypto/hashers/`가 하는
것과 정확히 같이 `tests/crypto/asyms/` 아래의 같은 거울 경로를 따릅니다.
`IAsymmetric::builtIn()`(`src/crypto/asym.cpp`)이 각 `EAsymmetrics` 값을
자기 구체 클래스로 디스패치합니다. 새 알고리즘은 거기에 `case` 하나를
추가하고, 그 enumerator는 **`EASYM_MAX` 바로 앞으로 가며 절대 중간에 삽입되지
않습니다**. 이 enum은 ABI 경계를 넘으므로(이 라이브러리는 shared 객체로
출하되고 설치된 패키지로 소비됩니다), 번호를 다시 매기면 옛 헤더로 컴파일된
호출자가 조용히 다른 알고리즘을 선택하게 되고 그것을 진단할 것이 아무것도
없습니다. 그 다음 그 enum에 대한 모든 전수 switch를 확인하고, 알고리즘이
인증서에 나타난다면 `CCert`의 `KEY_ALGOS`/`SIG_ALGOS` 테이블과
`signsMessageDirectly()`도 확인하십시오. RSA의 키/서명 DER 인코딩, 그리고
미래의 모든 `asyms/` 구현의 그것은 `CEncoder`/`CDecoder`가 다루지 않는 임의
정밀도 `INTEGER`를 위해 `asn1::CDer`(`asn1/der.hpp`)를 거칩니다 — 그 자체의
doc 주석을 보십시오. 미래의 진짜로 라이브러리가 제공할 수 없는
의존성(아직 없습니다. RSA는 `CBigNum`만 필요했고 그것도 밑바닥부터
만들었습니다)은 대신 위의 벤더링하고-타깃을-노출하는 패턴을 따를 것입니다.

`x509/`는 파싱도 생성도 합니다. `CCert`/`CCertBuilder`가 `Certificate`를 읽고
만들며(그리고 서명하며), `CCrlReader`/`CCrlWriter`가 `CertificateList`를,
`COcspRequest`/`COcspResponse`와 그 빌더들이 OCSP 교환을,
`CCertRequest`/`CCertRequestBuilder`가 PKCS#10 `CertificationRequest`를
담당하고, 열 확장 전부가 parse/build 쌍을 가지며, DER뿐 아니라 PEM도
처리됩니다(`ECertFormat`, `importPem()`/`exportPem()`. 둘 다
`CPemChainFormat`에 위임합니다 — 아래 `x509/chain/pem.hpp` 참고). 새 확장
타입은 `x509/exts/`의 정착된 모양을 따르고(자기 `OID`를 가진 구체
`IExtension` 하위 클래스를 `ext.cpp`의 디스패치 테이블에 추가하고, 짝이 되는
`IExtensionBuilder`도 함께), GeneralName 모양이나 값 객체 목록 모양의 필드를
보유해야 한다면 그 모양들을 지역적으로 다시 정의하는 대신
`x509/generalname.hpp`/`access.hpp`/`policy.hpp`를 재사용합니다.

링크 하나 단위의 서명 검증은 자리를 잡았습니다. `CCert::verifyBy(issuer)`,
`CCrlReader::verifyBy(issuer)`, `CCertRequest::verify()`, 그리고 OCSP 자신의
`verifySignature()`가 각각 원래 서명된 바이트에 대해 "이 키가 이것에
서명했는가?"에 답합니다(손으로 하고 싶은 호출자를 위해
`CCert::tbsCertificate()`/`CCrlReader::tbsCertList()`/
`CCertRequest::certificationRequestInfo()`가 그 바이트를 노출합니다). 여전히
없는 것은 X.509의 *관계적* 절반이고, 반쯤 만들어 두는 대신 지금은 의도적으로
범위에서 빼 두었습니다.

- **체인 구축과 경로 검증** — 이름 연결, 유효 기간,
  `BasicConstraints`/`KeyUsage`/`NameConstraints` 강제, 그리고 RFC 5280의
  "인식되지 않는 critical 확장을 거부하라" 규칙입니다. 이 라이브러리는
  검증자가 필요한 모든 것을 파싱하고 보존하며 그중 아무것도 강제하지
  않습니다. 이 문서 맨 앞의 범위 설명을 보십시오. 같은 공백이 PKCS#10의 CA
  쪽에도 나타납니다. `CCertBuilder::subjectFrom()`은 검증된 요청의 subject와
  키를 건네주고, 그 subject 이름과 그 요청된 확장들이 인증*되어야 하는지*를
  결정하는 것은 이 라이브러리가 모델링하지 않는 정책입니다.
