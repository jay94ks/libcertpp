# 개발 모델

[English](development.md)

## 테스트 및 프로젝트 파일

← [저장소 구성](../CONCEPTS.ko.md#세부-개념-문서)

```
tests/
  time.cpp                  # SDateTime / STimeSpan 테스트 케이스
  string.cpp                 # TString<T> 테스트 케이스
  name.cpp                    # CName 테스트 케이스
  oid.cpp                     # SRawOid/COid 파싱, 포맷, 순서, 캐시 인덱스, 동시성, 모든 알려진 OID 범위
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
    rng.cpp                       # IRng 주입/복제와 CRng 테스트 케이스
    hmac.cpp                      # CHmac 테스트 케이스 (RFC 4231의 SHA-224/256/384/512 벡터와 RFC 2202의 SHA-1 것들, 과도하게 긴 키의 해싱 규칙, 그리고 verify()가 정확한 tag만 받아들인다는 것)
    blake2smac.cpp                # CBlake2sMac을 키 있는 BLAKE2s 참조 KAT 256개 전체에 대조, chunk 처리, 키 수명 주기, HMAC-BLAKE2s와의 구분
    hkdf.cpp                       # CHkdf 테스트 케이스 (RFC 5869 부록 A의 SHA-256 A.1–A.3과 SHA-1 A.4–A.6. 더해서 salt가 없는 것이 HashLen만큼의 0 salt와 같다는 것)
    pbkdf2.cpp                      # CPbkdf2 테스트 케이스 (RFC 6070의 HMAC-SHA1 벡터, RFC 7914 11절의 HMAC-SHA256 것들, iterations가 0인 경우와 출력 길이 거부. 16777216 반복 케이스를 빼 둔 이유도 적혀 있습니다)
    siphash.cpp                   # CSipHash 테스트 케이스 (SipHash 참조 구현의 vectors_sip64 항목 64개 전부, chunk 처리, 키 재사용/재시작 의미, 오류 경로)
    syms/
      aes.cpp                      # AES 테스트 케이스 (NIST SP 800-38A CBC 기지 응답 벡터. F.2의 4블록 케이스를 padding 없이 포함. 왕복, 조작, 오류 경로)
      aria.cpp                     # ARIA 테스트 케이스 (RFC 5794 부록 A의 세 키 크기 벡터, CBC/padding, 잘못된 키와 IV)
      des.cpp                       # DES 테스트 케이스 (고전적인 FIPS-46 벡터)
      des3.cpp                       # TripleDES 테스트 케이스 (DES 합성 교차 확인)
      chacha20.cpp                    # ChaCha20 테스트 케이스 (RFC 8439 부록 A.1, chunk 키스트림, SSE2/AVX2/AVX-512 경계의 독립 scalar 차분)
    aeads/
      chacha20poly1305.cpp          # CPoly1305 + CChaCha20Poly1305 테스트 케이스 (RFC 8439 2.5.2/2.6.2/2.8.2)
      xchacha20poly1305.cpp          # CXChaCha20Poly1305 테스트 케이스 (draft-irtf-cfrg-xchacha A.3의 벡터, HChaCha20 부분키를 A.1에 대조, 그리고 마지막 8바이트가 반복되는 192비트 nonce가 키스트림을 반복하지 않는다는 것)
      aesgcm.cpp                     # CAesGcm 테스트 케이스 (GCM 명세 부록 B의 96비트 IV 케이스 1–4/7–10/13–16, aliasing, tag 절단, 조작, 오류 경로)
      ghash.cpp                       # Ghash 테스트 케이스 (GCM 비트 순서에서의 체 항등식, x 곱셈을 shift에 대조, chunk 처리, 이식 가능 경로 대 PCLMULQDQ 차분)
    eccurve.cpp                   # CEcCurve/SEcPoint 테스트 케이스 (군 법칙, 동시 곱, SEC1 인코딩, 군 위수 검사)
    ec2curve.cpp                  # CEc2Curve/SEc2Point 테스트 케이스. 알려진 10개 곡선 전부에 대해 (곡선 위에 있음, 부정, 군 법칙, 동시 곱, SEC1 인코딩, 군 위수 검사)
    policy.cpp                    # CAlgorithmPolicy 기본값과 레거시 알고리즘 opt-in 동작
    safe_api.cpp                  # 공개 crypto API의 소유형 출력 overload와 실패 상태 검사
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
    validator.cpp                 # CPathValidator 신뢰, 시간, 제약, 용도, 이름 제약, 깊이, 서명, 미지원 기능 결과
    gost.cpp                      # RFC 9215 GOST 인증서/CSR SubjectPublicKeyInfo와 서명 인코딩
    kemspki.cpp                   # RFC 9935 ML-KEM SubjectPublicKeyInfo 기지 응답과 잘못된 입력 거부
    chain/                        # 컨테이너 포맷당 .cpp 하나
      pem.cpp                       # CPemChainFormat 테스트 케이스: 왕복, 교체가 아니라 추가, 잘못된/잘린/암호화된 컨테이너, CRLF와 블록 사이 텍스트, 더해서 certs/openssl-*.pem — 이 라이브러리가 아니라 OpenSSL 3.4.0이 쓴 픽스처입니다
      pfx.cpp                       # CPfxFormat 테스트 케이스: OpenSSL 3가 쓴 PFX 컨테이너 다섯 개를 읽고, 자기 것을 왕복하고, MAC이 덮는 범위의 조작 스윕, 그리고 CCert PKCS#8 wrap/unwrap 쌍
      certs/                        # PEM 픽스처들. fixtures/에는 PFX 것들이 있습니다 — 둘 다 OpenSSL 3가 한 번 쓴 것을 체크인했으므로 테스트 모음에 openssl이 PATH에 없어도 됩니다. 이 라이브러리가 쓰지 않은 파일을 읽는 것이, 포맷의 구현과 자기 일관적인 것을 가르는 유일한 기준입니다
    realcerts.cpp                # certs/implemented/ 아래 디스크에 있는 실제 상용 인증서들: github.com, amazon.com, sourceforge.net, QuoVadis/DigiCert RSASSA-PSS 중간 인증서, 그리고 자기 서명이 종단 간으로 검증되는 IdenTrust ML-DSA-87 파일럿 루트
  dnssec/
    name.cpp                      # CDnsName 테스트 케이스 (와이어 형식, 대소문자 폴딩, 레이블 세기, 잘못된 이름, 압축 포인터 거부)
    records.cpp                    # RFC 5702, 6605, 8080, 9558의 발행 산출물에 대한 DNSKEY/DS/RRSIG 테스트
    keys.cpp                        # RFC 9558 GOST 알고리즘 23, 고정 폭 서명 재padding, 종단 간 변환을 포함한 CDnssecKeys 테스트
third-party/
  CMakeLists.txt           # 벤더링된 의존성을 CMake 타깃으로 노출합니다. CERTPP_BUILD_TESTS=ON일 때만 add_subdirectory됩니다
  doctest/
    doctest.h                 # 벤더링된 단일 헤더 테스트 프레임워크 (MIT)
CMakeLists.txt              # certpp(그리고 CERTPP_BUILD_TESTS=ON이면 테스트)를 shared(기본) 또는 static으로 빌드합니다
```
```

## 빌드 모델

← [개념](../CONCEPTS.ko.md)

CMake는 하나의 타깃 `certpp`(별칭 `certpp::certpp`)를 빌드하며, shared
라이브러리(기본)이거나 `-DCERTPP_BUILD_SHARED=OFF`를 통한 static
라이브러리입니다. `__COMPILES_LIBCERTPP__` 정의는 `PRIVATE`이고(라이브러리
자신의 번역 단위만 dllexport를 받습니다), `__SHARED_LIBCERTPP__`는
`PUBLIC`이므로 shared 빌드에 링크하는 소비자가 자동으로 dllimport로 표시된
선언을 받습니다. 명령은 [BUILDING.ko.md](../BUILDING.ko.md)를 보십시오.

하드웨어 가속은 그것이 끌어오는 서로 무관한 명령어 집합 계열에 맞춰 독립적인
네 빌드 옵션으로 나뉩니다 — 하나를 끄는 것이 다른 것들에 영향을 주는 일은
없습니다.

- `CERTPP_DISABLE_HWACCEL_SIMD`(기본 `OFF`)는 AES-NI와 SHA-NI에 속하지 않는
  확장 명령 경로를 끕니다. `CBigNum`의 ADX/BMI2, `CGf2m`·`Ghash`의
  PCLMULQDQ, `Ghash` 반사의 GFNI, AVX-512F P-256 private comb 선택기,
  SSE2/AVX2/AVX-512F ChaCha20 키스트림, Keccak의 BMI1 ANDN,
  SHA-384/SHA-512의 BMI2 RORX, Poly1305의 AVX512-IFMA가 해당합니다. 영향을
  받는 각 구성 요소는 이식 가능 경로를 유지합니다. 선택적 명령은 런타임 CPUID
  검사로 고르고, SSE2는 x86-64의 baseline입니다.
- `CERTPP_DISABLE_HWACCEL_AVX512`(기본 `OFF`)는 P-256 private comb 선택을 포함한
  AVX-512 단계를 끄며 더 좁거나 generic인 SIMD 경로는 계속 사용할 수 있습니다.
- `CERTPP_DISABLE_HWACCEL_SHA`(기본 `OFF`)는
  `SHA1::transform()`/`SHA256::transform()`
  (`src/crypto/hashers/sha1.cpp`, `src/crypto/hashers/sha256.cpp`)이 x86 SHA
  확장(각각 SHA1RNDS4/SHA1NEXTE/SHA1MSG1/SHA1MSG2와
  SHA256RNDS2/SHA256MSG1/SHA256MSG2) 대신 항상 자기 이식 가능 압축 루프를
  쓰게 강제합니다. 다른 선택 경로와 같은 방식으로 런타임 CPUID 검사
  (`hasSha()`. CPUID leaf 7
  sub-leaf 0, EBX 비트 29) 뒤에 있습니다.
  `MD5`는 영향을 받지 않습니다. SHA-384/SHA-512와 SHA-3/SHAKE에는 BMI 기반
  가속 경로가 있지만 이 SHA 확장 스위치가 아니라
  `CERTPP_DISABLE_HWACCEL_SIMD`가 제어합니다.
- `CERTPP_DISABLE_HWACCEL_AES`(기본 `OFF`)는 `AesCore`
  (`src/crypto/syms/aescore.cpp`)가 단일 블록/CBC의 AES-NI와 병렬 GCM 카운터의
  VAES 대신 이식 가능 라운드를 쓰게 강제합니다. AES-NI는 자기 런타임 CPUID
  검사(`hasAesNi()`. leaf 1, ECX 비트 25)를 사용합니다. VAES 검사는 CPUID에서
  AVX2/AVX-512F와 VAES를 직접 해석하고 XCR0에서 OS가 활성화한 해당 XMM/YMM/ZMM
  상태를 확인하므로 compiler별 CPU 기능 문자열에 의존하지 않습니다.
  `DES`/`TripleDES`에는 가속 경로가 없고
  영향을 받지 않습니다. `ChaCha20`은 AES 확장 대신 SSE2/AVX2/AVX-512F를 사용하며
  `CERTPP_DISABLE_HWACCEL_SIMD`에 응답합니다 — 복호 쪽이 쓰는
  Equivalent Inverse Cipher 구성은 위의 `crypto/syms/aes.hpp` 항목을
  보십시오.

네 설정 모두의 가속 경로와 이식 가능 경로는 바이트 단위로 동일한 결과를
만들어 낼 것으로 기대되며, 어느 경로든 변경이 끝났다고 보기 전에 전체 테스트
모음에 대해 검증합니다. 이 옵션들은 — 위의 `CERTPP_RNG_FALLBACK`과
마찬가지로 — 변경 시 `certpp` 자체의 전체 재빌드를 강제하는
`target_compile_definitions` 스위치이므로, 토글할 때마다 라이브러리 전체를
다시 빌드하지 않고 가속 구성과 이식 가능 전용 구성을 동시에 빌드해 두려면
별도 빌드 디렉터리(예: `build_noaccel/`)가 편리한 방법입니다.
