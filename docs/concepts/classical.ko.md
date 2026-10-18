# 고전 비대칭키 암호

[English](classical.md)

## 고전 비대칭키 암호

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

- **`crypto/asyms/rsa.hpp` / `src/crypto/asyms/rsa.cpp`**는 `RSA`
  (RFC 8017)를 정의합니다. 첫 구체 `IAsymmetric`입니다. 키는 `CDer`를 통해
  PKCS#1 DER(`RSAPublicKey`/`RSAPrivateKey`. 두 소수 형태만)로 직렬화됩니다.
  `sign()`/`verify()`는 EMSA-PKCS1-v1_5를 구현합니다. `IAsymmetricContext`는
  자기가 받은 digest를 어떤 해시가 만들었는지 듣지 못하므로, DigestInfo의
  해시 `AlgorithmIdentifier`는 digest의 바이트 길이에서
  추론합니다(16/20/28/32/48/64로 MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512를
  덮습니다). 같은 폭의 다른 해시는 digest만으로 구분할 수 없습니다. MD4가
  그 매핑의 레거시 16바이트 충돌인데, 그것도 16바이트
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

  RSA 키 객체는 공개 modulus `n`과 개인 CRT modulus `p`, `q`의 Montgomery context를
  캐시합니다. 따라서 반복 공개 연산, 개인 CRT 지수승, 개인키 연산의 fault 검사는
  호출마다 긴 나눗셈 두 번으로 `R`, `R²`, packed modulus를 다시 만들지 않고
  재사용합니다. 64비트 이하 지수는 전체 제곱-곱 체인 동안
  고정 폭 64비트 Montgomery 저장소에 머뭅니다. 더 긴 지수는 4비트 sliding window를
  사용하고 512비트를 넘으면 5비트로 넓히며, 누산기와 홀수 거듭제곱을 전체 체인 동안
  packed 형식에 유지합니다. 캐시된 런타임 기능 검사 뒤 BMI2/ADX와 정확한 Tiger Lake
  tuning target을 선택합니다. generic BMI2/ADX gate는 CPUID를 직접 해석하므로 compiler가
  특정 `__builtin_cpu_supports` 기능 문자열을 허용하는지에 의존하지 않습니다. 흔한
  1024비트·2048비트 modulus는 지수승마다 별도 16-limb·
  32-limb kernel을 한 번 선택하므로, compiler가 매 inner 반복에 limb-count 분기를 추가하지
  않고 통합 곱·reduction loop를 전개할 수 있습니다. 다른 크기는 runtime-count kernel을
  유지합니다. 제곱 단계는 같은 packed 피연산자를 동일한 CIOS body의 양쪽 입력으로 넘기는
  고정 count wrapper를 사용합니다. 곱·reduction schedule은 유지하면서 compiler가 독립적인
  오른쪽 피연산자 주소 chain을 제거할 수 있게 합니다. 이 경로들은 `CBigNum`의 문서화된
  variable-time 경계를 바꾸지 않습니다.

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

  `sign()`의 `g^k mod p` 항은 개인키와 함께 캐시한 Montgomery context와
  `CMontgomery::modExp()`의 4비트 sliding window를 사용합니다. 검증은
  `CMontgomery::modExpProduct()`를 호출해 하나의 공유 제곱 체인과 16항 2비트 곱 표로
  `g^u1*y^u2 mod p`를 계산합니다. 네이티브 Clang x86-64 빌드는 그 표와 모든
  중간값을 마지막 변환까지 packed 형식에 유지합니다. 2048비트 modulus는 RSA 공개
  modulus와 같은 고정 32-limb kernel을 사용합니다. 홀수 부분군 위수에 대한
  `CBigNum::modInverse()`는 binary extended GCD를 사용해 서명과 검증의 몫 크기
  곱셈·나눗셈을 피합니다. 검증 지수는 공개값이므로 그 경로의 지수 비트 분기는
  허용됩니다. 서명 경로도 `CBigNum`이 가변 길이 저장소를 사용하며 constant-time
  primitive가 아니므로 variable-time입니다. 이 제한은 공개 헤더와 호출자 주의사항에
  문서화되어 있습니다.
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
  좌표(`X/Z^2, Y/Z^3`, 무한점은 `Z == 0`)에서 작동합니다. 네이티브
  64×64→128 곱셈이 있는 x86-64 Clang/GCC 빌드에서는 좌표가 스택의 고정 폭
  64비트 Montgomery limb에 머뭅니다. 체는 지원하는 limb 폭마다 고정 count 곱셈
  kernel을 선택해 compiler가 곱과 reduction loop를 펼칠 수 있게 합니다. 4비트
  private-scalar window는 16개 후보를
  모두 스캔해 mask로 선택하며, 정확한 표준 P-256 파라미터는 프로세스 전역 33행 signed
  radix-256 comb 표도 사용합니다. batch-normalized affine 좌표는 좌표마다 field limb 4개만
  보관하고 모든 항을 스캔합니다. 지원하는 x86-64 Clang 빌드에서는 직접 CPUID와 XCR0를
  검사한 뒤 각 64바이트 affine 항목을 ZMM register 하나로 읽고 mask로 요청한 점을 남기는
  AVX-512F 선택기를 사용합니다. 다른 대상은 한쪽 방향 scalar mask 선택기를 사용합니다.
  두 구현 모두 private digit에 대해 같은 전체 행 스캔을 수행합니다. 추가 행 하나가 마지막
  carry를 소비하고 mask 기반 Y 부호 반전이 비밀 의존 조회나 분기 없이 음수 digit을
  처리합니다. 이 표는 호출마다 점을
  배가하지 않고 mixed 덧셈을 허용합니다. P-256은 Montgomery reduction에서
  희소 modulus와 `a == -3` 배가 공식을 사용합니다. 재사용 P-256 검증 context는 두 검증
  scalar가 모두 공개값이므로 별도의 위치별 4비트 comb를 사용합니다. 60 KiB 기저 표는
  프로세스 전체에서 공유하고 바인딩 공개키마다 60 KiB 표 하나를 보관하며, 직접 조회로
  점 배가 256회를 최대 128회 mixed 덧셈으로 바꿉니다. P-256 ECDH context는 현재 peer에
  대해 같은 60 KiB 위치별 표 형식을 지연 생성해 보관합니다. 공개 검증과 달리 private ECDH는
  행마다 항목 15개를 모두 스캔해 mask로 선택하며, 준비된 경로는 mixed 덧셈 64회만 수행하고
  점 배가는 하지 않습니다. peer가 바뀌면 캐시 표도 교체합니다. 다른 소수 곡선은 폭 8 wNAF
  검증 표와 일반 private scalar 경로를 유지합니다. 다른 빌드는 mask 기반 R0/R1
  `CBigNum` Montgomery ladder를 유지합니다. 두 경로 모두 스칼라 비트마다 하나가
  아니라 마지막 역원 하나만 계산합니다. 모듈러스별 컨텍스트는 `CEcCurve`
  인스턴스에 캐시되지 않고 `scalarMul()`/`scalarMulBase()`의 앞머리에서
  만들어져 아래로 전달됩니다. `p`/`a`/`b`가 공개 가변 필드이므로 캐시된
  컨텍스트는 호출자가 그중 하나에 쓸 때마다 무효화가 필요할 것이고, 그
  두 번의 나눗셈은 뒤따르는 스칼라 곱 옆에서는 측정되지 않습니다.
  고정 폭 경로는 스칼라 곱 경계에서 변환하고 fallback은
  `toJacobian()`/`toAffineFromJac()`을 사용하므로 Montgomery 형태의 값이 어느
  경로에서도 밖으로 나가지 않습니다. 아핀
  `add()`/`doublePoint()`/`isOnCurve()`는 의도적으로 `CBigNum`의 일반 경로에
  남는데, 군 연산 하나는 그 한 번의 모듈러 역원이 지배하고 컨텍스트를 분산시킬
  대상이 없기 때문입니다. `scalarMulBase()`의 comb와 호출별 window 경로는 모두 모든
  후보를 스캔하여 비밀 의존 고정 기저 테이블 조회를 피합니다.
  `doublePointJac()`/`addJac()`(Bernstein/Lange의
  `dbl-2007-bl`/`add-2007-bl`. 일반 `a`)과 `ec2curve.cpp`의 Lopez-Dahab
  대응물들은, 어떤 피연산자의 현재 값이 이후에 다시 읽히지 않을 때마다 그것을
  새 변수로 먼저 복사하지 않고 제자리에서 변경하도록 작성되어 있습니다(그런
  지점마다 어느 읽기가 그 피연산자의 마지막인지 이름을 댄 주석이 있습니다) —
  `CBigNum`/`CGf2m` 자신의 메서드들이 따르는 것과 같은
  복사보다-제자리 규율(위의 그들 doc 주석 참고)을 이 자유 함수들의 지역
  변수에까지 이어 간 것입니다. 어느 구현도 완전한 부채널 저항을 주장하지 않습니다.
  예외 점 처리는 데이터 의존 제어 흐름을 가지며 fallback은 가변 폭 `CBigNum` 값을
  할당하고 잘라내기도 합니다. 검증 context는 키를 바인딩할 때 generator와 바인딩한
  공개키의 폭 8 affine 홀수 배수 표를 한 번 batch-normalize하고 각 좌표를 `CBigNum`으로
  왕복하는 대신 Montgomery limb를 그대로 보관합니다. 반복 검증은 mixed 덧셈,
  Jacobian 누산기 하나, 마지막 역원 하나로 이 표를 재사용합니다. 직접
  `linearCombination(k1, p1, k2, p2)`을 호출하면 폭 5 signed-window NAF를 사용합니다.
  두 경로 모두 공개값에 따라 분기하고 표를 인덱싱하며 공개 검증값에만
  쓰도록 명시되어 있습니다. private 스칼라는 계속 `scalarMul()` 또는
  `scalarMulBase()`를 거칩니다.
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
  직렬화되고 공개키는 벌거벗은 SEC1 비압축 점으로 직렬화됩니다. X.509 계층은
  지원하는 명명 곡선 OID를 `SubjectPublicKeyInfo`와 별도로 상호 변환합니다. 서명은 표준
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
  ladder 실행 한 번). 고정 기저 곱과 공개 linear combination은 두 번째 피연산자를
  affine으로 특화해 `addMixedLD()`를 사용하고, 일반 private-scalar 곱은 완전한
  projective 공식을 유지합니다. `CGf2m`은 지원하는 다섯 폭을 고정 count PCLMUL
  곱·제곱 kernel로 분기한 뒤 높은 word를 체 다항식으로 직접 축약합니다. portable
  경로도 shift-and-XOR 곱 뒤 같은 축약기를 사용합니다.
  `linearCombination()`은 Lopez-Dahab 좌표에서 같은 공개 검증
  최적화를 제공하며 공개 스칼라 전용이라는 같은 제한을 갖습니다. `field`는
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
