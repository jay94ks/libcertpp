# 포스트퀀텀 암호 내부 구조

[English](post-quantum.md)

## 키 타입 및 ML-KEM

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

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
  [`docs/PQC.ko.md`](../PQC.ko.md)의 ML-KEM 작업 첫 단계로서 어떤
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
  [남은 PQC 작업](../pqc/implementation.ko.md)에 기록되어 있습니다.

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
  넣습니다. [`docs/BUILDING.ko.md`](../BUILDING.ko.md)를 보십시오.

## ML-DSA 내부 구현

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

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
  제시하지 않습니다. [엔지니어링, 검증 및 위험](../pqc/engineering.ko.md)을 보십시오.
  작업 집합은 스택이 아니라 힙에 할당됩니다(`TArray<Poly>`). ML-DSA-87의
  것이 크기 때문입니다 — A-hat만으로도 8x7 다항식, 56 KiB이고, 그 옆에
  십여 개의 벡터가 더 있습니다.

  pure 변형만 구현되어 있습니다. HashML-DSA는 자기만의 별도
  `id-hash-ml-dsa-*` OID를 가지고, 이 라이브러리가 읽으려는 어떤 인증서에도
  나타나지 않으며, 현재 호출자가 없는데도 해시 OID 테이블을 끌어들일 것입니다.
- **`crypto/asyms/mldsa.hpp` / `src/crypto/asyms/mldsa.cpp`**는 `CMlDsa`를
  정의합니다. `IAsymmetric`으로서의 ML-DSA이고 파라미터 집합당 인스턴스
  하나입니다 — `CEcdsa`가 자기 곡선들에 걸쳐 갖는 것과 같은 배치이며,
  `IAsymmetric::builtIn()`에 `EASYM_MLDSA44`, `EASYM_MLDSA65`,
  `EASYM_MLDSA87` 중 하나를 넘겨 도달합니다. 서명/검증만 합니다.
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
