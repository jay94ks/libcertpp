# 비대칭키 인터페이스와 현대 곡선

[English](asymmetric.md)

## 비대칭키 인터페이스

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

- **`crypto/asym.hpp`**은 `IAsymmetric`, `IAsymmetricContext`,
  `IAsymmetricTransformer`를 정의합니다. `IAsymmetric`은 키 재료를 보유하지
  않습니다. `keySizes()`는 알고리즘이 무엇을 받아들이는지 기술하고,
  `generateKeyPair(rng, keySize, out)`은 키를 만들며,
  `createPublicKey(out, bytes)`/`createPrivateKey(out, bytes)`는 키를
  역직렬화하고, `createContext(out, rng)`는 키가 없는 `IAsymmetricContext`를
  반환합니다. 이 `ERetCode`와 out 파라미터 형태가 주 API입니다. 실패 시 출력을
  비우고 크기, 인코딩, 파라미터, 할당, RNG 실패를 구분합니다. 예전 포인터 반환
  키/컨텍스트 팩토리는 호환 래퍼로 남으며 `ERET_OK`가 아니면 null을 반환합니다.
  키의 `serialize(COctet& out)`은 이미 같은 오류 보고 형태를 사용합니다.

  컨텍스트 생성은 컨텍스트가 소유할 `shared_ptr<IRng>` 또는 먼저 복제하는
  `const IRng&`를 받습니다. 소유한 생성기는 컨텍스트 수명 동안 고정되고 확률적
  서명과 RSA 암호화 padding에 사용됩니다. RNG가 없는 오버로드는 지역 `CRng`를
  만들어 이 경로에 위임합니다. 키 생성도 `const IRng&` 경로가 주 경로이고,
  호환 오버로드는 지역 `CRng`를 만듭니다.

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
  그리고 개인 스칼라에서 공개값 재계산입니다. 스칼라 clamp는 값을 8의 배수로
  만들므로 표준 기준점과의 곱은 이미 소수 위수 부분군에 들어갑니다. 유도값이 0이
  아니면 두 번째 `8*u` ladder가 추가로 거부할 경우는 없습니다. 상대 공개키에는
  곡선 방정식 검사가 의도적으로 없는데, X25519가 설계상 곡선 또는 그 2차 twist
  어느 쪽의 u 좌표든 받아들이기 때문입니다. 낮은 위수 상대가 만드는 전부 0인
  결과는 `deriveSharedSecret()`가 거부합니다. `Ed25519`/`Ed448`은
  `CEcdsa`/`CEcdsa2`가 갖는 스칼라 범위 검사를
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

## EdDSA, X25519 및 GOST

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

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

  스칼라 곱은 내부적으로 확장 투영 좌표(`EdPointProj`:
  Hisil/Wong/Carter/Dawson의 `X/Z, Y/Z, T=XY/Z`, "Twisted Edwards Curves
  Revisited")에서 작동하고 인코딩이나 키 경계에서만 아핀으로 변환합니다. cached 및
  affine-precomputed 점은 혼합 덧셈 비용을 줄이고, 공개 이중 스칼라 곱은 completed
  `P1P1`과 `P2` 형태도 유지해 배가마다 필드 곱셈 하나를 피합니다.
  `Fe25519::addLoose()`와 `subLoose()`는 결과를 곱셈이나 제곱이 즉시 소비할 때만 carry
  pass를 생략합니다. 전용 `square()` kernel은 `tools/fe_square_gen.cpp`가 생성하고
  `mul()`에 대조해 기계적으로 검사합니다.

  비밀 고정 기저 곱 `scalarMulBase()`(`B*r`과 `B*s`에 사용)는 스칼라를 부호 있는
  radix-16 숫자 64개로 재부호화합니다. 프로세스 전체 표의 32개 행에는
  `(1..8) * 256^i * B`가 들어 있습니다. 각 선택은 산술 mask로 8개 항목을 모두
  스캔하고, 0인 숫자도 덧셈을 수행합니다. 홀수 위치를 합하고 네 번 배가한 뒤
  짝수 위치를 합하므로, 한 연산의 점 배가가 256회에서 4회로 줄면서 비밀 인덱스
  조회도 생기지 않습니다. 임의 점 곱은 비밀 스칼라를 위해 분기 없는 256비트
  ladder를 유지합니다. 검증은 공개 sliding-window 숫자로 `k = SHA-512(R || A || M)
  mod L`일 때 `S*B - k*A`를 하나의 공유 배가 사슬에서 계산합니다. 각 `EdPublicKey`는
  `A`의 홀수 배수 8개를 준비해 보유하므로 반복 검증마다 가변 기저 표를 다시 만들지
  않습니다. 가져온 공개키는 전체 `L*A` 부분군 검사를 계속 통과해야 합니다. 서명의
  `R` 디코딩은 정규성, 곡선 위 점, 항등원 검사를 유지하지만 별도 `L*R`은 생략합니다.
  `A`가 이미 부분군에 있으므로 정확한 uncofactored 방정식은 같은 부분군의 `R`만
  받아들일 수 있으며, 2차수 `R` 음성 테스트가 그 추론을 검사합니다. 64비트 GCC/Clang
  빌드의 기본 radix-51 필드 배치는 unsigned limb 다섯 개와 네이티브 64-by-64-to-128
  product를 사용합니다. 이 product가 없는 대상은 signed 10-limb radix-2^25.5 fallback을
  유지합니다. 두 배치 모두 같은 고정 기저 signed-radix-16 경로를 사용합니다.
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

  필드 연산은 `src/crypto/asyms/fe448.hpp/.cpp`에 있습니다. 네이티브
  64×64→128 곱셈 대상은 radix-2^56 limb 8개를 사용하고, portable fallback은
  곱이 `uint64_t` 안에 들도록 radix-2^28 limb 16개를 사용합니다. 고정 지수 체인은
  일반 큰 수 나눗셈 없이 역원과 점 복구를 수행합니다. Edwards448은
  *untwisted*이므로(`a = 1`. edwards25519의
  `a = -1`에 대해) 여기의 `pointAddProj()`는 `Ed25519`의 `a = -1` 특화
  법칙이 아니라 일반 `a` 파라미터화 덧셈 법칙을 씁니다 — 이 모양에 대한
  널리 알려진 이름 붙은 공식이 `a = -1`에 특화되어 있으므로, 참조에서 옮겨
  적지 않고 아핀 덧셈 법칙에서 직접 유도했습니다(`ed448.cpp`의 이 함수
  자체 주석 참고). 확장 투영 좌표, `a = 1` 전용 배가 공식, 아핀/투영 혼합
  덧셈으로 스칼라 loop에서 역원을 없앴습니다.

  개인키는 확장된 RFC 8032 스칼라와 prefix를 캐시합니다. 프로세스 전체의 10열
  comb 표가 기준점 곱을 가속하고, 각 공개키는 반복 검증용 동일 형태의 표를
  보관합니다. 표 생성은 1,024개 항목을 역원 하나로 일괄 정규화합니다. 검증은
  공유 배가 45회와 혼합 덧셈 최대 90회로 `S*B - k*A`를 계산합니다. 가져온
  공개키는 계속 `L*A == 0`을 통과해야 합니다. 서명 `R` 디코딩은 정규 인코딩,
  곡선 위 점, 항등원 검사를 유지하지만 별도 `L*R`은 생략합니다. `A`가 이미
  부분군에 있을 때 정확한 uncofactored 방정식은 같은 부분군의 `R`만 받아들일
  수 있고, 2차수 `R` 음성 테스트가 이 경계를 검사합니다. Comb index는 스칼라에
  따라 달라지고 군 위수 스칼라 산술은 여전히 `CBigNum`을 사용하므로 Ed448
  서명에 constant-time을 주장하지 않습니다.
- **`crypto/asyms/x25519.hpp` / `src/crypto/asyms/x25519.cpp`**는
  `X25519`(Curve25519 위의 Diffie-Hellman 키 합의, RFC 7748)를 정의합니다 —
  `Ed25519`와 같은 체 소수(`2^255 - 19`)이고, 사실 같은 체 *구현*
  (`Fe25519`, `src/crypto/asyms/fe25519.hpp`)이지만, twisted Edwards가 아니라
  Montgomery 형태 곡선 연산입니다. X25519는 완전한 아핀 점 덧셈이 아니라
  u 좌표 Montgomery ladder(RFC 7748 5)만 필요하기 때문입니다.
  `sign()`/`verify()`는 `IAsymmetricContext`의 `ERET_NOTSUP` 기본값으로
  남아 있습니다(서명 연산이 존재하지 않습니다). `deriveSharedSecret()`만
  override됩니다. 개인키는 호출자의 원시 32바이트와 clamp된 작업용 사본을
  함께 보관합니다. 그래서 `serialize()`/`createPrivateKey()`는 원래 바이트를
  정확히 왕복하면서 반복 스칼라 곱은 clamp와 보안 사본 작업을 되풀이하지
  않습니다. context도 바인딩 개인키와 현재 상대 키의 concrete type 검사를
  성공한 뒤 그 결과를 cache합니다. `deriveSharedSecret()`은 계산된 비밀이 전부
  0이면 예측 가능한 출력을 반환하는 대신 거부합니다(RFC 7748 6.1 — 낮은
  위수의 상대 점, 예컨대 `u = 0`). 키는 DER 없이 RFC 7748의 원시 32바이트
  u 좌표/스칼라 인코딩으로 직렬화됩니다. RFC 7748 5.2의 Diffie-Hellman과
  반복 스칼라 곱 기지 응답 벡터에 대해 검증했으며, 이 모듈의 정착된 상수
  검증 규율과 일관되게 한 번 가져온 것을 그대로 옮긴 것이 아니라 하드코딩
  전에 같은 ladder의 독립 Python 구현으로 재유도했습니다.
