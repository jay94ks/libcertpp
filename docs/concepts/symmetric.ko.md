# 해시와 대칭키 암호

[English](symmetric.md)

## 해시

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

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
  나머지 계열에는 같은 전용 해시 확장이 없습니다. 대신 MD4는 48단계를 전개하고
  지원되는 경우 AVX-512VL ternary logic과 vector rotate를 사용합니다. MD5는 64단계를
  모두 전개하고 scalar ROL과 BMI1 ANDN을 사용합니다. 같은 의존성 사슬에서 측정한
  BMI2 RORX 변형은 더 느렸습니다. `Sha2_64Core::transform()`은 SHA-384/SHA-512
  회전에 BMI2 RORX를 사용하고, AVX-512VL 대용량 경로는 메시지 스케줄 네 개를 함께
  계산하고 ternary 라운드 logic을 사용합니다. `KeccakCore`는 25개 lane을 vector register에
  유지하고 rho/pi를 제자리 순환으로 적용하며 theta와 chi를 ternary logic으로 접는
  AVX-512VL permutation을 사용합니다. BMI1 ANDN은 더 좁은 폴백으로 남습니다.
  런타임 CPU 검사가 이 선택 경로들을 고르며,
  `CERTPP_DISABLE_HWACCEL_SIMD`로 끌 수 있습니다.
- **`crypto/hashers/blake2s.hpp` / `src/crypto/hashers/blake2s.cpp`**는 출력 길이가
  1바이트부터 32바이트인 RFC 7693 BLAKE2s를 `IHasher`로 구현합니다. private
  `Blake2sCore`가 parameter block 초기화, streaming, finalization, 압축을 맡으며,
  RFC 7693의 native keyed mode를 위한 `CBlake2sMac`도 이 core를 공유합니다.
  x86-64에서는 압축 함수가 작업 상태의 네 행을 SSE2 vector에 유지하고 각 column 및
  diagonal 단계의 독립적인 G 함수 네 개를 함께 계산합니다. SSE2는 x86-64 ABI의
  일부이므로 런타임 dispatch가 필요하지 않으며, 다른 대상과
  `CERTPP_DISABLE_HWACCEL_SIMD` 구성은 scalar 구현을 사용합니다. 비 keyed RFC 벡터와
  참조 keyed KAT가 가속 및 SIMD 비활성 빌드에서 이 공유 core를 검증합니다.
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
  않습니다(`SHAKE256`/Ed448과 달리) — [`docs/PQC.ko.md`](../PQC.ko.md)에
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
  전혀 없었으므로 `docs/PQC.ko.md`의 계획이 놓쳤던 선행 조건입니다),
  어디서든 쓸 수 있는 평범한 `EHashers` 멤버
  (`EHASH_SHA3_256`/`EHASH_SHA3_512`)입니다.

## 대칭키 암호

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

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
  `ESymmetrics`(`ESYM_AES`/`ESYM_ARIA`/`ESYM_DES`/`ESYM_3DES`/
  `ESYM_CHACHA20`) 팩토리이고
  `IAsymmetric::builtIn()`을 반영합니다.

  `generateKey(rng, out, size)`와 `generateIV(rng, key, out)`가 호출자 제공
  난수를 쓰는 경로입니다. RNG가 없는 오버로드는 지역 `CRng`를 만들어
  위임합니다. 원시 키 가져오기와 컨텍스트 생성은 `createKey(out, bytes)`와
  `createContext(out, key)`라는 `ERetCode` 주 API를 사용하며 둘 다 실패 시 포인터를
  비웁니다. 예전 포인터 반환 오버로드는 이들에 위임하고 실패 시 null을
  반환합니다.
- **`crypto/syms/aes.hpp`/`aria.hpp`/`des.hpp`/`des3.hpp`와 대응 소스**는
  `AES`(FIPS-197. 128/192/256비트 키), `ARIA`(RFC 5794. 128/192/256비트 키),
  `DES`(FIPS 46-3. 레거시/상호운용 전용), 그리고
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
  `aeads/aesgcm.cpp` 둘 다 사용), `AriaCore`(private
  `ariacore.hpp`/`.cpp`. `aria.cpp`가 사용), `DesCore`(공유 private
  `descore.hpp`/`.cpp`. `des.cpp`와 `des3.cpp` 둘 다 사용),
  `TripleDesCore`(`des3.cpp`)가 각 알고리즘 자신의 블록 암호 연산을 담고
  있으며, 모듈 밖의 무엇도 그것들을 필요로 하지 않으므로 private으로
  유지됩니다(`SymRawKey`. 길이 외에는 검증하지 않는 자명한 원시 바이트
  `ISymmetricKey`도 `src/crypto/syms/symkey.hpp`를 통해 같은 방식으로
  공유됩니다).

  `AesCore`에는 추가로 하드웨어 가속 경로들이 있습니다(x86-64 전용이고
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
  DES/3DES의 Feistel 네트워크를 위한 주류 x86 하드웨어 확장이 없습니다. portable
  core는 각 S-box와 P permutation을 결합하고, 회전 조회용 워드 두 개로 각 라운드 키를
  준비하며, TripleDES 블록을 세 EDE 단계 전체에서 permuted domain에 유지합니다. ARIA도
  portable 32비트 경로에서 확장 S-box 항목으로 substitution과 pre-diffusion을 결합하고
  남은 diffusion을 word 연산으로 처리합니다. DES, TripleDES, ARIA, AES-CBC 암호화는
  겹침이 안전하고 앞선 부분 블록이 없을 때 완전한 입력
  블록을 bulk loop에 직접 넘기고 나머지만 staging합니다. 앞쪽 겹침은 buffered 경로를
  유지합니다.
  AES-GCM은 독립적인 카운터 여덟 개도 함께 처리하며 AVX2, VAES, OS가 활성화한
  벡터 상태를 검사한 뒤 256비트 VAES를 사용합니다. AES-NI와 portable 경로는
  폴백으로 남습니다. VAES dispatch는 CPUID와 XCR0를 직접 읽으므로 `vaes`를
  `__builtin_cpu_supports` 기능 문자열로 허용하지 않는 Clang release도 가속 경로를
  컴파일할 수 있습니다.
  ChaCha20의 ARX 라운드에도 전용 확장이 없지만 블록들에 걸쳐 벡터화됩니다.
  4블록 묶음은 SSE2, 8블록은 AVX2, 16블록은 런타임 CPU 및 OS 벡터 상태 검사 뒤
  AVX-512F를 사용합니다. `CERTPP_DISABLE_HWACCEL_SIMD`가 전체를 제어하며,
  `CERTPP_DISABLE_HWACCEL_AVX512`로 AVX-512 단계만 따로 끌 수 있습니다 —
  위의 `src/crypto/syms/chacha20core.hpp` 항목을 보십시오.
  이 모듈이 이미 돌리는 같은 SP 800-38A/FIPS-46/RFC 8439 기지 응답 벡터와,
  세 키 크기 및 카운터 carry를 다루는 가속/portable CTR 비교로 검증합니다.
  지원하는 CPU에서는 가속 경로를 자동으로
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
  벡터와, 0–600바이트의 모든 길이 및 1/4/16/64 KiB 경계에서 독립적인 scalar
  구현에 대조하여 모든 벡터 단계와 scalar 나머지를 검증했습니다.
