# MAC, KDF, AEAD 및 난수

[English](protocols.md)

## MAC, KDF, AEAD 및 RNG

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

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
  `CRng`의 선례를 따릅니다. `CHkdf`와 `CPbkdf2`가 공유하는 것은 span을
  받는 정적 `derive()`뿐입니다. HKDF의 extract/expand 매개변수와 PBKDF2의 반복
  횟수는 하나의 유용한 공통 인터페이스를 이루지 않습니다.
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
  닫는 것이고, 0을 밀어 넣는 것으로는 그것을 표현할 수 없기 때문입니다. x86-64에서는
  전체 8블록 묶음을 런타임 기능 검사 후 AVX512-IFMA 경로로 처리하고, 짧은 입력과
  나머지는 이식 가능 5 limb 구현을 사용합니다. `CERTPP_DISABLE_HWACCEL_SIMD`는
  이식 가능 경로를 강제합니다.
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
  않습니다**. GFNI가 있으면 각 피연산자의 비트 반사를 명령어 하나로 처리하고,
  없으면 SSE2 수열이 같은 변환을 수행합니다. 거기서 축약은 교과서적인
  `x^128 = x^7 + x^2 + x + 1`입니다. 정확성을 눈으로
  확인할 수 없는 1비트 시프트 더하기 거울상 상수 수법을 들고 다니지 않습니다.
  길고 정렬된 입력은 재귀 4단계를 `H^4`, `H^3`, `H^2`, `H` 곱과 한 번의
  reduction으로 접습니다. 짧은 입력은 직렬 경로를 유지해 거듭제곱 준비를 피합니다.

  발행된 벡터는 두 경로를 구별할 수 없습니다 — 이 CPU가 택하는 쪽이 그
  벡터들이 도달하는 유일한 경로입니다 — 그래서
  `tests/crypto/aeads/ghash.cpp`는 수천 개의 무작위·구조화된 피연산자에 대해
  둘을 직접 비교하고, 비트 순서를 못 박는 체 항등식들을 확인합니다(곱셈
  항등원은 `00 ... 00 01`이 아니라 `80 00 ... 00` 블록입니다). `Ghash`는
  공개 헤더도 `CERTPP_API`도 없으므로, 그 테스트는
  `CERTPP_TEST_PRIVATE_SOURCES`를 통해 `ghash.cpp`를 자기 안으로 컴파일해
  넣습니다.
- **`src/crypto/syms/aescore.hpp`/`.cpp`**는 `AesCore`를 정의합니다. AES 키
  스케줄, 단일 블록 암복호, CBC 대용량 암호화, 카운터 8개 GCM CTR 처리를
  담습니다. AES-NI와 256비트 VAES는 `CERTPP_DISABLE_HWACCEL_AES`와 런타임
  CPU·OS 상태 검사 뒤에 있습니다. GCM이 공유할 수 있도록 `aes.cpp`에서 분리한 것입니다 —
  `DesCore`와 `ChaCha20Core`가 이미 갖는 배치입니다. GCM은
  `ISymmetricContext`가 표현할 수 있는 모드가 아닙니다. 임의의 카운터 블록에서,
  *그리고* (H를 위해) 전부 0인 블록에서 원시 정방향 블록 함수가 필요하고,
  역암호는 전혀 쓰지 않습니다.
- **`src/crypto/syms/chacha20core.hpp`/`.cpp`**는 `ChaCha20Core`, 즉 블록
  함수를 정의합니다. AEAD가 공유할 수 있도록 스트림 암호에서 분리한
  것이고 — `DesCore`와 `KeccakCore`가 이미 갖는 배치입니다. AEAD는 그것을
  `ISymmetric`이 표현할 수 없는 두 카운터에서 필요로 합니다. Poly1305 키
  유도를 위한 0, 그리고 페이로드를 위한 1 이후입니다.
  `xorStream()`은 `CERTPP_DISABLE_HWACCEL_SIMD` 뒤에 4블록 SSE2
  (`xorStream4()`) 경로와 8블록 AVX2(`xorStream8()`) 경로를 지닙니다. SSE2 경로에서
  열여섯 개 상태 워드 각각이 연속된 네 카운터에 대한 그 워드를 담은 `__m128i`가 되므로,
  20라운드 한 번으로 256바이트가 나오고, 그 다음 블록 우선 바이트 순서로
  돌아오기 위해 네 워드 그룹마다 4x4 전치를 합니다. 블록들은 구성상
  독립적이므로 직렬화해야 할 것이 없습니다. AVX2 경로는 8블록 이상의 입력에서
  같은 배치를 두 배 너비로 적용하며 런타임 기능 검사로 선택됩니다. SSE2 자체는
  x86-64 ABI의 일부이므로 런타임 CPUID 검사가 필요 없습니다. 전체 8블록 묶음은
  가능하면 AVX2를, 그 뒤 4블록 묶음은 SSE2를 사용하고, 나머지는 스칼라 루프로
  떨어집니다. 그 루프가 x86-64가 아닌 모든 타깃도 담당합니다.
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
