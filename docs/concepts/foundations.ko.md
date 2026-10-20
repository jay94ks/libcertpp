# 코어와 유틸리티

[English](foundations.md)

## 핵심 타입

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

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
  탐지하도록 만들어진 것입니다. `CERTPP_DISABLE_SECURE_MEM=ON` 빌드는
  `major`의 최상위 비트인 `VERSION_FLAG_SECURE_MEM_DISABLED`를 설정합니다.
  `SVersion` 비교는 이 비트를 마스킹하며 `isSecureMemory()`가 비트가 꺼져 있는지
  보고합니다.
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

## 유틸리티

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

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
- **`utils/secure.hpp` / `src/utils/secure.cpp`**는 공개 `CSecure` facade를
  정의합니다. private 페이지 풀은 `src/utils/securepool.hpp` /
  `securepool.cpp`에 있고 저장소를 지울 때 `CSecure::zero()`를 다시 호출합니다.
  비밀 바이트에 대한, 당연해 보이는 방식으로는 쓸 수 없는 연산들입니다.
  `alloc(size, alignment)`는 운영체제에서 직접 보호 페이지를 얻고 동시에 존재하는
  작은 할당들이 페이지 하나를 나눠 쓰게 합니다. 기본값에서는 OS의 large-page 크기로
  먼저 요청하고, 사용할 수 없으면 Windows의 `VirtualLock` 또는 POSIX의 `mlock`으로
  잠근 표준 페이지로 폴백합니다. `CERTPP_DISABLE_LARGE_PAGE=ON`이면 처음부터 표준
  페이지를 선택합니다. 일반 heap fallback은 없습니다. mapping 또는 잠금 실패는
  `ERET_NOMEM`입니다. `CERTPP_DISABLE_SECURE_MEM=ON`은
  `CSecure::alloc()`/`dealloc()` backend만 일반 정렬 heap 할당과 해제로 바꾸어
  공개 container 타입은 유지하면서 page 잠금과 해제 시 영 소거를 끕니다. 기본
  빌드의 `dealloc()`은 블록을 재사용하기 전에 지우고, 다른
  블록이 살아 있는 동안 페이지를 보호하며, 마지막 블록을 반환할 때 mapping 전체를
  지웁니다. 풀은 영점화한 표준 페이지를 최대 하나만 잠긴 상태로 보관해 재사용하고,
  그 밖의 표준 페이지와 large-page mapping은 운영체제에 돌려주기 직전에 전체를 지운 뒤
  필요에 따라 잠금을 풉니다.
  정렬을 생략한 overload도 최소 16바이트 정렬을 제공합니다. 명시적인 2의 거듭제곱 정렬을 사용하면
  SIMD 친화적인 상태를 보호 저장소에 바로 놓을 수 있습니다. `make<T>()`는
  `alignof(T)`를 사용하고 `shared_ptr` deleter에서 소멸자를 실행합니다.

  모든 비대칭 및 KEM 개인키 객체는 `CSecure::make()`로 생성됩니다. 따라서 Ed25519,
  Ed448, X25519의 비밀 배열을 포함한 inline 필드는 객체 수명 동안 보호됩니다.
  ML-DSA와 ML-KEM의 인코딩된 개인키는 `CSecureOctet`에 보관되고 생성 buffer는
  `CSecureBuffer`를 사용합니다. 대칭키 원문은 `CSecureOctet`, AES/ARIA key schedule은
  `TSecureArray`, 평문을 보관할 수 있는 CBC/RSA 변환 buffer는 `CSecureBuffer`를
  사용합니다. 기본 `COctet`이나 `TArray`, `CBigNum` 또는 다른 일반 container가 간접
  소유하는 저장소는 여전히 잠긴 page 밖에 있습니다.

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
  `generatePrime`(호출자가 제공한 `crypto::IRng`를 통하며, 호환 오버로드는 지역
  `CRng`를 만듭니다)이 있습니다.
  `fromHex`/`fromLittleEndian`/`toLittleEndian`/`fromBigEndianTruncated`가
  생성/직렬화를 마무리하고(16진 파싱 자체는 독립된 `CHex` 유틸리티에 있습니다.
  위를 보십시오), `condSwap`은 스칼라 곱 ladder를 위해 이미 할당된 limb를 산술
  mask로 교환합니다. 이를 둘러싼 가변 폭 타입 전체는 여전히 constant-time
  백엔드가 아닙니다. `crypto/`가 아니라 `utils/` 아래에 있는데, 타입 자체가 어느 한 알고리즘에
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

  `modInverse()`는 입력을 한 번 축약한 뒤 홀수 모듈러스에 binary extended GCD를
  사용합니다. 계수를 `m`으로 축약된 상태에 유지하므로 각 반복은 몫 크기 곱셈과
  나눗셈 대신 shift, 비교, 덧셈, 뺄셈만 수행합니다. 짝수 모듈러스는 일반 확장
  유클리드 경로를 유지합니다. 두 경로 모두 `CBigNum`의 문서화된 경계와 같이
  variable-time입니다.

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
  수열로(`tests/utils/montgomery.cpp`, 약 915,000개 단정). 네이티브 Clang x86-64
  빌드의 `modExp()`는 짧은 binary 체인과 더 긴 sliding-window 체인을 모두 packed
  64비트 저장소에 유지합니다. 곱 누산과 Montgomery 축약은 하나의 통합 CIOS 자리
  순회에서 함께 진행됩니다. `modExpProduct()`는 두 밑수에 2비트 동시 window를 적용해
  하나의 공유 제곱 체인과 같은 packed 표현을 사용합니다. 조건부 뺄셈을
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
