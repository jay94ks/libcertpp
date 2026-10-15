# 로드맵

[English](PLANS.md)

`libcertpp`에 요청되었으나 아직 구현되지 않은 것들을 기록합니다. 이 문서는
요청받은 작업과 그 요청의 이유를 추적하며, 희망 목록이 아닙니다. 완료된
항목은 이 문서에서 빠져 [`docs/CONCEPTS.ko.md`](CONCEPTS.ko.md)로
옮겨가고, 그렇게 된 이유는 [`docs/HISTORY.ko.md`](HISTORY.ko.md)에
남습니다.

양자내성 암호화 트랙은 자체 검토 문서와 단계 구분을 가지고 있으므로
[`docs/PQC.ko.md`](PQC.ko.md)를 참고하세요.

## 자동 CI와 플랫폼 매트릭스

관리자의 로컬 환경에 의존하지 않고 지원하는 모든 툴체인을 빌드하고 테스트하는
저장소 CI를 추가합니다. 초기 매트릭스는 Windows의 MSVC, Linux의 GCC와 Clang,
실행기를 사용할 수 있다면 macOS의 Apple Clang을 포함해야 합니다. shared와
static 라이브러리를 모두 검증하고, `CERTPP_WITHOUT_JSON` 및 하드웨어 가속 비활성
스위치의 대표 구성도 포함합니다.

Pull request 매트릭스는 필요한 범위로 제한합니다. 지원 운영체제마다 주 빌드와
전체 CTest 모음을 실행하고, 더 큰 구성 매트릭스와 sanitizer는 예약 또는 수동
실행 작업으로 둡니다. 적어도 한 작업은 라이브러리를 깨끗한 prefix에 설치한 뒤
별도 소비자 프로젝트를 `find_package(certpp REQUIRED)`와 `certpp::certpp`로
빌드해야 합니다. 저장소 내부 빌드의 성공만으로는 설치 패키지를 검증할 수
없습니다.

매트릭스가 문서화되고, 필수 작업이 변경을 차단하며, sanitizer 실패에 분석 가능한
로그가 남고, [`docs/BUILDING.ko.md`](BUILDING.ko.md)의 유지보수 빌드 명령이
자동화와 일치하면 이 작업을 완료한 것으로 봅니다.

## 요청받은 알고리즘

| 알고리즘 | 표준 | 용도 |
| --- | --- | --- |
| GOST R 34.10-2012 / Streebog의 **X.509 및 DNSSEC 연결 작업** (알고리즘 자체는 완료됨) | RFC 9215, RFC 9558 | 러시아 프로파일 인증서 및 DNSSEC |

여기 요청되었다가 완료된 작업은 [`docs/CONCEPTS.ko.md`](CONCEPTS.ko.md)에
기술되어 있고, 그 배경은 [`docs/HISTORY.ko.md`](HISTORY.ko.md)에 담겨
있습니다. 여기에는 반복하지 않으며, 목록으로 만들어 두면 다음 작업이
완료될 때마다 낡게 됩니다.

구현에 영향을 주는 참고사항:

- **소수체 곡선 ECDH는 현재 constant-time이 아닙니다.** 다만 처음 보이는
  것과는 이유가 다릅니다. `CEcCurve::scalarMul()`은 이미 분기 없는
  *형태*의 ladder이지만, constant-time이 아닙니다: 루프가
  `k.bitLength()`번 돌고(반복 횟수가 스칼라의 최상위 설정 비트 위치를
  누출), `CBigNum::condSwap()`이 비밀 스칼라의 한 비트에 대한 실제 분기이며,
  `CBigNum`이 선행 0 limb를 잘라내어 모든 연산이 피연산자에 비례하는 일을
  합니다. `scalarMulBase()`는 네 번째 이유를 더합니다: `_baseTable[windowValue]`
  를 인덱스하는데 `windowValue`가 비밀 스칼라의 4비트이므로 데이터에 의존하는
  메모리 접근이고 캐시 타이밍 채널입니다. 이것을 constant-time으로 만드는 일은
  별개의 더 큰 작업입니다 -- [Constant-time 및 성능](roadmap/performance.ko.md)을 참고하세요.
- **GOST는 알고리즘이 구현되었고 인코딩만 남았습니다.**
  `Streebog256`/`Streebog512`와 `CGost3410`(9종의 매개변수 집합)이
  `crypto/`에 있으며 RFC 6986/7091/9215/9385로 검증되었습니다. 남은 것은
  OID와 와이어 포맷입니다: `parameters` 필드를 생략하는
  `id-tc26-signwithdigest-*` 서명 OID, `parameters`가 매개변수 집합 OID를
  담고 키 비트가 *OCTET STRING을 감싼* BIT STRING인 `SubjectPublicKeyInfo`,
  그리고 DER `SEQUENCE { r, s }`가 아니라 원시 `s || r` 블롭인 서명 값.
- **GOST의 DNSSEC 사정은 둘로 갈립니다.** RFC 5933이 2001년 서명 알고리즘을
  등록했고 RFC 8624는 그것을 쓰지 말라고 합니다. 2012년 알고리즘들은 그보다
  나중의 자체 등록(RFC 9558)을 가지고 있습니다. DNSKEY 유틸리티가 어떤 DNSSEC
  알고리즘 번호를 지원할지는 현행 IANA 레지스트리 대조 확인이 필요합니다.

## 상세 문서

- [Constant-time 및 성능](roadmap/performance.ko.md)
- [계획에 없음](roadmap/not-planned.ko.md)
