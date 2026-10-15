# 문서 안내

[English](README.md)

이 페이지는 `libcertpp` 문서의 지도입니다. 하려는 작업에 맞는 경로를 선택하세요.
각 정보는 하나의 문서가 소유하며, 요약 문서는 같은 내용을 따로 유지하는 대신 그
문서로 링크해야 합니다.

전체 파일 목록은 [문서 인덱스](INDEX.ko.md)를 참고하십시오.

## 목적별 시작점

| 목적 | 여기서 시작 | 다음 문서 |
| --- | --- | --- |
| 프로젝트 평가 또는 빌드 | [`README.ko.md`](../README.ko.md) | [`BUILDING.ko.md`](BUILDING.ko.md) |
| 벤치마크 결과 검토 | [`concepts/performance.ko.md`](concepts/performance.ko.md) | 남은 작업은 [`roadmap/performance.ko.md`](roadmap/performance.ko.md) |
| C++ API 사용 | [`specs/README.ko.md`](../specs/README.ko.md) | API 지도, 레시피, 함정, 컴파일되는 예제 |
| 변경 기여 | [`CONTRIB.ko.md`](../CONTRIB.ko.md) | 아래의 아키텍처, 컨벤션, 빌드 레퍼런스 |
| AI 코딩 에이전트로 작업 | [`AGENTS.md`](../AGENTS.md)(영문) | `CONTRIB.ko.md`의 AI 섹션과 작업 관련 문서 |
| 설계가 존재하는 이유 이해 | [`HISTORY.ko.md`](HISTORY.ko.md) | 현재 상태는 `CONCEPTS.ko.md` |
| 계획된 작업 찾기 | [`PLANS.ko.md`](PLANS.ko.md) | PQ 전용 검토는 `PQC.ko.md` |

## 유지보수자 문서

| 문서 | 소유하는 내용 | 소유하지 않는 내용 |
| --- | --- | --- |
| [`CONCEPTS.ko.md`](CONCEPTS.ko.md) | 현재 모듈, 경계, 파일, 지원 동작 | 역사적 서술 또는 미래 작업 |
| [`RULES.ko.md`](RULES.ko.md) | 소스 구성, 네이밍, 포맷팅, 공개 주석, 테스트 규칙 | 빌드 명령 또는 제품 사용법 |
| [`BUILDING.ko.md`](BUILDING.ko.md) | 설정, 빌드, 테스트, 설치, 옵션, 예제, sanitizer | API 레시피 |
| [`PLANS.ko.md`](PLANS.ko.md) | 아직 완료되지 않았거나 명시적으로 범위 밖인 요청 작업 | 완료된 기능 목록 |
| [`HISTORY.ko.md`](HISTORY.ko.md) | 역사적 결정, 조사, 측정, 완료된 수정 | 현재 아키텍처의 간결한 설명 |
| [`PQC.ko.md`](PQC.ko.md) | PQ 설계 검토, 검증 출처, 구현 단계 | 프로젝트 전체 로드맵 |

## 호출자 문서

[`specs/`](../specs) 디렉터리는 `docs/`와 함께 유지 보수하며 작업 중심의 API
질문에 답합니다:

- [`api-map.ko.md`](../specs/api-map.ko.md)는 작업을 헤더와 타입에 연결합니다.
- [`recipes.ko.md`](../specs/recipes.ko.md)는 흔한 호출을 맥락 안에서 보여 줍니다.
- [`pitfalls.ko.md`](../specs/pitfalls.ko.md)는 성공한 것처럼 보이지만
  잘못되었거나 불완전한 호출을 기록합니다.

[`examples/`](../examples) 디렉터리는 컴파일되는 둘러보기를 담습니다.
[`examples/wiki/`](../examples/wiki)는 공개 타입별 API 레퍼런스 페이지를 만들
때 사용하는 컴파일되는 소스 조각을 담습니다. `examples/wiki/snippets/` 아래의
생성된 Markdown은 결과물이지 유지 관리하는 문서가 아닙니다.

## 문서가 서로 다를 때의 우선순위

1. 공개 헤더가 API 계약과 doc 주석을 정의합니다.
2. 컴파일되는 예제가 지원되는 사용법을 보여 줍니다.
3. 테스트가 동작과 경계 조건을 고정합니다.
4. `CONCEPTS.ko.md`가 의도된 현재 구조를 설명합니다.
5. 호출자 명세와 요약이 위 자료와 다르면 호출자 명세와 요약을 고쳐야 합니다.

빌드 동작은 최종적으로 `CMakeLists.txt`가 결정하며 `BUILDING.ko.md`는 이를 유지
관리하는 설명입니다. `HISTORY.ko.md`의 역사적 문장은 과거 상태를 설명할 수
있으므로 그 맥락에서 읽어야 합니다.

## 언어 및 생성 콘텐츠

영문이 원본 언어입니다. 유지 관리하는 독자용 문서는 3번째 줄에서 링크하는
`<이름>.ko.md` 한국어 짝 문서를 가집니다. 운영용 진입점인 `AGENTS.md`와
`CLAUDE.md`는 예외입니다. 짝을 이루는 문서는 같은 변경에서 두 언어를 모두
갱신하고, 번역이 있다면 문서 간 링크도 독자의 언어 안에 유지합니다.

생성된 위키 snippet 또는 API 페이지를 손으로 수정하지 마세요. 원본은 공개
헤더의 Javadoc과 대응하는 컴파일되는 예제입니다. 자세한 내용은
[`examples/wiki/README.ko.md`](../examples/wiki/README.ko.md)를 참고하세요.
