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

## 완료된 신뢰성과 생태계 통합 계획

신뢰성과 생태계 통합 계획은 완료되었습니다. 현재 동작은
[아키텍처와 개념](CONCEPTS.ko.md), 호출자 계약은 [`specs/`](../specs),
빌드와 보안 절차는 [빌드와 검증](BUILDING.ko.md) 및
[`SECURITY.ko.md`](../SECURITY.ko.md)가 관리합니다. 폐지 확인과 완전한 RFC 5280
인증서 정책 처리는 core 경로 검증에 포함된 것처럼 취급하지 않고 validator의
명시적인 미지원 기능으로 남아 있습니다.

## 상세 문서

- [보안 및 성능](roadmap/performance.ko.md): 페이지 잠금 비밀 메모리의 남은 보호
  container 작업 포함
- [계획에 없음](roadmap/not-planned.ko.md)
