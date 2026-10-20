# 계획에 없음

[English](not-planned.md)

← [로드맵](../PLANS.ko.md)

- **실시간 폐지 확인과 완전한 RFC 5280 정책 트리 처리.** `CPathValidator`는 명시적인
  `CTrustStore`에 대해 문서화한 core 경로 검사를 수행하지만, 추가 기능을 요청하면
  `EPATH_REVOCATION_UNAVAILABLE` 또는 `EPATH_POLICY_PROCESSING_UNAVAILABLE`을
  반환합니다. 이 기능이 필요한 응용은 폐지 상태 공급원이나 더 완전한 정책 엔진을
  통합해야 합니다.

현재 측정값은 [성능](../concepts/performance.ko.md)이, 완료된 성능 이정표는
[변경 이력](../HISTORY.ko.md)이 관리합니다. 이후 결과로 대체된 중간 조사는 로드맵
항목으로 유지하지 않습니다.
