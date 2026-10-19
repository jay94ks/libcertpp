# Constant-time 및 성능 작업

[English](performance.md)

이 문서에는 아직 남은 작업만 둡니다. 현재 벤치마크 결과와 방법론은
[성능](../concepts/performance.ko.md)에, 완료된 최적화·조사·부정적 결과는
[변경 이력](../HISTORY.ko.md)과 [계획에 없음](not-planned.ko.md)에 기록합니다.

## 보안 작업

- **portable constant-time 소수 곡선 fallback을 완성합니다.** 네이티브 x86-64
  Clang/GCC 빌드는 이제 체 좌표를 고정 폭 Montgomery limb에 유지하고 private window
  후보를 모두 스캔하며 전체 군 위수 폭을 처리합니다. portable fallback은 여전히 할당,
  limb 정리, 산술 비용이 피연산자에 따라 달라지는 `CBigNum`을 사용합니다. 플랫폼
  독립적인 주장을 하기 전에 이 fallback을 교체하거나 variable-time 경계를 명시적으로
  유지합니다.
- **ML-DSA 서명의 타이밍 누출을 감사합니다.** Fiat-Shamir-with-aborts의 재시도
  횟수는 설계상 데이터 의존적입니다. 현재 구현은 비밀 중간값을 지우고 한 반복
  안에서는 비밀에 따른 테이블을 피하지만, 공개된 Dilithium 공격을 기준으로 한
  전용 타이밍 부채널 검토는 아직 받지 않았습니다. [PQC 엔지니어링과
  위험](../pqc/engineering.ko.md)을 참고하십시오.
