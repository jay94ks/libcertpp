# 남은 PQC 작업

[English](implementation.md)

← [포스트퀀텀 암호](../PQC.ko.md)

핵심 ML-KEM과 ML-DSA 구현은 완료되었습니다. 구현 과정은
[변경 이력](../HISTORY.ko.md)에 있으며, 이 문서에는 미완료 작업만 둡니다.

## ML-KEM 인증서 통합

X.509 알고리즘 표와 키 코덱에 ML-KEM SubjectPublicKeyInfo 지원을 추가합니다.
구현은 import/export 과정에서 파라미터 집합을 보존하고, AlgorithmIdentifier
parameters가 없음을 요구하며, 원시 FIPS 203 캡슐화 키를 BIT STRING에 담아야
합니다. 상호운용 테스트에는 독립적으로 만들어진 fixture 또는 두 번째 구현을
사용해야 합니다.

이 작업은 인증서에 KEM 공개 키를 추가합니다. ML-KEM을 인증서 서명 알고리즘으로
만들거나 `IAsymmetric`에 억지로 넣지 않습니다.

## ML-DSA 타이밍 검토

서명의 데이터 의존 분기, 메모리 접근, 관측 가능한 재시도 동작을 집중적으로
검토합니다. 공개된 Dilithium 타이밍 공격과 구현을 대조하고, constant-time으로
만들 수 있는 범위와 없는 범위를 기록하며, 강제할 수 있는 속성에는 집중 테스트
또는 측정 도구를 추가합니다.

## 추가 알고리즘

안정적인 상호운용 인코딩과 구체적인 호출자 요구가 생겼을 때만 SLH-DSA,
FN-DSA, HQC, 복합 또는 하이브리드 인증서 방식을 다시 평가합니다. 새 알고리즘은
ML-KEM과 ML-DSA에 사용한 것과 같은 외부 벡터, 잘못된 입력, 독립 상호운용 근거를
갖춰야 합니다.
