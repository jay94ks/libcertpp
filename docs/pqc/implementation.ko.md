# 향후 PQC 후보

[English](implementation.md)

← [포스트퀀텀 암호](../PQC.ko.md)

핵심 ML-KEM과 ML-DSA 구현, RFC 9935 ML-KEM 공개키 SPKI 코덱, ML-DSA
재시도/타이밍 감사 도구가 완료되었습니다. 구현 과정은
[변경 이력](../HISTORY.ko.md)에 있습니다. 감사 도구는 분석을 위해 시도 횟수와
거부 범주를 보고하지만 Fiat-Shamir-with-aborts 서명을 constant-time 연산으로
바꾸지는 않습니다.

## 추가 알고리즘

안정적인 상호운용 인코딩과 구체적인 호출자 요구가 생겼을 때만 SLH-DSA,
FN-DSA, HQC, 복합 또는 하이브리드 인증서 방식을 다시 평가합니다. 새 알고리즘은
ML-KEM과 ML-DSA에 사용한 것과 같은 외부 벡터, 잘못된 입력, 독립 상호운용 근거를
갖춰야 합니다.
