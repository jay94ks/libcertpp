# 포스트퀀텀 암호

[English](PQC.md)

이 라이브러리는 ML-KEM(FIPS 203)과 ML-DSA(FIPS 204)를 밑바닥부터 구현합니다.
이 문서는 현재 구현 목록이며, 구현 과정과 완료된 조사는
[변경 이력](HISTORY.ko.md)에 보존합니다.

## 현재 구현

| 영역 | 현재 코드 |
| --- | --- |
| ML-KEM | `CMlKem`이 원시 FIPS 203 연산을 노출하고 `MLKEM`이 ML-KEM-512/768/1024용 `IKem`을 구현합니다. 키는 FIPS 203 인코딩을 사용합니다. |
| ML-DSA | `CMlDsa`가 ML-DSA-44/65/87용 `IAsymmetric`을 구현합니다. 서명은 메시지를 직접 받고 hedged 난수를 사용합니다. |
| 공유 프리미티브 | SHA3-256/512, 증분 squeeze를 갖춘 SHAKE128/256, 안전 비교·선택·영 소거, 알고리즘별 NTT 환을 트리 안에 구현했습니다. |
| X.509 | ML-DSA 공개 키와 서명이 인증서 및 CSR 파싱/빌드에 연결되어 있습니다. 제3자가 만든 IdenTrust ML-DSA-87 파일럿 루트가 테스트에서 검증됩니다. ML-KEM SubjectPublicKeyInfo 지원은 구현되지 않았습니다. |

ML-KEM과 ML-DSA는 모든 파라미터 집합에 대해 NIST ACVP 벡터로 검사합니다.
테스트에는 ML-KEM 암묵적 거부와 키 검증, ML-DSA 검증 거부 사례, 독립 구현이
만든 ML-DSA 인증서가 포함됩니다. 정확한 테스트 표면과 현재 보안 한계는
[엔지니어링, 검증 및 위험](pqc/engineering.ko.md)을 참고하십시오.

## 상세 문서

- [표준과 인터페이스 설계](pqc/design.ko.md)
- [엔지니어링, 검증 및 위험](pqc/engineering.ko.md)
- [남은 PQC 작업](pqc/implementation.ko.md)

완료된 구현 작업은 변경 이력의 [04](history/04-ml-kem.ko.md),
[05](history/05-secure-memory-and-ml-dsa.ko.md),
[06](history/06-ml-dsa-and-portability.ko.md),
[07](history/07-protocol-primitives.ko.md), [13](history/13-ml-dsa.ko.md)장에
정리되어 있습니다.
