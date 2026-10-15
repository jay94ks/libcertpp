# 엔지니어링, 검증 및 위험

[English](engineering.md)

← [포스트퀀텀 암호](../PQC.ko.md)

## 구현된 기반

ML-KEM과 ML-DSA는 Keccak 프리미티브를 공유하지만 modulus와 NTT 구조가 다르므로
서로 별도의 다항식 환 구현을 사용합니다. 현재 코드는 다음과 같이 구성됩니다.

- `SHAKE128`과 `SHAKE256`은 증분 `squeeze()` 출력을 제공하고, SHA3-256과
  SHA3-512는 고정 출력 framing과 함께 같은 Keccak permutation을 공유합니다.
- `src/crypto/kems/mlkemring.hpp`, `mlkemcodec.hpp`, `mlkemsampler.cpp`가
  ML-KEM의 환, 패킹, 압축, 샘플러를 구현합니다.
- `src/crypto/asyms/mldsaring.hpp`, `mldsacodec.hpp`,
  `mldsarounding.hpp`, `mldsasampler.hpp`가 대응하는 ML-DSA 단위를 구현합니다.
- `CSecure`가 constant-time 동등 비교와 선택, 명시적 영 소거를 제공합니다.
  ML-KEM 역캡슐화는 구별 가능한 ciphertext 실패를 보고하지 않고 암묵적 거부를
  사용합니다.

## 트리 안의 검증

`tests/crypto/kems/kat_mlkem.cpp`는 세 ML-KEM 파라미터 집합 모두에 대해 키 생성,
캡슐화, 역캡슐화, 암묵적 거부, 키 검증을 NIST ACVP 데이터와 대조합니다. 주변
`mlkem*.cpp` 테스트는 환, 코덱, 공개 인터페이스, 변조, chunk 경계를 다룹니다.

`tests/crypto/asyms/kat_mldsa.cpp`와 `kat_mldsaver.cpp`는 세 파라미터 집합 모두에서
ML-DSA 키 생성, 결정적·hedged 서명, 유효한 검증, 포함된 모든 거부 사유를
검사합니다. 나머지 `mldsa*.cpp` 테스트는 환, 샘플러, 라운딩, 패킹, 공개
인터페이스를 실행합니다. `tests/x509/realcerts.cpp`는 독립 구현이 만든 ML-DSA-87
인증서를 검증하므로 근거가 라이브러리 자신의 왕복 출력에만 의존하지 않습니다.

## 보안 한계

ML-DSA 서명은 Fiat-Shamir-with-aborts를 사용하므로 시도 횟수가 비밀에서 유도된
값에 의존합니다. 구현은 무제한 재시도 루프를 사용하고 모든 탈출 경로에서 비밀
중간값을 지우며, 한 시도 안에서는 비밀에 따른 테이블을 피합니다. 공개된
Dilithium 공격을 기준으로 한 전용 타이밍 부채널 감사는 받지 않았습니다.

ACVP 및 상호운용 테스트는 기능 호환성을 입증하지만 제3자 보안 감사를 뜻하지는
않습니다. 이 한계는 [PQC 작업 목록](implementation.ko.md)과
[constant-time 로드맵](../roadmap/performance.ko.md) 양쪽에 남은 작업으로
기록합니다.
