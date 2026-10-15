# 표준과 인터페이스 설계

[English](design.md)

← [포스트퀀텀 암호](../PQC.ko.md)

## 구현 범위

`libcertpp`는 표준화된 ML-KEM과 ML-DSA 계열을 구현합니다. ML-KEM은 키
캡슐화를, ML-DSA는 서명을 제공합니다. SLH-DSA, FN-DSA, HQC, 복합 또는
하이브리드 인증서 방식은 현재 구현 범위 밖이며 가능한 미래 작업으로만
관리합니다.

구현된 두 계열 모두 저장소의 의존성 규칙을 따릅니다. 암호 코드는 트리 안에서
구현하고, 공개 ACVP 벡터와 독립 구현은 테스트 오라클로 사용합니다. `certpp`에는
제3자 암호 라이브러리를 링크하지 않습니다.

## 인터페이스 적합성

ML-DSA의 공개 연산은 키 생성, 서명, 검증이므로 `IAsymmetric`을 구현합니다.
`CMlDsa` 하나가 `EASYM_MLDSA44`, `EASYM_MLDSA65`, `EASYM_MLDSA87`로 고르는
세 파라미터 집합을 처리합니다. 고전 hash-then-sign 구현과 달리 ML-DSA는
메시지를 직접 받고 digest 크기를 0으로 보고합니다.

ML-KEM에는 별도의 `IKem`/`IKemContext` 인터페이스가 있습니다. 캡슐화는
ciphertext와 새로운 공유 비밀을 함께 만들고, 역캡슐화는 ciphertext를 공유
비밀로 바꿉니다. 어느 연산도 일반적인 비대칭 암호화가 아닙니다. `MLKEM` 하나가
`EKEM_MLKEM512`, `EKEM_MLKEM768`, `EKEM_MLKEM1024`를 처리합니다.

KEM 키는 `crypto/keys.hpp`에서 자체 계열을 이룹니다. `IKemPublicKey`,
`IKemPrivateKey`, `SKemKeyPair`가 있으며, 컨텍스트는
`IAsymmetricContext`와 같은 방식으로 바인딩된 키에 대해 작동합니다.

## X.509 적합성

ML-DSA AlgorithmIdentifier의 parameters는 없으며, 바깥 BIT STRING에 원시
FIPS 204 공개 키 또는 서명을 담습니다. 인증서와 CSR 코드는 세 ML-DSA OID를
모두 인식하고 직접 메시지 서명으로 검증하며 ML-DSA로 서명된 객체를 만들 수
있습니다.

ML-KEM 알고리즘과 키 연산은 완성되어 있지만 X.509 SubjectPublicKeyInfo 인코딩은
`CCert`에 연결되어 있지 않습니다. 이 경계는 [남은 PQC 작업](implementation.ko.md)에
기록합니다.
