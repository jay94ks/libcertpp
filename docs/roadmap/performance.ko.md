# 보안 및 성능 작업

[English](performance.md)

이 문서에는 아직 남은 작업만 둡니다. 현재 구현 세부사항은
[기반과 핵심 유틸리티](../concepts/foundations.ko.md), 벤치마크 결과와 방법론은
[성능](../concepts/performance.ko.md), 완료된 작업은
[변경 이력](../HISTORY.ko.md)이 관리합니다.

## 보안 작업

### 보호된 비밀 저장소 완성

현재 보호 저장소의 동작, fallback switch, 한계는
[기반과 핵심 유틸리티](../concepts/foundations.ko.md)와
[보안 경계와 주의사항](../../specs/pitfalls.ko.md)에 기록합니다. 남은 작업은 일반
container 저장소를 사용하는 비밀 payload를 옮기는 것입니다.

1. 비밀을 담는 나머지 `COctet`, `CBuffer`, 기본 allocator `TArray` 인스턴스를
   감사합니다. 장기 보관하거나 재사용하는 소유자는 역할에 따라 `CSecureOctet`,
   `CSecureBuffer`, `TSecureArray`로 옮깁니다.
2. 공개 산술까지 보안 allocator로 보내지 않으면서 RSA, DSA, ECDSA, GOST의 장기 보관
   private `CBigNum` 구성 요소에 보호된 limb 저장소를 추가합니다.
3. nonce, seed, 파생 비밀, private 산술 임시값을 위한 재사용 가능한 연산 단위 secure
   arena를 검토하여 page 잠금을 hot loop 밖에 둡니다.
4. host 잠금 제한에 의존하지 않고 사용 전 잠금, 잠금 해제 전 영점화, required-mode
   실패를 검증하는 주입 가능한 플랫폼 backend를 추가합니다. Linux에서는 잠긴 byte
   집계와 fork 동작을, Windows에서는 대응하는 할당·잠금·잠금 해제·반환 순서를
   검증합니다.

## 성능 작업

- **Windows thread 의존성을 CMake에 반영합니다.** Clang/MinGW 빌드는 여전히
  `SecurePool`의 `std::mutex` 때문에 명시적인 `-lwinpthread`가 필요합니다. 유지
  보수하는 CMake 패키지에서 이 의존성을 export하고 검증합니다.
- **portable constant-time 소수 곡선 fallback을 완성합니다.** 네이티브 x86-64
  Clang/GCC 빌드는 고정 폭 Montgomery limb와 전체 스캔 private window를 사용합니다.
  portable fallback은 여전히 비용이 가변적인 `CBigNum`의 할당, limb 정리, 산술에
  의존합니다. 이를 교체하거나 플랫폼별 타이밍 경계를 명시적으로 유지합니다.
- **공개된 타이밍 공격을 기준으로 ML-DSA 서명을 감사합니다.** 기존 감사 도구는 재시도
  동작을 측정하지만, Fiat-Shamir-with-aborts와 데이터 의존적인 재시도 횟수에 대한 전용
  검토를 대신하지 않습니다. [PQC 엔지니어링과 위험](../pqc/engineering.ko.md)을
  참고하십시오.
