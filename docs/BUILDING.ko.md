# 빌드와 검증

[English](BUILDING.md)

`libcertpp`는 CMake(3.15 이상)로 빌드하며, C++17 컴파일러가 필요합니다.

## 구성 및 빌드

공유 라이브러리 (기본값):

```sh
cmake -S . -B build
cmake --build build --config Debug
```

정적 라이브러리:

```sh
cmake -S . -B build -DCERTPP_BUILD_SHARED=OFF
cmake --build build --config Debug
```

단일 구성(single-config) 제너레이터(Makefiles, Ninja)에서는 `--config`
대신 빌드 타입을 지정하세요:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## 상세 문서

- [구성과 설치](building/configuration.ko.md)
- [테스트와 예제](building/verification.ko.md)
