# libcertpp 예제

[English](README.md)

이 예제들은 테스트 모음과 나란히 `certpp_example_<name>` 실행 파일로
빌드됩니다(`CERTPP_BUILD_EXAMPLES` CMake 옵션으로 제어되며 기본값은 `ON`
입니다). `build/<config>/`에서 순서대로 실행하십시오 — 첫 번째 이후의 각
예제는 이전 예제가 `examples/output/`에 쓴 인증서(와 개인키)를 적재하므로,
처음에는 순서대로 실행되어야 합니다.

1. **`01_issue_ca_root`** — P-256 키 쌍을 생성하고 그것을 둘러싼 자기 서명
   루트 CA 인증서를 발행합니다(`BasicConstraints{CA:true}`,
   `KeyUsage{keyCertSign,cRLSign}`, `SubjectKeyIdentifier`).
   `ca_root.pem`을 씁니다.
2. **`02_issue_intermediate`** — `ca_root.pem`을 적재하고, 두 번째 키 쌍을
   생성하고, 루트가 서명한 중간 CA 인증서를 그것에 대해 발행합니다
   (`BasicConstraints{CA:true,pathLen:0}`, 그리고 루트의
   `SubjectKeyIdentifier`를 되가리키는 `AuthorityKeyIdentifier`).
   `intermediate.pem`을 씁니다.
3. **`03_issue_leaf`** — `intermediate.pem`을 적재하고, 세 번째 키 쌍을
   생성하고, 중간 CA가 서명한 TLS 서버 형태의 leaf 인증서를 그것에 대해
   발행합니다(`BasicConstraints{CA:false}`,
   `ExtendedKeyUsage{serverAuth}`, 그리고 DNS 이름 두어 개를 지닌
   `SubjectAltName`). `leaf.pem`을 씁니다.
4. **`04_sign_verify`** — `leaf.pem`을 적재하고
   `CCert::signData()`/`verifyData()`로 임의의 데이터를 그 개인키로 서명해
   되검증합니다. 의도적으로 조작된 메시지(실패가 기대됩니다)와 공개 인증서만
   쓰는 검증 패스도 포함합니다.

`examples/output/`은 gitignore되어 있습니다. 그것을 삭제하면(또는 그냥
1단계부터 다시 실행하면) 전부를 새 키로 다시 생성합니다.
`examples/common.hpp`는 공유되는 파일 I/O 및 출력 보일러플레이트이고, 그
자체로 예제는 아닙니다.

[`examples/wiki/`](wiki/README.ko.md)는 별개의 것입니다. 공개 타입당
컴파일되는 예제 하나이고, 단일 `certpp_example_wiki` 타깃으로 빌드되어
실행되는 대신 GitHub 위키에 발행됩니다. 그것은 walkthrough가 아닙니다 —
snippet 형식은 그 자신의 README를 보십시오.
