# libcertpp examples

These build as `certpp_example_<name>` executables alongside the test suite (gated behind the
`CERTPP_BUILD_EXAMPLES` CMake option, `ON` by default). Run them from `build/<config>/` in
order -- each one after the first loads the certificate (and private key) the previous one
wrote to `examples/output/`, so they need to run in sequence the first time:

1. **`01_issue_ca_root`** -- generates a P-256 key pair and issues a self-signed root CA
   certificate around it (`BasicConstraints{CA:true}`, `KeyUsage{keyCertSign,cRLSign}`,
   `SubjectKeyIdentifier`). Writes `ca_root.pem`.
2. **`02_issue_intermediate`** -- loads `ca_root.pem`, generates a second key pair, and issues
   an intermediate CA certificate for it signed by the root
   (`BasicConstraints{CA:true,pathLen:0}`, `AuthorityKeyIdentifier` pointing back at the root's
   `SubjectKeyIdentifier`). Writes `intermediate.pem`.
3. **`03_issue_leaf`** -- loads `intermediate.pem`, generates a third key pair, and issues a
   TLS-server-style leaf certificate for it signed by the intermediate
   (`BasicConstraints{CA:false}`, `ExtendedKeyUsage{serverAuth}`, `SubjectAltName` with a couple
   of DNS names). Writes `leaf.pem`.
4. **`04_sign_verify`** -- loads `leaf.pem` and uses `CCert::signData()`/`verifyData()` to sign
   arbitrary data with its private key and verify it back, including a deliberately tampered
   message (expected to fail) and a verify pass using only the public certificate.

`examples/output/` is gitignored; delete it (or just rerun from step 1) to regenerate
everything with fresh keys. `examples/common.hpp` is shared file I/O/printing boilerplate, not
an example of its own.
