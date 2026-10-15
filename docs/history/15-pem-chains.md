# PEM certificate chains

[한국어](15-pem-chains.ko.md)

## `x509/chain/pem`: the PEM container format, and PEM moved out of `CCert`

← [History](../HISTORY.md)

`include/certpp/x509/chain.hpp` had defined `IChainFormat` — read and write a
`CCertCollection` as a container file — with `builtIn()` returning null for
every format. This is the PEM half: `CPemChainFormat`
(`include/certpp/x509/chain/pem.hpp`, `src/x509/chain/pem.cpp`), wired into
`builtIn(ECHAINFMT_PEM)`.

The non-obvious part is the direction of the dependency. `CCert` already had
PEM: multi-block scanning, label handling, base64 framing, and four ways of
recognising a private-key block (PKCS#1, DSA traditional, SEC1, PKCS#8 — the
last of those tried four ways in turn). All of that was *container* work
sitting in a certificate class because, until `CCertCollection` existed, there
was nowhere else to put it. So it moved rather than being wrapped:
`CPemChainFormat` is now the only PEM handling in the library, and
`CCert::importPem()`/`exportPem()`/`detectCertFormat()` are thin delegations —
`importPem()` loads a one-entry collection and keeps the first entry,
`exportPem()` saves one, `detectCertFormat()` asks
`IChainFormat::detect()`. The 15 existing `CCert` PEM test cases passed
unmodified afterwards, which is the only reason a refactor of this shape is
safe to make. A new case in `tests/x509/chain/pem.cpp` additionally pins
`exportPem()`'s bytes to the format's own `save()` output byte for byte, so the
delegation cannot quietly become a second implementation.

Two things `CCert` keeps and the format reaches through friendship: `_asym`
(the algorithm a candidate key block has to parse under, already resolved by
`importDer()`) and a new private `lookupKeyAlgoOid()` over the existing
`KEY_ALGOS` table — the OID a PKCS#8 key block carries has to come from the
same table `importDer()` resolved the certificate's algorithm from, not from a
second copy that can drift.

The decisions worth recording, since the interface allowed either answer:

- **`save()` does not write private keys unless asked.** PEM has no
  encryption, so a key written out is a key in the clear; `builtIn()` returns
  the certificates-only form and `CPemChainFormat(true)` is the opt-in (what
  `exportPem(out, /*includePrivateKey=*/true)` constructs). A key in the clear
  is occasionally what a caller wants; a key in the clear that nobody asked for
  is not. The `password` argument is *ignored outright* in both directions —
  not accepted-and-checked, which would read like protection — and the header,
  the doc comments and a test all say so.
- **A certificate whose algorithm this library cannot resolve is loaded, not
  rejected.** `importDer()` parses it fully and leaves `keyAlgo()`/`signAlgo()`
  as raw OID text; dropping it would lose a certificate the file genuinely
  holds and that the collection's name-based lookups still work on. Only its
  key is unavailable, so no private key ever pairs with it. Tested against a
  real certificate with one byte of its SPKI algorithm OID changed.
- **Key blocks are paired cryptographically, not positionally.** The whole file
  is scanned first, then each certificate is offered every unconsumed key block
  until `CCert::privateKey(IPrivateKeyPtr&)`'s own public-key comparison
  accepts one. A key before its certificate, a key after it, and a key that
  belongs to neither all behave correctly, which positional pairing cannot
  manage.
- **A structurally broken block fails the whole container** (`ERET_BADREQ`),
  where `CCert::importPem()` used to stop scanning at that point and report
  success with whatever it had already found. That is the one documented
  behaviour the move deliberately changes: silently truncating a scan is how a
  file loses a certificate, or a key, without anyone being told. It is called
  out in `importPem()`'s own doc comment.
- **A password-encrypted key block is `ERET_NOTSUP`, not `ERET_BADREQ`** —
  either an `ENCRYPTED PRIVATE KEY` label (PKCS#8) or RFC 1421's
  `Proc-Type: 4,ENCRYPTED` header, which openssl still writes. The file is
  well-formed; what it needs is a password this format has no way to accept.
  Without the `Proc-Type` check the legacy form would have reported "malformed"
  instead, since its headers are not base64.
- **PKCS#9 attributes ride in openssl's own `Bag Attributes` shape**
  (`friendlyName:`/`localKeyID:` outside the encapsulation boundaries, where
  RFC 7468 5.2 allows arbitrary text and every other reader skips it), so
  `SCertEntry`'s attributes survive a PFX → PEM → PFX trip, as `IChainFormat`'s
  own doc comment promises for both formats. A `friendlyName` containing a line
  break is refused rather than written into a header it would run out of.

One thing the old `CCert` version did not do and this one does: the decoded
key blocks are zeroized (`CSecure::zero`) on the way out of `load()`, whichever
of its return paths is taken — they are plaintext private keys, and leaving
this function's own copies in freed heap memory is free to avoid. It is not a
claim that no copy survives: the caller's PEM text holds the same bytes in
base64 and is the caller's to scrub.

`load()` builds up locally and commits to the collection only once the whole
file has parsed, because the interface requires appending *and* requires that a
failure leave the collection untouched — writing into the output as the scan
proceeds reads as the obvious implementation and is exactly the bug that
sentence exists to forbid.

Testing deliberately avoids proving the implementation against itself. The
fixtures under `tests/x509/chain/certs/` were all written by OpenSSL 3.4.0:
`tests/x509/certs/implemented/`'s three real commercial certificates converted
with `openssl x509 -inform DER`, a throwaway RSA and P-256 self-signed pair
from `openssl req -x509 -newkey ...` interleaved so each key sits next to the
certificate it does *not* belong to, the same EC key as a traditional SEC1
block, a `openssl pkcs12 -nokeys` bag dump for the `Bag Attributes` parsing,
and the key encrypted both ways openssl can encrypt it. The three real
certificates come back out of openssl's base64 byte-identical to the `.der`
files on disk, which is the interoperability claim that matters. Nothing was
fetched from the network.

Negative controls, each injected, rebuilt, and restored:

| injected fault | caught by |
|---|---|
| `load()` commits each entry into the output collection as it parses, instead of at the end | 9 failures: all four corrupt-container subcases report the collection left half-populated, and three key-pairing cases break as well (the committed copies never receive the key) |
| `load()` clears the collection before adding, i.e. replaces instead of appending | 5 failures in the merge case (count 6 instead of 7, every index shifted) |
| a block whose payload decodes but isn't a certificate is skipped instead of failing the container | 4 failures: the corrupt-payload and whole-group-truncation subcases both report `ERET_OK`, and the collection is left with the surviving entries |

The third control also found a gap in the first draft of the tests. The
"truncated payload" case had removed 40 characters from the end of the base64
body, which leaves a partial 4-character group — so the *decoder* rejected it
and the certificate parse never ran, meaning the test would have passed even
with the DER check disabled. The fix was a second subcase that truncates by a
whole number of base64 groups, which decodes cleanly and can only be caught by
the DER parse. Two layers, two subcases.
