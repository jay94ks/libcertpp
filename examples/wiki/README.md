# Wiki examples

[한국어](README.ko.md)

The example code published on the
[GitHub wiki's API reference](https://github.com/jay94ks/libcertpp/wiki/API-Reference) —
one snippet per public class, struct and enum, 173 of them.

They live here, in the build, rather than only in the wiki, for one reason:
**a published example that has never been compiled is a guess.** This
directory is a build target, so an example that stops compiling breaks the
build instead of quietly misleading a reader.

## Layout

| | |
| --- | --- |
| `core.cpp` | the top-level `certpp` headers, plus `io/` and `utils/` |
| `asn1.cpp` | `certpp::asn1` |
| `crypto_core.cpp` | `certpp::crypto`'s own headers — hashers interface, MACs, KDFs, RNG, curves, AEADs |
| `crypto_hashers.cpp` | the concrete hashes under `crypto/hashers/` |
| `crypto_syms.cpp` | the block and stream ciphers under `crypto/syms/` |
| `crypto_asyms.cpp` | the signature and key-agreement algorithms under `crypto/asyms/`, and the KEMs |
| `x509_core.cpp` | `certpp::x509`'s own headers — certificates, CRLs, OCSP, CSRs, collections, containers |
| `x509_exts.cpp` | the ten extension types under `x509/exts/` |
| `dnssec.cpp` | `certpp::dnssec` |
| `main.cpp` | an empty `main()`, so the whole thing links |
| `snippets/` | generated: one `<Type>.md` per example, which the wiki pages splice in |

## How an example is written

```cpp
// === CCert ===
// One or two sentences of prose, shown above the snippet on the wiki page.
void exampleCCert(const COctet& der) {
    CCert cert;
    if (cert.importDer(der) != ERET_OK) {
        return;
    }
    // ...
}
```

- The `// === <TypeName> ===` marker names the type, exactly as the header
  spells it. It is what pairs a snippet with its wiki page.
- The function is named `example<TypeName>`.
- **The function body is what gets published**, dedented. It is written as the
  code a caller would write, not as a test — no asserts, no `doctest`.
- **Parameters are how an example gets what it cannot conjure.** A snippet
  needing a DER blob or a peer's public key takes it as a parameter, and
  `tools/exsplit.py` publishes the parameter list as a `// given: ...` line
  above the snippet. A placeholder expression like `/* file contents */` would
  not compile, which defeats the point.
- Each one carries the thing about its type that a caller gets wrong, where
  there is one — see
  [`specs/pitfalls.md`](../../specs/pitfalls.md). Twenty near-identical
  parse/build pairs with twenty interchangeable examples would document
  nothing.

## Regenerating the wiki

```sh
cmake --build build --config Debug --target certpp_example_wiki   # must pass first
python tools/exsplit.py                                           # -> snippets/*.md
python tools/wikigen.py emit <path to the wiki clone>
```

`tools/wikigen.py` reads the reference half of every page out of the headers'
Javadoc — nothing is retyped — and splices in the matching snippet. Each page
records the commit it came from, which is what makes a stale wiki page
detectable rather than merely wrong.

The generator will also tell you if a public type has no example yet, which is
how this directory stays complete as the library grows.

## These are not the walkthrough examples

`examples/*.cpp` one directory up are runnable programs:
`01_issue_ca_root.cpp` through `04_sign_verify.cpp` issue a real
root/intermediate/leaf hierarchy and sign with it, each one reading the
previous one's output. Those are the place to look for how the pieces fit
together. The snippets here answer a narrower question — *how do I call this
one type* — and are per-type precisely so that every type has one.
