# OIDs and correctness fixes

[한국어](20-oids-and-correctness.ko.md)

## `COid`/`SRawOid`, and every OID the library names living in one place

← [History](../HISTORY.md)

The OID module finished, and the OIDs the library defines were collected into
it. What that changed is not the size of the API but the number of places an
OID can be spelled.

#### `SRawOid` and `COid`

`SRawOid` is an OID's arcs and nothing else: a fixed array plus a count, with
`parse()`, `toString()`, `compare()` and the stream operators. `COid` is a
handle onto one of the library's named OIDs or onto an OID parsed from text --
a `shared_ptr` to a cached slot, so a `COid` is a pointer-sized value and
copying one is a refcount bump rather than a re-parse.

`SKnownOid` is the table entry: `{ uint32_t nth; const char* s; }` and nothing
else. It stores the index into the table and the dotted-decimal text, and the
arcs are parsed out of that text by `SRawOid::parse()` when a `COid` is
constructed for it. An earlier design had the entry carry its arcs as well.
That was dropped deliberately: the string and the arcs are two spellings of
one fact, they can disagree, and keeping them in agreement needs a second
parser and a rule about which one wins. There is now one.

The table is filled at runtime, atomically. `CACHED` is a zero-initialized
`std::atomic<Slot*>` array; the first `COid` constructed for an entry publishes
its slot with `compare_exchange_strong` (acquire/release) and every later one
reads it. Nothing is initialized at load time, so there is no static-init
ordering to get wrong and no OID work on the process's startup path. The loser
of a race deletes its own slot; slots are deliberately never freed, since the
`shared_ptr`s aliasing them use a no-op deleter and a `COid` may outlive any
particular use of it.

`SRawOid::parse()` enforces X.690 8.19.4 as well as the syntax: `arcs[0] <= 2`,
and `arcs[1] < 40` when `arcs[0] < 2`. A rejected OID comes back with
`count == 0` rather than holding the prefix that did parse.
`COid::operator=(const CString&)` resets to empty on a parse failure rather
than silently keeping the previous OID, which was the other way a bad OID could
go unnoticed.

118 OIDs are collected in `CERTPP_KNOWN_OIDS`: hashes, key algorithms,
signature algorithms, 30 named curves, the X.509 extensions this library
models, access methods, EKU purposes, OCSP, the PKCS#12/PFX set, and the DN
attributes `CName` recognizes. Each entry is written with its index spelled out
rather than numbered by a macro: a macro counter makes the value correct but
invisible, and inserting an entry would silently renumber everything after it.

#### The OID codec decodes to arcs

`CDecoder::decodeOid`, `CEncoder::encodedOidSize`/`encodeOid`,
`CReader::readOid` and `CWriter::writeOid` each gained an `SRawOid` overload.
The string forms (`decodeOidString`, `encodeOidString`,
`encodedOidStringSize`, `readOidString`) are now implemented on top of them
rather than carrying their own conversion. `decodeOidString` in particular used
to have its own copy of the digit loop; there is now one formatter,
`SRawOid::toString()`, and having two formatters for one value is how they come
to disagree about the same OID -- which is exactly what had happened between
`CName`'s DN table and the OID it was describing.

`CEncoder::parseOidArcs` was made public so `SRawOid::parse()` reuses the one
tested parser instead of a second implementation of the leading-zero and
arc-width rules.

#### x509 no longer stores OIDs as strings

`IExtension::_oid`, `SCertRequestAttribute::oid`,
`CAccessDescription::_accessMethod`, `CPolicyInformation::_policyIdentifier`,
`CEkuExtension(Builder)::_purposes` and `CGeneralName`'s `registeredID` are
`COid`s now, and the twenty extension `static constexpr const char* OID`
constants in `include/certpp/x509/exts/*.hpp` are `static constexpr SKnownOid`
aliases of `COid::` constants -- same names, so call sites and tests keep
reading the way they did, but the OID appears once in the library rather than
twice. The tables in `cert.cpp` (`KEY_ALGOS`, `EC_CURVES`, `SIG_ALGOS`,
`RSA_SIG_OIDS`, `DSA_SIG_OIDS`, `ECDSA_SIG_OIDS`), `pfx.cpp`'s 23 anonymous-namespace
constants, and `ocspcodec.hpp`'s two are the same change. Every OID comparison
in the library is now on arcs; the dotted-decimal form is produced only where
an OID is displayed, which is `resolveKeyAlgo()`/`resolveSigAlgo()` falling
back to the OID's own text for an algorithm it has no name for.

`CCert::keyAlgo()` and `CCert::signAlgo()` were *not* migrated, and that is not
an oversight: they hold display names (`"RSA"`, `"EC"`,
`"sha256WithRSAEncryption"`), not OIDs. Converting them to `COid` was tried and
reverted -- the PEM writer dispatches on `keyAlgo().compare("RSA")`, and six
existing tests compare the same accessor against those names.

#### Three bugs found on the way

- **`CName::TYPE_OIDS` claimed `domainComponent` had ten arcs.** It is
  `0.9.2342.19200300.100.1.25` -- seven. The table had been padded with three
  zeros. Fixed in `src/name.cpp`, in the comments in `include/certpp/name.hpp`,
  and in `tests/name.cpp`.
- **`CString == COid(...)` compiles, and is always true.** This one is worth
  naming. `TString::operator==` takes `const TString&`, and the comparison
  reaches a `COid` through a conversion that has nothing to do with the OID's
  arcs. Written as `sigAlgoOid == COid(COid::RSASSA_PSS)` in
  `CCert::importDer()`, it held for every certificate: every self-signed
  certificate took the RSASSA-PSS branch, came out of `importDer()` carrying the
  digest algorithm that branch's defaults give rather than the one it was
  actually signed with, and then failed to verify against its own signature.
  The same shape was live in `crl.cpp` (every CRL-entry extension read as a
  reason code) and in `ocspcodec.cpp` (every OCSP extension read as a nonce);
  those two passed the suite only because nothing exercised either path with an
  extension that was *not* the one being recognized. All three now read into an
  `SRawOid` and hold a `COid`, so the comparison means what it says.
  `tests/oid.cpp` pins the behaviour both ways so the form cannot come back.
- **`pfx.cpp`'s OID writer emitted a doubly-wrapped OBJECT IDENTIFIER.** The
  file-local `encodeOid(const char*, CBuffer&)` produces content octets only,
  because `appendOid()` adds the tag and length. The `SKnownOid` overload added
  alongside it appended its own TLV, so `appendOid()` wrapped the result twice
  and the reader correctly rejected the content type. Found by instrumenting
  `load()`'s thirty-odd `return`s one at a time, since every one of them reports
  only `load() == ERET_OK`.

`src/oid.cpp` does not compile on either toolchain out of the box -- it carried
a redefinition of `SRawOid::operator=(SRawOid&&)` on GCC and of `COid::equals` on
MSVC, which is why the verification scripts used to move it aside. Both are
resolved; the scripts no longer need to.

Verified as 130/130 on all four configurations: GCC Release+ASan, GCC ASan,
MSVC Release, MSVC Debug.

#### Two paths that matched on the OID without checking it

The `CString == COid` trap fixed above was live in two more places, and neither
had a test that would have caught it -- because each file's other tests either
write no such extension at all, or write the one whose OID does match.

`tests/x509/crl.cpp` now builds a genuine CRL entry through `CCrlWriter`, with
a reason, and then changes exactly one thing about it: the reason code's OID
(`2.5.29.21`, content `55 1D 15`) to certificatePolicies (`2.5.29.32`, content
`55 1D 20`). Both encode to three content octets, so every length in the
encoding stays valid and the OID is the only variable. The entry must still
decode, and must report no reason. The test also decodes the unmodified
entry first and requires the reason to be there, so that "no reason" in the altered
case is a decision rather than a decode that never worked.

`tests/x509/ocsp.cpp` does the same to a response's nonce, retargeting
`id-pkix-ocsp-nonce` to `id-pkix-ocsp-basic` -- adjacent OIDs, differing only
in the last arc, so again nothing else in the encoding moves. What the bug
returned there was worse than a misread flag: a response carrying, say, a CRL
reference would have had that reference's bytes handed back as the request's
nonce, which is a replay-protection check answering with data it was never
asked for.

Both tests were confirmed to fail against the pre-fix code and pass against the
current code, which is the only claim worth making about a test added for a bug
that has already been fixed.

Writing these also corrected a wrong first attempt at them, which hand-built
the DER. The positive half of the CRL test failed for a reason that had nothing
to do with the OID under test, which is what it means for a hand-built fixture
to be testing the fixture rather than the code.

## `io/array`: a fixed TArray leaked the buffer it owned

← [History](../HISTORY.md)

`~TArray()` called `clear()` then `trimExcess()`, and `trimExcess()` returns
false immediately when `EARRAY_FIXED` is set -- before reaching its `delete[]`.
An array that had grown onto the heap and was then marked fixed therefore never
released that buffer. `wrap()` had the same defect for the same reason: it
cleared and trimmed the array before overwriting `_data`, so re-wrapping a fixed
array leaked the old buffer too.

Nothing observable was wrong with such an array. Size, capacity, type and
contents were all exactly right, and every assertion an ordinary test can make
about them passed. The whole suite had been run with
`ASAN_OPTIONS=detect_leaks=0`, which is what hid it.

The fix gives the destructor, and `wrap()`, a `releaseOwnedBuffer()` that hands
back whatever the array owns without regard for `EARRAY_FIXED`. That flag means
"refuse to reallocate", which is a statement about the array while it is in use
-- a destructor is not in use, and neither is a `wrap()` about to replace the
buffer outright. The ownership test is unchanged from `reserve()`/`trimExcess()`:
an `EARRAY_STATIC` array aliases a caller's memory and must not be freed, and
everything else is ours. `tests/io/array.cpp` covers both the leaking case and
the must-not-free-the-caller's-buffer case, since a fix that did the latter would
be worse than the leak.

The whole suite now passes under LeakSanitizer with detection enabled. Before
this, `io_array` did not.

## SHA-512 and SHA-384: a byte-swap, two shorter round functions, and a decomposition that says not to vectorise

← [History](../HISTORY.md)

`Sha2_64Core` built each big-endian message word one byte at a time -- eight
loads and seven shift-or pairs per word -- where x86-64's `BSWAP` and AArch64's
`REV` are one instruction. `loadBe64()` names those instructions behind a
portable loop for a compiler with neither. Sixteen `bswap` now appear in the
generated `transform()`, one per word, against three instructions of packing per
word where there were twenty-three. SHA-384 shares this core, so it gets both
changes.

`Ch` and `Maj` are in their shorter forms -- `g ^ (e & (f ^ g))` rather than
`(e & f) ^ (~e & g)`, which spends a `NOT` that x86-64 does not have, and
`((a | b) & c) | (a & b)` rather than a five-operation expression. Neither
changes an output bit.

Neither change was worth writing without first measuring which part of the
compression function costs anything. Decomposed per 128-byte block: packing
5.0%, message schedule 19.9%, **rounds 75.1%**. The roadmap's item 2 proposed
vectorising the schedule, and the argument for it -- that sixteen 64-bit words
fill exactly four 256-bit registers -- is correct. The schedule is 20% of a
function whose other 75% is a serial dependency chain, so it is not where the
2x lives.

SHA-512 333.5 -> 355.8 MiB/s, +6.7%, against an OpenSSL control that moved
-0.4%.

## GHASH: the subkey was being reflected once per 16 bytes

← [History](../HISTORY.md)

`Ghash::multiplyAccelerated` converts between GCM's bit-reflected convention
and the ordinary polynomial basis three times, twenty instructions each --
forty-five of its ninety-one instructions. One of the three is on `h`, the
subkey, which is fixed for the whole message. It was being re-reflected once
per 16 bytes of payload.

`reset()` now reflects it once into `_hReflected`, and `absorb()` uses that. The
other two conversions are on the block and on the product, both of which change,
so they stay -- but where GFNI is present each is one `GF2P8AFFINEQB` instead of
twenty. Which of the two applies is read from a CPUID-guarded static once per
message rather than twice per block, because a guarded static costs a load and a
test on every read and this runs every 16 bytes.

The public `Ghash::multiply()`, which takes a raw `h` and cannot use a prepared
copy, is unchanged in cost.

**310.9 -> 237.5 instructions per 16-byte block, 23.6% fewer**; AES-256-GCM
438.1 -> 494.1 MiB/s, +12.8%, against a control that moved -0.8%, with a
spread of 1.9% and 2.9% within each side. The instruction count is nearly
twice the clock, and that is the useful part:
what was removed was cheap, well-pipelined SSE2 shifting, while what remains is
latency-bound on a 5--7 cycle `PCLMULQDQ` chain.

This closes P2, which was closed once before on the grounds that "VPCLMULQDQ is
the only remaining path", with 4-block chaining measured 9--16% slower. That
negative result stands -- `VPCLMULQDQ` aggregates *independent* carry-less
multiplies, and GCM's per-block multiplies are one serial chain, so there is
nothing there to aggregate. What paid was not vectorising anything. It was
noticing that a quarter of the function was recomputing a constant.

The GFNI bit-reversal matrix is `0x8040201008040201`. It was first written as
`0x0102040810204080`, which is its transpose and computes the identity -- it
reversed nothing, and the GHASH field identities failed at once. Settled by
running every candidate against the SSE2 sequence that was already there and
already correct, over all 256 byte values in all 16 positions. MSVC declares the
GFNI intrinsics in `zmmintrin.h` rather than `immintrin.h`.

Verified 130/130 on GCC Release+ASan, GCC ASan, MSVC Release and MSVC Debug.

## The SHA-512 byte-swap's fallback branch: wrong, and nothing could have said so

← [History](../HISTORY.md)

`loadBe64()`'s `#else` branch -- the path for a compiler with no byte-swap intrinsic -- was
byte-reversing its input instead of assembling it big-endian. It was wrong for every one of
256 asymmetric patterns tried by hand. It also never ran.

That is the whole of the problem: as a branch inside an `#if`, it is compiled by none of the
four configurations this library ships, since GCC and MSVC both take a builtin. Four green
builds, 130/130 four times over, and a branch that has never produced a correct answer.

It is worth being precise about how it survived, because the first hand-check passed it. That
check filled all eight bytes with the same value, where a byte reversal and a big-endian
assembly agree, so it could not tell a correct implementation from this one. Only an
asymmetric pattern distinguishes them, and that is what the test now uses.

So the portable form is a function, `loadBe64Portable()`, public and always compiled, rather
than a branch that nothing builds. Being a function is what makes it testable at all.
`tests/crypto/hashers/sha512.cpp` holds it against a reference written a different way on
purpose -- indexing from the least significant byte and shifting right, where the function
under test indexes from the most significant and shifts left -- over every byte value in every
one of the eight positions. Verified to fail against the broken version, 2,345 of 2,364
assertions.

The builtins stay, because they are not decoration: GCC 13 turns the portable loop into
twenty-two instructions against the builtin's two (`movq`; `bswap`). Clang does recognise the
loop and compiles either form to three instructions, which is why this is spelled out per
compiler rather than left to the optimiser.

Nothing about the measured performance changes -- GCC and MSVC never took this branch, and
neither takes it now.
