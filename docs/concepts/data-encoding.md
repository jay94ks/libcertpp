# I/O and ASN.1

[한국어](data-encoding.ko.md)

## I/O and buffers

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`io/span.hpp`** defines `TSpan<T>` (mutable) and `TReadOnlySpan<T>`
  (read-only, implicitly constructible from a `TSpan<T>`) — non-owning
  views over contiguous memory, used throughout the library instead of a
  raw pointer+length pair. `SByteSpan`/`SReadOnlyByteSpan` alias the
  `uint8_t` instantiations (see
  [RULES.md](../rules/api.md#types) for the `T`- vs
  `S`-prefix rule this follows). Entirely templates, so it has no `.cpp`.
- **`io/array.hpp`** defines `TArray<T, TAllocator>`, an owning, growable array --
  `TSpan<T>`'s owning counterpart for arbitrary element types (`TString<T>`
  fills the same role specifically for character types). The allocator defaults
  to `SDefaultArrayAllocator`; every owned allocation, reallocation, and release
  goes through the selected allocator. `TSecureArray<T>` selects
  `SSecureArrayAllocator`, whose owned dynamic buffers use `CSecure` and receive
  at least 16-byte alignment. `CERTPP_DISABLE_SECURE_MEM=ON` redirects those
  allocations to the ordinary aligned heap. `wrap()` still aliases caller-owned
  storage, so the allocator cannot protect or wipe that external buffer. `EArrayType`
  tracks two orthogonal things in one `uint8_t`: a mutually-exclusive
  STATIC/DYNAMIC sub-type (`EARRAY_TYPE_MASK`, whether the array owns its
  heap allocation or -- via the static `wrap()` -- merely aliases a
  caller-supplied buffer it must never `delete[]`) and an independent
  `EARRAY_FIXED` flag (rejecting `reserve()`/`trimExcess()`/any
  `resize()`/`add()`/`insert()` that would need to grow past the current
  capacity). A non-fixed STATIC array transforms into DYNAMIC the first
  time it actually needs to grow -- whether that growth is requested
  directly via `reserve()` or indirectly via `resize()`/`add()`/`insert()`,
  since they all funnel through `reserve()` to make room; at that point it
  allocates its own buffer and stops aliasing the wrapped one, without
  freeing it, since it was never owned. `markFixed()` ORs `EARRAY_FIXED`
  into whichever sub-type is already set, a no-op on a still-`EARRAY_NONE` (freshly
  default-constructed, no elements ever added) array. Every mutating method
  (`add()`, `insert()`, `remove()`, `pop()`, `resize()`, `reserve()`,
  `trimExcess()`, `clear()`) manages element lifetimes manually via
  placement `new`/explicit `~T()` calls rather than assuming `T` is
  trivially constructible/destructible, the same manual-lifetime approach
  `COctet` and `TString<T>` take for their own element types. Entirely
  templates, so it has no `.cpp` -- like `TSpan<T>`.

  Three real bugs surfaced by writing `tests/io/array.cpp` against a
  lifetime-tracking element type (which flags a constructor/`operator=`
  call whose operand's lifetime had already ended, e.g. via a stale magic
  byte a destructor writes on its way out): `reserve()` only ever
  transitioned `EARRAY_STATIC` to `EARRAY_DYNAMIC`, and only when `_data`
  was already non-null -- so a plain default-constructed `TArray<T>()`
  (`EARRAY_NONE`) stayed stuck reporting `EARRAY_NONE` forever even after
  `add()`ing real elements, which made `empty()`/`operator bool()` (both of
  which treat `EARRAY_NONE` as empty regardless of size) permanently wrong
  for the single most common way to use this class; `insert()` shifted
  elements by move-constructing sources into place and destroying them,
  then plain-assigned (not placement-constructed) the new value into the
  vacated slot -- but that slot's object lifetime had already ended (its
  destructor ran as part of the shift, or -- for a pure append -- it was
  still the live default object `resize()` had just constructed there,
  which the fix must destroy before reusing), so the assignment (or, for
  the pure-append case, the following shift's placement-`new`) ran against
  either dead or still-live memory; and `markFixed()` masked `_type` with
  `~EARRAY_TYPE_MASK` before OR-ing in `EARRAY_FIXED`, wiping out the
  STATIC/DYNAMIC sub-type bits it should have left untouched (`EARRAY_FIXED`
  is a disjoint bit needing no such mask, unlike `reserve()`/`trimExcess()`'s
  legitimate "replace the sub-type" pattern the code had evidently been
  copied from). A fourth, unrelated bug -- an inverted `resize()`
  short-circuit (`!(_type & EARRAY_FIXED) && !reserve(size)` instead of
  `(_type & EARRAY_FIXED) || !reserve(size)`) that skipped the capacity
  check entirely for a fixed array needing to grow, letting `add()`/
  `resize()` placement-`new` past the end of `_cap` -- was caught by the
  same test suite once the other three were fixed and it could run
  cleanly.
- **`io/buffer.hpp` / `src/io/buffer.cpp`** define `CBuffer` and
  `CSecureBuffer`, owning, resizable raw byte buffers: `resize()`, `store()`, `toPtr()` for the raw
  pointer, and `toSpan()` to hand it on. It is the *working* buffer of the
  three byte containers here, and the distinction between them is
  load-bearing enough that
  [`RULES.md`](../RULES.md)'s "Buffer handling"
  section legislates it: `CBuffer` is what a result is assembled in
  (resize once, `memcpy`/`memset` into it, read it back), `COctet` is what a
  finished fixed-length result is kept in, and `TArray<T>` is for sequences
  of genuinely distinct elements rather than bytes. Nearly every `encode()`/
  `build()` in the library accumulates into a `CBuffer` and converts to a
  `COctet` at the end. Two sharp edges worth knowing: `resize()` preserves
  existing content but does **not** zero the bytes it adds (unlike
  `TArray<uint8_t>`), and it returns `bool` -- a caller that ignores it and
  then writes through `toPtr()` is writing out of bounds on an allocation
  failure. `CSecureBuffer` has the same value and move contract but routes
  every owned allocation through `CSecure`; the default build therefore keeps
  it in locked page-backed memory and wipes it on release. Its storage is at
  least 16-byte aligned for SIMD consumers. `CERTPP_DISABLE_SECURE_MEM=ON`
  keeps the type and API but makes `CSecure` use ordinary aligned heap memory.
- **`utils/base64.hpp` / `src/utils/base64.cpp`** define `CBase64`, which is
  both halves of a base64 codec in one class: an incremental transform
  (`push()`/`finish()`, with an `EBase64Mode` fixing the direction --
  `EB64M_ENCODE`, `EB64M_ENCODE_BR` for PEM-style line breaking at
  `LINE_LENGTH`, `EB64M_DECODE` -- and internal `MAX_BUFFER` chunking), and
  static one-shot `encode()`/`decode()` for a whole buffer at once. The
  decoder is deliberately lenient about `=` padding and whitespace, which is
  what makes it usable on PEM blocks as they actually appear in the wild;
  `CCert::importPem()`/`exportPem()` are its main consumers. Note
  `io/base64.hpp` is **not** this: it is an empty placeholder header that
  declares nothing and that `certpp.hpp` deliberately does not include.
- **`utils/json.hpp` / `src/utils/json.cpp`** define `CJson`, a JSON value
  tree for null, booleans, numbers, strings, arrays and objects. `parseJson()`
  accepts exactly one complete JSON value; `toString()` escapes strings and
  object keys, preserves finite `double` round trips, and emits `null` for
  non-finite numbers or values beyond its depth limit. `toBson()` and
  `parseBson()` encode/decode BSON documents, including nested objects and
  arrays, booleans, strings, nulls, doubles and BSON integers (converted to
  `double`); unsupported BSON types are rejected. BSON scalar roots cannot be
  encoded. JSON is included by `certpp.hpp` unless `CERTPP_WITHOUT_JSON` is
  enabled; that option also omits `json.hpp` from installation and skips
  `tests/utils/json.cpp`.
- **`io/octet.hpp` / `src/io/octet.cpp`** define `COctet` and
  `CSecureOctet`, owning, fixed-size byte buffers (not resizable/growable,
  unlike `TString<T>`) --
  `store()` replaces its content (copying and taking ownership; a null
  pointer or zero size is rejected and leaves prior content untouched, so a
  failed `store()` can't corrupt an existing instance), `clear()` releases
  it, and `toSpan()`/`toPtr()` give read-only access. Copy construction/
  assignment deep-copy. Move *construction* transfers ownership and leaves
  the source empty; move *assignment* swaps instead, so the source ends up
  holding whatever the target had -- the project-wide convention described
  under `io/array.hpp` below, which keeps a self-move safe and leaves the
  old buffer to be freed by the source's own destructor. `COctet::secureClear()`
  wipes one ordinary allocation on request. `CSecureOctet` instead routes its
  full lifetime through `CSecure`, so retained secret bytes stay protected and
  are wiped automatically in the default build; the disable option has the
  same ordinary-heap meaning described for `CSecureBuffer`.
- **`io/stream.hpp` / `src/io/stream.cpp`** define `IStream`, the
  read/write/seek stream interface (capability-queried via
  `capabilities()`/`EStreamCapability`, optional operations like
  `trimExcess()`/`length(newLen)`/`flush()` default to `ERET_NOTIMPL` rather
  than being pure virtual), plus the `IStream::createMemory(...)` factory
  functions. The `.cpp` only implements the factories; the concrete
  in-memory implementation is `MemStream`, a private class under
  `src/io/` (`memstream.hpp`/`.cpp`) that is not exposed through
  `include/certpp/` (`MemStream::write()` returned 0 on every successful
  write instead of the byte count -- a real bug, since that return value is
  the only way `IStream::write()`'s contract lets a caller detect a short or
  failed write; fixed when `CWriter` started depending on it) — see
  [RULES.md](../RULES.md#internal-implementation-headers)
  for why it lives there and how its header guard/include differ from a
  public header.

## ASN.1

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`asn1/tag.hpp` / `src/asn1/tag.cpp`** define `CTag`, an ASN.1 tag
  (class + constructed flag + tag number), with `decode()`/`encode()`
  to/from a `TReadOnlySpan<uint8_t>`/`TSpan<uint8_t>`, plus `ETagClass` and
  `EUniversalTags` for the standard tag classes/universal tag numbers.
- **`asn1/decoder.hpp` / `src/asn1/decoder.cpp`** define `CDecoder`, static
  methods for decoding ASN.1 data (`EEncodingRule` selects BER/CER/DER;
  `EDecoderStatus` reports why a decode failed), split into two layers:
  - **TLV framing** (tag-agnostic): `readEncodedValue()` reads a full
    tag-length-value, handling both definite-length values and BER/CER
    indefinite-length values (resolved by scanning nested values for the
    end-of-contents marker, bounded by a `MAX_NESTING_DEPTH` guard so a
    maliciously deep indefinite-length nesting can't exhaust the stack).
    `readNextElement()` layers a cursor on top of it to iterate a
    SEQUENCE/SET's members.
  - **Content decoding** (tag-independent, so these work whether the
    caller's tag was the plain universal one or an IMPLICIT/context-specific
    one): `decodeBoolean()`, `decodeInteger()`, `decodeEnumerated()`,
    `decodeNull()`, `decodeOctetString()`, `decodeBitString()` +
    `testNamedBit()` (NamedBitList, e.g. X.509 KeyUsage), `decodeOid()` +
    `countOidArcs()`/`decodeOidString<TChar>()` (the latter formats the arcs
    as dotted-decimal text, e.g. "1.2.840.113549.1.1.1", into a
    `TString<TChar>` -- purely ASCII digits/`.`, so it's locale-independent
    for both `TChar`s, unlike `decodeString<TChar>()`),
    `decodeText()`/`decodeString<TChar>()` (validates
    UTF8String/PrintableString/IA5String/NumericString charsets; other
    string tags pass through -- `decodeString<TChar>()` additionally
    transcodes into a `TString<TChar>` via `TUtf8Encoding<TChar>`), and
    `decodeUtcTime()`/`decodeGeneralizedTime()` (into an `SDateTime`), and
    `decodeDistinguishedName()` (into a `CDistinguishedName`, from a
    SEQUENCE's content octets -- see below for the exact structure expected).
    These take just the value's content octets (an outer `readEncodedValue()`
    call's `outArea`), not the tag+length header. `decodeOctetString()` and
    `decodeBitString()` each have a `COctet&` overload alongside their
    `SReadOnlyByteSpan&` one, copying the content into an owning `COctet`
    instead of aliasing the source buffer.

  `decodeDistinguishedName()` parses an X.501 Name/RDNSequence: each content
  element must be a SET (RelativeDistinguishedName) containing exactly one
  AttributeTypeAndValue (SEQUENCE { type OBJECT IDENTIFIER, value ANY }) --
  a multi-valued RDN is rejected outright, since `CDistinguishedName` only
  ever holds one `CName` per `ENameType`, so keeping just the first value
  and silently dropping the rest would be the wrong failure mode. `type`
  must resolve via `CName::attributeTypeOf()` -- an attribute type it can't
  name fails the whole `Name`, which is why one `organizationIdentifier`
  used to make a real EU-regulated certificate unimportable, and why
  `ENameType` had to grow rather than the decoder learn to skip (dropping an
  unnamed attribute would make two different DNs compare equal, and DN
  equality is what `CCertCollection::buildChain()` uses to match issuer and subject);
  `value` must be a PrintableString, UTF8String or IA5String (the three kinds
  `CEncoder::encodeDistinguishedName()` ever writes -- see below), decoded via
  `decodeString<wchar_t>()` and converted to narrow via
  `TString<wchar_t>::convertTo<char>()` before constructing the `CName`
  (mirroring `CDistinguishedName::tryParse(CWideString)`'s same conversion
  path). Always applies DER's rules regardless of the enclosing document's
  rule set, since X.501 Names are encoded with DER in practice even inside
  a BER/CER document -- so, unlike `readEncodedValue()`, it doesn't take an
  `EEncodingRule` parameter.

  `decoder.hpp` also hosts `EEncodingRule`/`checkEncodingRule` and the
  CER-segment-limit check (`CER_MAX_SEGMENT`/`exceedsCerSegmentLimit`),
  since both the decoder and `CEncoder` need them.
- **`asn1/encoder.hpp` / `src/asn1/encoder.cpp`** define `CEncoder`, the
  write-side counterpart, mirroring `CDecoder`'s two layers:
  - **TLV framing**: `writeEncodedValue()` writes a tag-length-value using
    definite-length form (valid under all three rule sets; BER/CER's
    optional indefinite-length form is never produced), and
    `encodedValueSize()` sizes a destination buffer up front.
    `writeSequenceOf()`/`writeSetOf()` build a SEQUENCE/SET's content by
    concatenating already-encoded children; `writeSetOf()` additionally
    reorders them into CER/DER's canonical ascending order first (valid
    under BER too, so it's always applied).
  - **Content encoding**: `encodeBoolean()`, `encodeInteger()`,
    `encodeEnumerated()`, `encodeNull()`, `encodeOctetString()`,
    `encodeBitString()` + `encodeNamedBitList()` (trims trailing zero bits
    per X.690 11.2.2), `encodeOid()` + `encodedOidSize()`,
    `encodeOidString<TChar>()` + `encodedOidStringSize<TChar>()` (the
    inverse of `decodeOidString<TChar>()`: parses a dotted-decimal
    `TString<TChar>` via the private `parseOidArcs<TChar>()` helper, then
    encodes exactly like `encodeOid()`),
    `encodeText()`/`encodeString<TChar>()` (the inverse of
    `decodeText()`/`decodeString<TChar>()`, validating via `decodeText()`
    after transcoding a `TString<TChar>` to UTF-8) + `encodedStringSize<TChar>()`,
    `encodeUtcTime()`/`encodeGeneralizedTime()` (+
    `encodedGeneralizedTimeSize()`, since its length varies with whether
    there's a fractional-seconds part), and `encodeDistinguishedName()` (+
    `encodedDistinguishedNameSize()`; see below). `encodeOctetString()` and
    `encodeBitString()` each have a `const COctet&` overload too, a thin
    wrapper over the `SReadOnlyByteSpan` one via `COctet::toSpan()`. These
    always emit DER-canonical value encoding (minimal-length integers,
    `0xFF`/`0x00` booleans, ...) — a free choice for a writer, and canonical
    form is valid BER/CER too, so
    none of them take an `EEncodingRule` parameter.

  `encodeDistinguishedName()` is the inverse of `decodeDistinguishedName()`:
  one RDN (SET) per component, in the `CDistinguishedName`'s ascending
  `ENameType` order (`std::map`'s own iteration order), each containing
  exactly one AttributeTypeAndValue -- `type` from `CName::attributeOid()`,
  `value` from the component's *unescaped* text
  (`CName::toString<wchar_t>(false)`) encoded via `encodeString<wchar_t>()`
  (genuine, locale-independent UTF-8), tried first as a PrintableString and,
  only if that charset check fails, as a UTF8String instead. `ENAME_DC` is
  the one exception: RFC 4519 2.4 gives `domainComponent` IA5String as its
  syntax with no alternative, so it is written that way and fails outright
  rather than falling back. The private
  `buildAttributeTypeAndValue()`/`buildDistinguishedNameContent()` helpers
  build the full nested TLV bytes into a scratch `TArray<uint8_t>`
  bottom-up (OID TLV + value TLV -> AttributeTypeAndValue SEQUENCE TLV ->
  RDN SET TLV -> concatenated RDNSequence content); `encodedDistinguishedNameSize()`
  and `encodeDistinguishedName()` both call the same private helper (so they
  can never disagree on what gets encoded) and just differ in whether the
  result is measured or copied into the caller's destination. An empty
  (no-component) `CDistinguishedName` encodes successfully to zero content
  octets (an empty SEQUENCE) -- as with `encodedStringSize()`, a `0` return
  from the size-only helper is ambiguous between "empty" and "unencodable";
  call `encodeDistinguishedName()` directly and check its return value to
  tell them apart. Like the decoder side, always applies DER's rules and
  takes no `EEncodingRule` parameter.
- **`asn1/reader.hpp` / `src/asn1/reader.cpp`** define `CReader`, which pairs
  `CDecoder`'s content-level `decode*()` methods with stream/cursor
  management, so a caller doesn't hand-roll `readNextElement()` +
  `decode*()` for every field. Constructed from an `IStream`, it reads from
  it lazily: `growBuffer()` pulls one more chunk into an owned `COctet` only
  when a parse attempt actually runs out of buffered data, rather than
  reading the whole stream up front, so data written to the stream after
  construction (but before it's needed) is still visible. `CDecoder` still
  needs a contiguous span per attempt (and BER/CER indefinite-length parsing
  requires scanning ahead), so growth itself isn't avoidable, just its
  timing; constructed from a span directly (e.g. a parent element's already
  fully-buffered content), there's no stream to grow from, so it simply
  aliases the span. Since `growBuffer()` reallocates `COctet` (which frees
  the old allocation), a plain saved `SReadOnlyByteSpan` cursor snapshot can
  go stale mid-call -- every method that needs to roll back the cursor on
  failure goes through the private `withRollback()` helper, which tracks a
  `_generation` counter bumped on each reallocation and reconstructs the
  correct rollback target (the saved span if nothing grew, or the whole
  current buffer if it did, since `growBuffer()` always rebuilds it from
  exactly the saved span's unconsumed bytes plus newly-read ones) instead of
  trusting a potentially-dangling saved pointer. Because of this owned,
  on-demand-reallocated buffer, `CReader` is move-only (copying would leave
  the copy's cursor pointing into the source's buffer). Every typed
  `readBoolean()`/`readInteger()`/
  `readEnumerated()`/`readNull()`/`readOctetString()`/`readBitString()`
  (`SReadOnlyByteSpan` and `COctet` overloads)/`readOid()`/
  `readOidString<TChar>()`/`readText()`/`readString<TChar>()`/
  `readUtcTime()`/`readGeneralizedTime()` reads the next element expecting
  a specific plain UNIVERSAL, *primitive* tag (rejecting a constructed
  encoding too, since none of `CDecoder`'s content-level decoders
  reassemble constructed/segmented BER/CER strings) -- on any mismatch or
  decode failure, the cursor is left exactly where it was, so a caller can
  try a different read or treat an OPTIONAL/DEFAULT field as absent.
  `readDistinguishedName()` follows the same tag-mismatch-leaves-cursor-alone
  contract, but expects a *constructed* SEQUENCE (like `readSequence()`) and
  fully decodes it via `CDecoder::decodeDistinguishedName()` rather than
  returning a nested `CReader`, since a `CDistinguishedName` is a complete
  value in its own right, not something a caller iterates member-by-member.
  `readSequence()`/`readSet()`/`readConstructed()` return a nested `CReader`
  over a constructed value's content, for descending into SEQUENCE/SET (or,
  for `readConstructed()`, any other constructed tag, e.g. a
  context-specific `[n]` EXPLICIT wrapper). The low-level
  `readNextElement()` underlies all of these and is the escape hatch for
  IMPLICIT-tagged or CHOICE content the typed methods can't recognize by
  their plain universal tag.
- **`asn1/writer.hpp` / `src/asn1/writer.cpp`** define `CWriter`, the
  write-side counterpart: each typed `writeBoolean()`/`writeInteger()`/...
  method encodes its content into a scratch buffer via the matching
  `CEncoder::encode*()`, then writes the full tag-length-value to the
  stream via `writeElement()` (`CEncoder::writeEncodedValue()` under the
  hood), verifying the stream reports writing every byte. `writeSequence()`/
  `writeSet()` mirror `CEncoder::writeSequenceOf()`/`writeSetOf()` exactly
  (an array of already-encoded children) rather than introducing a new
  nested-builder API; build each child with `CEncoder` (or a nested
  `CWriter` over its own memory stream) first, exactly as the existing
  `CEncoder`-only tests already do. `writeDistinguishedName()` follows the
  same scratch-buffer-then-`writeElement()` pattern as the other typed
  writes, sizing the buffer via `CEncoder::encodedDistinguishedNameSize()`
  and filling it via `CEncoder::encodeDistinguishedName()`, then writing it
  under the SEQUENCE tag. Unlike `CReader`, `CWriter` only holds
  an `IStreamPtr` + `EEncodingRule`, so it's freely copyable.
