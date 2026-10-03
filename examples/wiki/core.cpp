#include <certpp.hpp>

using namespace certpp;

// === SVersion ===
// Compares the header the caller compiled against with the library actually loaded.
void exampleSVersion() {
    SVersion lib = GetLibraryVersion();
    if (lib != HEADER_VERSION) {
        // built against one version of the headers, linked against another
    }
}

// === TArray ===
// Collects bytes into a growable TArray<uint8_t>, the array type the library's own byte-producing
// calls fill. Every growing call reports failure with a bool rather than throwing, and reserve()
// up front turns one reallocation per add() into one in total.
void exampleTArray(SReadOnlyByteSpan source) {
    TArray<uint8_t> bytes;
    if (!bytes.reserve(source.size)) {
        return;
    }

    for (size_t i = 0; i < source.size; ++i) {
        if (!bytes.add(source.data[i])) {
            return;
        }
    }

    // A leading zero byte is not part of an unsigned magnitude; remove() shifts the tail down
    // and reports false only for an out-of-range index.
    while (bytes.size() > 1 && bytes[0] == 0x00) {
        if (!bytes.remove(0)) {
            return;
        }
    }
}

// === CBuffer ===
// Allocates a resizable byte buffer and hands its storage to a callee as a span. resize() keeps
// the bytes already there but leaves the bytes it adds uninitialized, so fill() is what makes a
// grown buffer defined.
void exampleCBuffer(SReadOnlyByteSpan source) {
    CBuffer work;
    if (!work.resize(source.size + 16)) {
        return;
    }

    if (!work.fill(0x00)) {
        return;
    }

    SByteSpan out = work.toSpan();
    const size_t copied = source.copyTo(out);

    // work.size() is still source.size + 16 here: a buffer's size is the capacity it was given,
    // never what a callee actually wrote into it.
    if (copied != source.size) {
        work.clear();
    }
}

// === COctet ===
// Takes a private copy of a blob that only lives as long as the caller's span. store() reports
// false for a null or zero-length source and leaves whatever the octet already held, so an empty
// input has to go through clear() instead of store().
void exampleCOctet(SReadOnlyByteSpan der) {
    COctet owned;
    if (der.empty()) {
        owned.clear();
    } else if (!owned.store(der)) {
        return;
    }

    if (!owned) {
        return;
    }

    // toSpan()/toPtr() are views into the octet's own allocation, valid only while it lives.
    SReadOnlyByteSpan view = owned.toSpan();
    if (view.size > 1 && view[0] == 0x30) {
        // a SEQUENCE tag: this looks like DER
    }
}

// === TReadOnlySpan ===
// SReadOnlyByteSpan is the alias a caller names for an immutable, non-owning view. Its operator==
// compares the pointer and the size, not the bytes -- comparing contents is sequencialEqual(),
// and for anything secret it is CSecure::equals().
void exampleTReadOnlySpan(SReadOnlyByteSpan first, SReadOnlyByteSpan second) {
    if (first.empty() || second.empty()) {
        return;
    }

    if (first == second) {
        // the very same buffer, not merely equal bytes
    }

    if (first.sequencialEqual(second)) {
        // equal contents, wherever they live
    }

    // slice() clamps to what is there instead of running off the end, so an over-long length or
    // an offset past the end yields a shorter or empty span rather than a wild read.
    SReadOnlyByteSpan body = first.slice(2);
    if (body.size >= 4 && body.slice(0, 4).sequencialEqual(second.slice(0, 4))) {
        // the two share a 4-byte prefix after the first's first two bytes
    }
}

// === TSpan ===
// SByteSpan is the mutable alias a caller names, and it carries capacity, not length: the span
// over a 64-byte buffer keeps reporting 64 until something narrows it. Track what was written
// and slice() down to that.
void exampleTSpan(SReadOnlyByteSpan source) {
    uint8_t buf[64];
    SByteSpan out(buf, sizeof(buf));
    out.clear();

    const size_t written = source.copyTo(out);
    if (written == 0) {
        return;
    }

    // out.size is still 64 -- copyTo() reports a length, it does not narrow the span. Pass the
    // narrowed span onward, not `out`, or everything downstream reads the padding too.
    SByteSpan used = out.slice(0, written);
    const SDjbValue tag = CDjb::compute(used);
    if (tag == 0) {
        return;
    }

    CSecure::zero(out);   // the whole buffer, padding included
}

// === ESeekMode ===
// Selects what a seek() offset is measured from. ESEEK_END with a negative offset reads a
// trailer without first asking for the stream's length; every mode clamps into [0, length]
// rather than parking the position out of range.
void exampleESeekMode(const IStreamPtr& stream) {
    if (!stream || (stream->capabilities() & ESTREAM_SEEK) == 0) {
        return;
    }

    if (stream->seek(-4, ESEEK_END) != ERET_OK) {
        return;
    }

    uint8_t trailer[4] = {};
    if (stream->read(trailer, sizeof(trailer)) != sizeof(trailer)) {
        return;
    }

    // ESEEK_CUR is relative to where that read left the position, so this re-reads the same
    // four bytes; ESEEK_SET would be relative to the start.
    if (stream->seek(-4, ESEEK_CUR) != ERET_OK) {
        return;
    }
}

// === EStreamCapability ===
// A bitmask of what a stream supports, not a single value: test the bit you are about to rely
// on. A memory stream reports all three, but a stream handed in from elsewhere may be read-only
// or unseekable, and the calls it cannot do fail at run time rather than at compile time.
void exampleEStreamCapability(const IStreamPtr& stream) {
    if (!stream) {
        return;
    }

    const uint32_t caps = stream->capabilities();
    if ((caps & ESTREAM_WRITE) == 0) {
        return;
    }

    const uint8_t marker[] = { 0x30, 0x82 };
    if (stream->write(marker, sizeof(marker)) != sizeof(marker)) {
        return;
    }

    // Reading back what was just written needs both bits, not just ESTREAM_READ.
    const uint32_t both = uint32_t(ESTREAM_READ | ESTREAM_SEEK);
    if ((caps & both) == both && stream->seek(0, ESEEK_SET) != ERET_OK) {
        return;
    }
}

// === IStream ===
// Obtains a stream from the IStream::createMemory() factory, which is the only way to get one.
// createMemory() with no argument starts empty, and a write leaves the position at the end --
// so reading back what you just wrote needs an explicit seek(), unlike the span overload, which
// starts already rewound.
void exampleIStream(SReadOnlyByteSpan content) {
    IStreamPtr stream = IStream::createMemory();
    if (!stream) {
        return;
    }

    if (stream->write(content.data, content.size) != content.size) {
        return;
    }

    if (stream->seek(0, ESEEK_SET) != ERET_OK) {
        return;
    }

    uint8_t head[8] = {};
    SByteSpan into(head, sizeof(head));
    const size_t got = stream->read(into);
    if (got == 0) {
        return;   // a short read reports the count; there is no error code on read()
    }

    if (stream->close() != ERET_OK) {
        return;
    }
}

// === CDistinguishedName ===
// Parses a "CN=..., O=..., C=..." distinguished name and reads one component back. tryParse()
// fails outright on an attribute type it does not recognize rather than dropping it: a dropped
// attribute would make two genuinely different names compare equal, and DN equality is what
// matches an issuer to a subject.
void exampleCDistinguishedName(const CString& text) {
    CDistinguishedName dn;
    if (!CDistinguishedName::tryParse(dn, text)) {
        return;
    }

    CName cn;
    if (!dn.tryGet(ENAME_CN, cn)) {
        return;
    }

    // trySet() refuses to replace a component that is already present unless told to overwrite,
    // so the second argument is not optional once the name came from somewhere else.
    if (!dn.trySet(CName(ENAME_O, "Example Corp"), true)) {
        return;
    }

    CString rendered;
    dn.toString(rendered);
}

// === CName ===
// Builds one DN attribute and renders it. A CName stores non-ASCII bytes escaped internally;
// toString(out, false) undoes that and gives the original bytes back, while toString(out, true)
// shows the stored form -- so the default is what you want for display.
void exampleCName(const CString& value) {
    CName cn(ENAME_CN, value.toPtr(), value.size());
    if (!cn) {
        return;   // a null or empty input yields an empty CName, not a reported failure
    }

    CString plain;
    cn.toString(plain, false);

    // equals() short-circuits on the precomputed DJB hash before comparing bytes, so it is the
    // cheap comparison; compare() is the ordering one.
    CName other(ENAME_CN, "example.com");
    if (cn.equals(other)) {
        // same type and same value
    }

    if (CName::typeOf(CName::keyOf(cn.type())) != cn.type()) {
        return;   // key <-> type is a round trip for every recognized attribute
    }
}

// === IStringEncoding ===
// Obtained from an encoding's get() factory, never constructed directly. Call measure() first:
// the number of bytes an encoding needs is not the number of characters it was handed, for
// anything outside ASCII.
void exampleIStringEncoding(const CString& text) {
    IStringEncoding<char>& enc = TUtf8Encoding<char>::get();

    TReadOnlySpan<char> src = text.toSpan();
    const size_t needed = enc.measure(src);
    if (needed == 0) {
        return;
    }

    CBuffer out;
    if (!out.resize(needed)) {
        return;
    }

    const size_t written = enc.encodeTo(out.toSpan(), src);
    if (written == 0) {
        return;   // 0 is the failure report; there is no error code here
    }

    // written, not needed, is the length to carry forward.
    COctet encoded;
    if (!encoded.store(out.toPtr(), written)) {
        return;
    }
}

// === TAsciiEncoding ===
// The 1:1 encoding for the ASCII-only X.509 string types (PrintableString, IA5String). It
// sanitizes instead of failing -- any character above 127 is written out as a space -- so if
// "not representable" has to be an error, check the input yourself before encoding it.
void exampleTAsciiEncoding(const CString& text) {
    IStringEncoding<char>& enc = TAsciiEncoding<char>::get();

    TReadOnlySpan<char> src = text.toSpan();
    if (src.empty()) {
        return;
    }

    for (size_t i = 0; i < src.size; ++i) {
        if (static_cast<unsigned char>(src[i]) > 127) {
            return;   // would silently become ' '
        }
    }

    uint8_t bytes[CName::MAX_LEN];
    SByteSpan dst(bytes, sizeof(bytes));
    const size_t written = enc.encodeTo(dst, src);
    if (written != src.size) {
        return;   // input longer than dst: encodeTo() clamps rather than reporting overflow
    }
}

// === TString ===
// CString is the alias a caller names (CWideString for wchar_t). size() excludes the
// terminator, find() returns an offset_t that is negative when there is no match, and the
// growing calls report allocation failure with a bool.
void exampleTString(const CString& subject) {
    CString line("CN=");
    line.append(subject);

    const offset_t eq = line.find('=');
    if (eq < 0) {
        return;
    }

    CString value = line.subString(static_cast<size_t>(eq) + 1);
    if (value.empty()) {
        return;
    }

    if (value.compareIgnoreCase(value.toUpper()) != 0) {
        return;
    }

    // convertTo() transcodes through TStringConverter rather than truncating each unit.
    CWideString wide = value.convertTo<wchar_t>();
    if (wide.empty()) {
        return;
    }
}

// === TStringConverter ===
// Transcodes between char and wchar_t one span at a time -- what TString::convertTo() uses
// underneath. The template arguments are <destination, source> in that order, and measure() has
// to run before convert() because the destination length is not the source length.
void exampleTStringConverter(const CString& narrow) {
    TStringConverter<wchar_t, char> conv;

    TReadOnlySpan<char> src = narrow.toSpan();
    const size_t units = conv.measure(src);
    if (units == 0) {
        return;
    }

    CWideString wide;
    if (!wide.resize(units)) {
        return;
    }

    // An instance carries an mbstate_t, so one converter belongs to one conversion: reuse it
    // for a second, unrelated string and it resumes mid-sequence.
    TSpan<wchar_t> dst = wide.toSpan();
    const size_t converted = conv.convert(dst, src);
    if (converted != units) {
        wide.clear();
    }
}

// === TStringFunctions ===
// The raw-pointer string primitives TString and CName are built on, usable directly when you
// have a pointer and a length instead of a TString. Everything here takes an explicit size and
// never looks for a terminator -- countOf() is the one call that does.
void exampleTStringFunctions(const char* header) {
    using Fn = TStringFunctions<char>;

    const size_t len = Fn::countOf(header);
    if (len == 0) {
        return;   // also what a null pointer reports, rather than crashing
    }

    const offset_t colon = Fn::find(header, len, ':');
    if (colon < 0) {
        return;
    }

    // caseCmp() compares exactly the count it is given and does not stop at a terminator, so
    // the length has to be checked first, not inferred from the result.
    const size_t nameLen = static_cast<size_t>(colon);
    if (nameLen != 12 || Fn::caseCmp(header, "content-type", nameLen) != 0) {
        return;
    }
}

// === TUtf8Encoding ===
// The UTF-8 codec X.509's UTF8String fields go through. measure() is what sizes the
// destination: for wchar_t the byte count and the character count differ, so sizing from the
// source's own length truncates every string with a non-ASCII character in it.
void exampleTUtf8Encoding(const CWideString& text) {
    IStringEncoding<wchar_t>& enc = TUtf8Encoding<wchar_t>::get();
    TReadOnlySpan<wchar_t> src = text.toSpan();

    CBuffer utf8;
    const size_t bytes = enc.measure(src);
    if (bytes == 0 || !utf8.resize(bytes)) {
        return;
    }

    if (enc.encodeTo(utf8.toSpan(), src) != bytes) {
        return;
    }

    // Going back the other way, decodeFrom() reports characters written, not bytes consumed --
    // and it takes its destination by non-const reference, so it needs a named span.
    CWideString back;
    if (!back.resize(src.size)) {
        return;
    }

    TSpan<wchar_t> dst = back.toSpan();
    if (enc.decodeFrom(dst, utf8.toSpan()) != src.size) {
        back.clear();
    }
}

// === SDateTime ===
// Reads the current time and checks it against a validity bound. now() and from() default to
// *local* time -- pass true for UTC, which is the only form X.509 encodes and the only one the
// two sides of a comparison can safely share.
void exampleSDateTime(const SDateTime& notAfter) {
    if (notAfter.isZero()) {
        return;   // the field was absent, or never decoded
    }

    const SDateTime now = SDateTime::now(true);
    const SDateTime bound = notAfter.isUtc ? notAfter : notAfter.toUtc();

    if (now.toMilliseconds() > bound.toMilliseconds()) {
        return;   // already expired
    }

    const STimeSpan left = bound.diff(now);
    if (left.totalDays() < 30) {
        // renew soon
    }
}

// === STimeSpan ===
// A signed duration in milliseconds. Every accessor is taken from absolute(), so totalDays() of
// a negative span comes back positive -- the sign survives only in the milliseconds field, which
// is what to test when the direction is the thing you care about.
void exampleSTimeSpan(const SDateTime& notBefore, const SDateTime& notAfter) {
    const STimeSpan validity = notAfter.diff(notBefore);
    if (validity.milliseconds <= 0) {
        return;   // notAfter is not actually after notBefore; totalDays() would not have shown it
    }

    if (validity.totalDays() > 398) {
        return;   // longer than a public TLS certificate is allowed to live
    }

    // Arithmetic is plain +/-; a literal is implicitly a millisecond count.
    const STimeSpan skew(5 * 60 * 1000);
    const SDateTime earliest = notBefore.subtract(skew);
    if (earliest.isZero()) {
        return;
    }
}

// === CBase64 ===
// Streams bytes through the incremental Base64 encoder. finish() may need more than one call:
// it returns how many bytes it produced, and a non-zero return means there may be more, so it
// has to be drained in a loop before the output is complete.
void exampleCBase64(SReadOnlyByteSpan der) {
    CBase64 b64(EB64M_ENCODE_BR);

    uint8_t out[4096];
    SByteSpan whole(out, sizeof(out));

    size_t total = b64.push(der, whole);
    if (b64.state() != ERET_OK) {
        return;   // ERET_NOSPC means `whole` was too small; retrying bigger works, no reset()
    }

    size_t more = 0;
    do {
        SByteSpan tail(out + total, sizeof(out) - total);
        more = b64.finish(tail);
        total += more;
    } while (more > 0);

    if (b64.state() != ERET_OK) {
        return;
    }

    CString pem(reinterpret_cast<const char*>(out), total);
}

// === EBase64Mode ===
// Picks what a CBase64 object does, and for encoding it also picks whether the output wraps. A
// PEM body needs the 64-column breaks EB64M_ENCODE_BR inserts; EB64M_ENCODE emits one unbroken
// line, which is right for a URL or an HTTP header and wrong inside a PEM block.
void exampleEBase64Mode(SReadOnlyByteSpan der, bool forPem) {
    CString body;
    if (!CBase64::encode(body, der, forPem)) {
        return;
    }

    // The streaming form takes the same choice as a mode, and reset(mode) switches an existing
    // object over instead of building a second one.
    CBase64 codec(forPem ? EB64M_ENCODE_BR : EB64M_ENCODE);
    if (codec.mode() != EB64M_DECODE) {
        codec.reset(EB64M_DECODE);
    }

    // Decoding ignores line breaks either way, so the wrap choice above costs nothing here.
    CBuffer raw;
    if (!CBase64::decode(raw, body)) {
        return;
    }
}

// === CBigNum ===
// Modular arithmetic on an arbitrary-precision unsigned integer. add/sub/mul/mod/mulMod mutate
// the value they are called on and return it only so calls can be chained, so a caller that
// still needs the original has to copy it first -- the most common way to corrupt a computation
// with this class.
void exampleCBigNum(const CBigNum& base, const CBigNum& modulus) {
    CBigNum product = base;             // copy: base itself has to survive this
    product.mulMod(CBigNum(3), modulus);

    CBigNum inverse;
    if (!CBigNum::modInverse(product, modulus, inverse)) {
        return;   // product and modulus are not coprime, so no inverse exists
    }

    uint8_t wire[32];
    SByteSpan field(wire, sizeof(wire));
    if (!inverse.toBigEndian(field)) {
        return;   // wider than 32 bytes: nothing was written, rather than a truncated value
    }

    // Both copies of a secret scalar have to go: the span, and the heap limbs behind the value.
    CSecure::zero(field);
    inverse.secureClear();
}

// === SignedBig ===
// A magnitude plus a sign flag, for the one thing CBigNum cannot represent. CBigNum is unsigned
// and its sub() requires the operand to be no larger, so a difference that may come out either
// way is carried as a magnitude and a bool.
void exampleSignedBig(const CBigNum& a, const CBigNum& b) {
    SignedBig diff;

    if (a.compare(b) >= 0) {
        diff.mag = a;        // copy first: sub() mutates the value it is called on
        diff.mag.sub(b);
        diff.neg = false;
    } else {
        diff.mag = b;
        diff.mag.sub(a);
        diff.neg = true;
    }

    if (diff.mag.isZero()) {
        diff.neg = false;    // there is only one zero; keep the sign canonical
    }
}

// === CDjb ===
// The fast non-cryptographic hash the library uses to short-circuit CName comparison: unequal
// hashes settle it in one integer compare, and only equal ones go on to compare bytes. Never for
// a security decision -- it is deliberately not one of crypto's hashers.
void exampleCDjb(const CString& key, SReadOnlyByteSpan blob) {
    if (key.empty() || blob.size < 2) {
        return;
    }

    // computeAsLower()/computeAsUpper() fold case so a case-insensitive key hashes alike, but
    // they are two different functions: pick one per table and keep to it.
    const SDjbValue folded = CDjb::computeAsLower(key.toSpan());

    // combine() folds two finished hashes into one.
    const SDjbValue pair = CDjb::combine(folded, CDjb::compute(blob));

    // compute(hash, span) instead continues one hash over more data, for input arriving in
    // pieces; the one-argument overload is just compute(SEED, span).
    const size_t half = blob.size / 2;
    SDjbValue running = CDjb::compute(CDjb::SEED, blob.slice(0, half));
    running = CDjb::compute(running, blob.slice(half));

    if (CDjb::combine(folded, running) != pair) {
        return;   // chunked and one-shot agree, which is what makes streaming safe
    }
}

// === CGf2m ===
// Arithmetic in GF(2^m), the binary field the NIST B-/K- curves live in. A CGf2m keeps a
// non-owning pointer to its SGf2mField, so build one from knownFieldPtr()'s program-lifetime
// singleton: a field copied onto the stack leaves every element derived from it dangling.
void exampleCGf2m() {
    const SGf2mField* field = CGf2m::knownFieldPtr(EGF2M_M163);
    if (!field) {
        return;
    }

    CGf2m b;
    if (!CGf2m::fromHex(*field, "0x07b6882caaefa84f9554ff8428bd88e246d2782ae2", b)) {
        return;   // malformed, or not strictly below 2^163
    }

    CGf2m product(*field, 2);
    product.mul(b);          // mutates product, as every operation here does

    if (product.isZero()) {
        return;              // inverse() is undefined for zero
    }

    CGf2m check = product;   // copy first: inverse() would otherwise consume product
    check.inverse();

    TArray<uint8_t> wire;
    product.toBigEndian(wire);   // always fieldByteLen() bytes -- 21 for GF(2^163)
}

// === EGf2mKnownField ===
// Names one of the five binary fields this library defines. The "B" (random) and "K" (Koblitz)
// curve of a given size share a field, so EGF2M_M233 covers both B-233 and K-233: the
// identifier picks m and the reduction polynomial, not a curve equation.
void exampleEGf2mKnownField(EGf2mKnownField which) {
    if (which <= EGF2M_UNKNOWN || which >= EGF2M_MAX) {
        return;   // EGF2M_UNKNOWN and EGF2M_MAX are sentinels, not fields
    }

    const SGf2mField* field = CGf2m::knownFieldPtr(which);
    if (!field) {
        return;
    }

    CGf2m one(*field, 1);
    CGf2m squared = one;
    squared.square();

    if (squared != one) {
        return;   // 1^2 == 1 in every one of them
    }
}

// === SGf2mField ===
// The degree m plus the reduction polynomial x^m + x^terms[0] + ... + 1. knownField() copies the
// value out, which is right for reading these numbers -- but a CGf2m built from it keeps a
// pointer to it, so for that use CGf2m::knownFieldPtr() instead.
void exampleSGf2mField() {
    SGf2mField field;
    if (!CGf2m::knownField(EGF2M_M571, field)) {
        return;
    }

    // termCount is 1 for a trinomial and 3 for a pentanomial; only that many entries of terms[]
    // carry anything, and reading the rest reads whatever was left there.
    if (field.termCount != 1 && field.termCount != 3) {
        return;
    }

    for (size_t i = 0; i < field.termCount; ++i) {
        if (field.terms[i] == 0 || field.terms[i] >= field.m) {
            return;   // 0 < terms[i] < m always holds for a known field
        }
    }

    const size_t width = (field.m + 7) / 8;   // 72 bytes for GF(2^571)
    if (width > CGf2m::LIMB_COUNT * sizeof(uint64_t)) {
        return;
    }
}

// === CHex ===
// Decodes a hex string into bytes. The "0x" prefix is optional and an odd digit count is treated
// as left-padded with one '0', so "abc" and "0abc" decode identically -- meaning a string that
// lost a digit decodes successfully with every byte shifted. Check the length you expected.
void exampleCHex(const char* digits, SReadOnlyByteSpan expectedKeyId) {
    TArray<uint8_t> bytes;
    if (!CHex::decode(digits, bytes)) {
        return;   // a character outside [0-9a-fA-F]; bytes is left untouched
    }

    if (bytes.size() != 20) {
        return;   // a SHA-1 key identifier: an odd-length input would not have failed above
    }

    SReadOnlyByteSpan keyId(bytes.begin(), bytes.size());
    if (!keyId.sequencialEqual(expectedKeyId)) {
        return;   // content comparison; operator== here would compare pointers instead
    }
}

// === CMontgomery ===
// A division-free modular-arithmetic context precomputed for one fixed modulus. It needs an odd
// modulus: built from an even or zero one, isValid() is false and every operation silently does
// nothing, so that check is not optional. CBigNum::mod()/mulMod() stay the path for any modulus.
void exampleCMontgomery(const CBigNum& modulus, const CBigNum& base, const CBigNum& exponent) {
    CMontgomery mont(modulus);
    if (!mont.isValid()) {
        return;   // zero or even; use CBigNum::modExp() instead of getting no-ops
    }

    const CBigNum direct = mont.modExp(base, exponent);   // ordinary form in, ordinary form out

    // Working in the Montgomery domain instead: convert in once, compute, convert back once.
    // Mixing a converted value with an unconverted one is the way to misuse this class.
    CBigNum acc = mont.toMont(base);
    mont.mul(acc, acc);              // squaring through the same object is supported
    mont.add(acc, mont.one());       // one() is R mod m, the Montgomery form of 1
    const CBigNum ordinary = mont.fromMont(acc);

    if (direct.compare(mont.modulus()) >= 0 || ordinary.compare(mont.modulus()) >= 0) {
        return;   // never happens: every result comes back already reduced
    }
}

// === CSecure ===
// Zeroizes and compares secret bytes. zero() survives the dead-store elimination a plain
// memset() does not, and equalsMask() reads both inputs in full and yields a 0xFF/0x00 mask, so
// neither the matching-prefix length nor the outcome itself has to be branched on.
void exampleCSecure(SReadOnlyByteSpan candidate, SReadOnlyByteSpan expected, SReadOnlyByteSpan fallback) {
    uint8_t chosen[32];
    SByteSpan out(chosen, sizeof(chosen));

    const uint8_t mask = CSecure::equalsMask(candidate, expected);
    if (!CSecure::select(mask, expected, fallback, out)) {
        CSecure::zero(out);
        return;   // a null span, or the three sizes did not all match
    }

    // Where the outcome is not itself sensitive, equals() is the same comparison with a bool.
    if (!CSecure::equals(candidate, expected)) {
        // a mismatch, reported anyway -- a differing length also lands here
    }

    CSecure::zero(out);
}
