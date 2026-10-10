#include <certpp/x509/chain/pem.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/reader.hpp>
#include <certpp/utils/base64.hpp>
#include <certpp/utils/bignum.hpp>
#include <certpp/utils/secure.hpp>
#include <cstring>
#include <vector>

namespace certpp {
namespace x509 {

    using asn1::CDecoder;
    using asn1::CDer;
    using asn1::CEncoder;
    using asn1::CReader;
    using asn1::CTag;
    using asn1::EAENC_DER;
    using asn1::EATAG_CONTEXT_SPECIFIC;

    namespace {

        constexpr const char* BEGIN_MARKER = "-----BEGIN ";
        constexpr const char* END_PREFIX = "-----END ";
        constexpr const char* DASHES = "-----";

        /* The one label this format reads back as a certificate. Everything else -- a key, a
         * CSR, DH parameters, openssl's own "TRUSTED CERTIFICATE" -- is handled as a candidate
         * private key, which is the same split CCert::importPem() has always made: a label this
         * library doesn't understand costs a failed key-parse attempt and nothing more, whereas
         * guessing that an unknown label might be a certificate would feed arbitrary DER to
         * importDer() and report somebody else's structure as a malformed certificate. */
        constexpr const char* CERT_LABEL = "CERTIFICATE";

        /* How scanBlock() ended. Not an E-prefixed public enum: this is file-local machinery,
         * not API. */
        enum BlockScan {
            SCAN_END = 0,       // No further "-----BEGIN " marker; the scan is complete.
            SCAN_OK,            // A complete block was read and its body decoded.
            SCAN_MALFORMED,     // A "-----BEGIN " with no usable block behind it.
            SCAN_ENCRYPTED,     // A block whose body is password-encrypted (RFC 1421 headers).
        };

        /* One decoded encapsulated block, plus where its boundary started -- load() needs that
         * offset to know which stretch of explanatory text belongs to this block. */
        struct PemBlock {
            CString label;
            COctet der;
            size_t begin;

            PemBlock() : begin(0) {
            }
        };

        /* Finds the next "-----BEGIN <label>-----" / "-----END <label>-----" block in text at or
         * after cursor (RFC 7468), decoding its base64 body (via CBase64::decode(), which
         * already tolerates the body's own embedded line breaks, so CRLF and LF files read
         * alike). Advances cursor past the block found.
         *
         * Unlike the scan this replaces (CCert's own findNextPemBlock(), which folded every
         * outcome into a single false and so stopped mid-file without telling anyone), the three
         * failure modes are distinguished, because load() owes its caller a different answer for
         * each: no more blocks is how a healthy scan ends, a structurally broken block means the
         * container is malformed, and an encrypted body means the container needs a password
         * this format does not have. */
        BlockScan scanBlock(const CString& text, size_t& cursor, PemBlock& out) {
            const offset_t beginPos = text.find(BEGIN_MARKER, cursor);
            if (beginPos < 0) {
                return SCAN_END;
            }

            out.begin = static_cast<size_t>(beginPos);

            const size_t labelStart = out.begin + std::strlen(BEGIN_MARKER);
            const offset_t labelEnd = text.find(DASHES, labelStart);
            if (labelEnd < 0) {
                return SCAN_MALFORMED;
            }

            out.label = text.subString(labelStart, static_cast<size_t>(labelEnd) - labelStart);

            const offset_t bodyStart = text.find('\n', static_cast<size_t>(labelEnd));
            if (bodyStart < 0) {
                return SCAN_MALFORMED;
            }
            const size_t bodyPos = static_cast<size_t>(bodyStart) + 1;

            CString endMarker(END_PREFIX);
            endMarker.append(out.label);

            const offset_t endPos = text.find(endMarker.toPtr(), bodyPos);
            if (endPos < 0) {
                return SCAN_MALFORMED;
            }

            const CString body = text.subString(bodyPos, static_cast<size_t>(endPos) - bodyPos);

            const offset_t afterEnd = text.find('\n', static_cast<size_t>(endPos));
            cursor = (afterEnd < 0) ? text.size() : static_cast<size_t>(afterEnd) + 1;

            // --> RFC 1421's encrypted-key headers ("Proc-Type: 4,ENCRYPTED" plus DEK-Info),
            // which openssl still writes for a traditional key given -aes256. They sit inside
            // the boundaries, ahead of the base64, so the body would simply fail to decode;
            // reporting "needs a password" rather than "malformed" is the difference between a
            // caller fixing their file and a caller fixing their password handling.
            if (body.find("Proc-Type:") >= 0) {
                return SCAN_ENCRYPTED;
            }

            CBuffer decoded;
            if (!CBase64::decode(decoded, body)) {
                return SCAN_MALFORMED;
            }

            out.der = COctet(SReadOnlyByteSpan(decoded.toPtr(), decoded.size()));
            return SCAN_OK;
        }

        /* Appends one "-----BEGIN <label>-----\n<base64 body, line-wrapped>-----END
         * <label>-----\n" block (RFC 7468) to text. False only if CBase64::encode() itself fails
         * (out of memory). */
        bool writeBlock(CString& text, const char* label, const COctet& der) {
            CString body;
            if (!CBase64::encode(body, der.toSpan(), true)) {
                return false;
            }

            text.append("-----BEGIN ").append(label).append("-----\n");
            text.append(body);
            text.append("-----END ").append(label).append("-----\n");
            return true;
        }

        /* Whether ch is one of the four ASCII whitespace characters PEM text uses. Written as
         * values rather than escapes, matching IChainFormat::detect()'s own skip loop. */
        inline bool isSpace(char ch) {
            return ch == 0x20 || ch == 0x09 || ch == 0x0D || ch == 0x0A;
        }

        /* 0-15 for a hex digit, -1 otherwise. CHex::decode() isn't usable here: openssl writes
         * localKeyID as space-separated byte pairs ("01 00 00 00"), and CHex rejects anything
         * outside the alphabet rather than skipping separators. */
        inline int hexDigit(char ch) {
            if (ch >= '0' && ch <= '9') {
                return ch - '0';
            }
            if (ch >= 'a' && ch <= 'f') {
                return ch - 'a' + 10;
            }
            if (ch >= 'A' && ch <= 'F') {
                return ch - 'A' + 10;
            }

            return -1;
        }

        /* Zeroes the decoded key blocks load() collected, on the way out of every return path it
         * has. They are plaintext private keys in freed heap memory otherwise -- the blocks that
         * paired with a certificate as much as the ones that paired with nothing, since the key
         * object made from one keeps its own copy. The PEM text itself still holds the same bytes
         * in base64 and belongs to the caller, so this is not a claim that no copy survives
         * load(); it is this function's own copies not being left behind. */
        struct KeyBlockScrubber {
            std::vector<COctet>& blocks;

            explicit KeyBlockScrubber(std::vector<COctet>& target) : blocks(target) {
            }

            ~KeyBlockScrubber() {
                for (COctet& block : blocks) {
                    if (!block.empty()) {
                        CSecure::zero(SByteSpan(
                            const_cast<uint8_t*>(block.toPtr()), block.size()));
                    }
                }
            }
        };

        /* Appends an entry's PKCS#9 attributes to text as openssl's own "Bag Attributes" header
         * -- exactly the shape `openssl pkcs12 -nokeys -out bundle.pem` emits, which is why it
         * is this shape and not an invention of this library's own. It sits outside the
         * encapsulation boundaries, where RFC 7468 explicitly allows arbitrary explanatory text,
         * so a reader that doesn't know about it (including openssl itself) skips it. A no-op for
         * an entry with neither attribute, so a collection that never touched them -- every
         * collection CCert::exportPem() builds, for one -- round-trips byte for byte. */
        void appendAttributes(CString& text, const SCertEntry& entry) {
            const bool haveName = entry.friendlyName.size() > 0;
            const bool haveId = !entry.localKeyId.empty();

            if (!haveName && !haveId) {
                return;
            }

            text.append("Bag Attributes\n");

            if (haveName) {
                text.append("    friendlyName: ").append(entry.friendlyName).append("\n");
            }

            if (haveId) {
                static const char* DIGITS = "0123456789ABCDEF";

                text.append("    localKeyID:");
                for (size_t i = 0; i < entry.localKeyId.size(); ++i) {
                    const uint8_t byte = entry.localKeyId.toPtr()[i];
                    text.append(' ');
                    text.append(DIGITS[byte >> 4]);
                    text.append(DIGITS[byte & 0x0F]);
                }
                text.append("\n");
            }
        }

        /* Reads the attributes appendAttributes() wrote back out of the explanatory text in
         * text[from, to) -- the stretch between the previous block's end and this block's own
         * "-----BEGIN ". Both attributes are optional and anything else in the region is
         * ignored, since that region is also where tools put subject=/issuer= dumps, comments and
         * blank lines. The last occurrence of each wins, which only matters for a hand-edited
         * file; a malformed localKeyID (an odd number of hex digits, or a stray non-hex
         * character) is left out rather than failing the load, because an attribute is a label
         * for a certificate, not part of it. */
        void parseAttributes(
            const CString& text, size_t from, size_t to, CString& outName, COctet& outLocalKeyId
        ) {
            outName = CString();
            outLocalKeyId = COctet();

            if (to <= from || to > text.size()) {
                return;
            }

            const char* const base = text.toPtr();
            size_t at = from;

            while (at < to) {
                size_t lineEnd = at;
                while (lineEnd < to && base[lineEnd] != '\n') {
                    ++lineEnd;
                }

                // Trim both ends of the line, so indentation and a CR before the LF are gone.
                size_t start = at;
                size_t stop = lineEnd;
                while (start < stop && isSpace(base[start])) {
                    ++start;
                }
                while (stop > start && isSpace(base[stop - 1])) {
                    --stop;
                }

                static const char* NAME_KEY = "friendlyName:";
                static const char* ID_KEY = "localKeyID:";

                // --> A prefix test, which CString::compare() deliberately isn't (it compares
                // lengths too, so a line that *starts* with the key is "greater" than it).
                const size_t length = stop - start;
                const size_t nameKeyLen = std::strlen(NAME_KEY);
                const size_t idKeyLen = std::strlen(ID_KEY);

                if (length >= nameKeyLen
                    && std::memcmp(base + start, NAME_KEY, nameKeyLen) == 0)
                {
                    size_t valueStart = start + nameKeyLen;
                    while (valueStart < stop && isSpace(base[valueStart])) {
                        ++valueStart;
                    }

                    outName = CString(base + valueStart, stop - valueStart);
                } else if (length >= idKeyLen
                    && std::memcmp(base + start, ID_KEY, idKeyLen) == 0)
                {
                    std::vector<uint8_t> bytes;
                    int high = -1;
                    bool bad = false;

                    for (size_t i = start + idKeyLen; i < stop; ++i) {
                        const char ch = base[i];
                        if (isSpace(ch) || ch == ':') {
                            continue;
                        }

                        const int value = hexDigit(ch);
                        if (value < 0) {
                            bad = true;
                            break;
                        }

                        if (high < 0) {
                            high = value;
                            continue;
                        }

                        bytes.push_back(static_cast<uint8_t>((high << 4) | value));
                        high = -1;
                    }

                    if (!bad && high < 0 && !bytes.empty()) {
                        outLocalKeyId = COctet(SReadOnlyByteSpan(bytes.data(), bytes.size()));
                    }
                }

                at = (lineEnd < to) ? lineEnd + 1 : to;
            }
        }

    } // namespace

    /* Unwraps a PKCS#8 PrivateKeyInfo, reaching the algorithm-specific key blob inside. */
    bool CPemChainFormat::unwrapPkcs8PrivateKey(const COctet& data, COctet& outInner) {
        CReader wrapper(data.toSpan(), EAENC_DER);
        CReader seq;
        if (!wrapper.readSequence(seq)) {
            return false;
        }

        int64_t version = 0;
        if (!seq.readInteger(version)) {
            return false;
        }

        // privateKeyAlgorithm AlgorithmIdentifier -- read past, not resolved (see this method's
        // own doc comment on why: only whether the inner blob happens to match the certificate's
        // own algorithm's wire format matters, not which OID PKCS#8 itself names).
        CReader algoSeq;
        if (!seq.readSequence(algoSeq)) {
            return false;
        }

        COctet inner;
        if (!seq.readOctetString(inner)) {
            return false;
        }

        outInner = move(inner);
        return true;
    }



    /* Converts a PKCS#8-wrapped DSA private key's inner blob (a bare INTEGER x) into this
     * library's own traditional DSAPrivateKey wire format. */
    bool CPemChainFormat::convertPkcs8DsaInnerToNative(
        const COctet& innerX, const COctet& keyAlgoParams, const COctet& rawPublicKey,
        COctet& outNative
    ) {
        if (keyAlgoParams.empty() || rawPublicKey.empty()) {
            return false;
        }

        // rawPublicKey() is the complete DER INTEGER y TLV (see CCert's own
        // buildDsaPublicKeyBlob() comment on why), not just its bare magnitude -- unwrap it.
        // That unwrapping is what differs from CCert::buildDsaNative()'s other caller, which
        // has no certificate and recovers y as g^x mod p instead; everything after it is the
        // same encoder, so it lives in one place.
        CTag yTag;
        SReadOnlyByteSpan yContent;
        SReadOnlyByteSpan yCursor = rawPublicKey.toSpan();
        if (!CDecoder::readNextElement(yCursor, EAENC_DER, yTag, yContent)
            || yTag != CTag::INTEGER)
        {
            return false;
        }

        return CCert::buildDsaNative(
            keyAlgoParams.toSpan(), CBigNum::fromBigEndian(yContent), innerX, outNative);
    }

    /* Tries candidate as cert's own private key, attempting every shape it might be in until one
     * both parses under cert's own algorithm and matches its public key. */
    bool CPemChainFormat::tryAttachPrivateKey(CCert& cert, const COctet& candidate) {
        // --> cert._asym, reached through the friendship CCert grants this class, rather than
        // IAsymmetric::builtIn(cert.publicKey()->algorithm()): it is the same object, already
        // resolved by importDer(), and going the long way round would decode the public key
        // before knowing whether there is a private one worth trying.
        if (!cert._asym || candidate.empty()) {
            return false;
        }

        crypto::IPrivateKeyPtr pvt = cert._asym->createPrivateKey(candidate);

        // A traditional (non-PKCS#8) "EC PRIVATE KEY" block: standard SEC1, not this library's
        // own native EC format (see CCert::convertSec1ToNative()'s own doc comment).
        if (!pvt) {
            COctet native;
            if (CCert::convertSec1ToNative(candidate, native)) {
                pvt = cert._asym->createPrivateKey(native);
            }
        }

        if (!pvt) {
            COctet inner;
            if (unwrapPkcs8PrivateKey(candidate, inner)) {
                // RSA's PKCS#8 form: the inner blob is the final PKCS#1 RSAPrivateKey directly.
                pvt = cert._asym->createPrivateKey(inner);

                if (!pvt) {
                    // RFC 8410 (Ed25519/Ed448/X25519): the inner blob is itself a separately
                    // DER-encoded OCTET STRING wrapping the raw seed.
                    COctet seed;
                    if (CCert::unwrapOctetString(inner, seed)) {
                        pvt = cert._asym->createPrivateKey(seed);
                    }
                }

                if (!pvt) {
                    // EC's usual PKCS#8 form (e.g. `openssl req -newkey ec ...`): the inner blob
                    // is itself a SEC1 ECPrivateKey, not a raw scalar.
                    COctet native;
                    if (CCert::convertSec1ToNative(inner, native)) {
                        pvt = cert._asym->createPrivateKey(native);
                    }
                }

                if (!pvt) {
                    // DSA's usual PKCS#8 form: the inner blob is a bare INTEGER x, not the
                    // traditional {version, p, q, g, y, x} SEQUENCE.
                    COctet native;
                    if (convertPkcs8DsaInnerToNative(
                            inner, cert.keyAlgoParams(), cert.rawPublicKey(), native))
                    {
                        pvt = cert._asym->createPrivateKey(native);
                    }
                }
            }
        }

        if (!pvt) {
            return false;
        }

        return cert.privateKey(pvt) == ERET_OK;
    }

    /* Builds a standards-compliant SEC1 ECPrivateKey (RFC 5915) blob. */
    bool CPemChainFormat::buildSec1PrivateKey(const CCert& cert, COctet& out) {
        // --> CCert::buildSec1FromNative() is this encoder, with its three inputs passed in
        // rather than read off a certificate, so that CCert's own PKCS#8 export can reach it
        // too. Reachable here through the friendship CCert grants this class. Two copies of a
        // key encoder is two places for the encoding to drift.
        return CCert::buildSec1FromNative(
            cert.rawPrivateKey(), cert.keyAlgoParams(), cert.rawPublicKey().toSpan(), out);
    }

    /* Builds a standards-compliant PKCS#8 PrivateKeyInfo (RFC 8410) blob. */
    bool CPemChainFormat::buildPkcs8PrivateKey(const CCert& cert, COctet& out) {
        const COctet& privateKey = cert.rawPrivateKey();
        if (privateKey.empty()) {
            return false;
        }

        // --> CCert's own KEY_ALGOS table, reached through the friendship it grants this class,
        // so the OID written here and the one importDer() resolved the certificate's algorithm
        // from can never be two different tables that drift apart.
        COid keyOid;
        if (!CCert::lookupKeyAlgoOid(cert.keyAlgo(), keyOid)) {
            return false;
        }

        // --> Encoded from the arcs. keyAlgo() already parsed this OID out of the certificate, and
        // formatting it to text only to have encodeOidString() parse it back would undo that.
        uint8_t oidContentBuf[32];
        size_t oidContentLen = 0;
        if (!CEncoder::encodeOid(
                TSpan<uint8_t>(oidContentBuf, sizeof(oidContentBuf)), keyOid.raw(), oidContentLen))
        {
            return false;
        }

        CBuffer body;
        uint8_t versionContent = 0x00;
        if (!CDer::appendTlv(body, CTag::INTEGER, SReadOnlyByteSpan(&versionContent, 1))) {
            return false;
        }

        // privateKeyAlgorithm AlgorithmIdentifier ::= SEQUENCE { OID } -- RFC 8410: no parameters.
        CBuffer algoIdContent;
        if (!CDer::appendTlv(
                algoIdContent, CTag::OBJ_ID, SReadOnlyByteSpan(oidContentBuf, oidContentLen))
            || !CDer::appendSequence(body, algoIdContent.toSpan()))
        {
            return false;
        }

        // privateKey OCTET STRING wrapping a separately DER-encoded CurvePrivateKey OCTET STRING
        // (RFC 8410 section 7's double-wrapping) around the raw seed.
        CBuffer innerTlv;
        if (!CDer::appendTlv(innerTlv, CTag::STRING_OCTET, privateKey.toSpan())
            || !CDer::appendTlv(body, CTag::STRING_OCTET, innerTlv.toSpan()))
        {
            return false;
        }

        CBuffer full;
        if (!CDer::appendSequence(full, body.toSpan())) {
            return false;
        }

        out = COctet(full.toSpan());
        return true;
    }

    /* Appends cert's attached private key to text as one PEM block, in whichever standard shape
     * its algorithm actually has. */
    bool CPemChainFormat::appendPrivateKeyBlock(CString& text, const CCert& cert) {
        COctet keyDer;
        const char* label = nullptr;

        if (cert.keyAlgo().compare("RSA") == 0) {
            keyDer = cert.rawPrivateKey();
            label = "RSA PRIVATE KEY";
        } else if (cert.keyAlgo().compare("DSA") == 0) {
            keyDer = cert.rawPrivateKey();
            label = "DSA PRIVATE KEY";
        } else if (cert.keyAlgo().compare("EC") == 0 && buildSec1PrivateKey(cert, keyDer)) {
            label = "EC PRIVATE KEY";
        } else if (buildPkcs8PrivateKey(cert, keyDer)) {
            label = "PRIVATE KEY";
        }

        if (!label) {
            // An algorithm with no standard PEM encoding this library can build. The key is left
            // out rather than written as something no other tool could read back -- see this
            // method's own doc comment, and save()'s @return.
            return true;
        }

        return writeBlock(text, label, keyDer);
    }

    /* Constructs the PEM format. */
    CPemChainFormat::CPemChainFormat(bool withPrivateKeys)
        : _withPrivateKeys(withPrivateKeys)
    {
    }

    /* Returns which format this implementation handles. */
    EChainFormats CPemChainFormat::format() const {
        return ECHAINFMT_PEM;
    }

    /* Reports whether this format requires a password -- it does not, and has no secrecy at
     * all. */
    bool CPemChainFormat::needsPassword() const {
        return false;
    }

    /* Reports whether save() writes private keys. */
    bool CPemChainFormat::includesPrivateKeys() const {
        return _withPrivateKeys;
    }

    /* Reads the next RFC 7468 encapsulated block out of text, whatever its label. */
    ERetCode CPemChainFormat::nextBlock(
        const CString& text, size_t& cursor, CString& outLabel, COctet& outDer
    ) {
        PemBlock block;
        switch (scanBlock(text, cursor, block)) {
            case SCAN_OK:
                outLabel = block.label;
                outDer = block.der;
                return ERET_OK;

            // --> The scan running out of blocks is how a healthy scan ends, so it is reported
            // separately from the two ways a block can be present but unusable.
            case SCAN_END:
                return ERET_NOTFOUND;

            case SCAN_ENCRYPTED:
                return ERET_NOTSUP;

            case SCAN_MALFORMED:
            default:
                return ERET_BADREQ;
        }
    }

    /* Appends one RFC 7468 encapsulated block. */
    bool CPemChainFormat::appendBlock(CString& text, const char* label, const COctet& der) {
        return writeBlock(text, label, der);
    }

    /* Reads concatenated PEM blocks into a collection, appending one entry per CERTIFICATE
     * block. */
    ERetCode CPemChainFormat::load(
        const SReadOnlyByteSpan& data, const SReadOnlyByteSpan& password, CCertCollection& out
    ) const {
        // --> Not "unused because this implementation is incomplete": PEM has no password, so
        // there is nothing a password could be used for here. See this class's doc comment.
        (void)password;

        if (!data.data || data.size == 0) {
            return ERET_BADREQ;
        }

        const CString text(reinterpret_cast<const char*>(data.data), data.size);

        // --> Everything is built up locally and committed to out at the very end, because
        // load() appends: a file that goes wrong at its third block must leave the caller's
        // collection holding exactly what it held before, not the first two certificates plus an
        // error code. Writing into out as the scan proceeds reads as the obvious implementation
        // and is precisely the bug the interface's "left as it was rather than half-populated"
        // sentence exists to forbid.
        std::vector<SCertEntry> entries;
        std::vector<COctet> keyBlocks;

        // Scrubs keyBlocks whichever way this function returns -- see KeyBlockScrubber.
        const KeyBlockScrubber scrubber(keyBlocks);

        size_t cursor = 0;
        size_t previousEnd = 0;

        for (;;) {
            PemBlock block;
            const BlockScan scan = scanBlock(text, cursor, block);

            if (scan == SCAN_END) {
                break;
            }

            if (scan == SCAN_ENCRYPTED) {
                return ERET_NOTSUP;
            }

            if (scan == SCAN_MALFORMED) {
                return ERET_BADREQ;
            }

            if (block.label.compare(CERT_LABEL) != 0) {
                if (block.label.compare("ENCRYPTED PRIVATE KEY") == 0) {
                    // PKCS#8's own encrypted form (RFC 5958 EncryptedPrivateKeyInfo). The DER
                    // parsed, so this is not a malformed file -- it is a file whose key is
                    // protected by a password-based algorithm this format has no password for.
                    return ERET_NOTSUP;
                }

                keyBlocks.push_back(move(block.der));
                previousEnd = cursor;
                continue;
            }

            SCertEntry entry;
            if (entry.cert.importDer(block.der) != ERET_OK) {
                return ERET_BADREQ;
            }

            parseAttributes(text, previousEnd, block.begin, entry.friendlyName, entry.localKeyId);

            entries.push_back(move(entry));
            previousEnd = cursor;
        }

        if (entries.empty()) {
            return ERET_BADREQ; // no CERTIFICATE block: not a certificate container at all.
        }

        // --> Pairing happens after the whole file has been read, not as each block arrives, so
        // a key block that sits *after* its certificate pairs just as well as one before it --
        // both layouts occur in the wild. A key is consumed once it pairs, so two certificates
        // sharing a key (which would have to be the same key twice in the file) can't both claim
        // the same block, and a key that pairs with nothing is simply dropped: a bundle carrying
        // somebody else's key next to a certificate still loads.
        for (SCertEntry& entry : entries) {
            for (COctet& candidate : keyBlocks) {
                if (candidate.empty()) {
                    continue;
                }

                if (tryAttachPrivateKey(entry.cert, candidate)) {
                    entry.privateKey = entry.cert.privateKey();

                    // Zeroed here rather than left to the scrubber, because marking the block
                    // consumed is dropping this copy of it -- the key object the certificate now
                    // holds has its own.
                    CSecure::zero(SByteSpan(
                        const_cast<uint8_t*>(candidate.toPtr()), candidate.size()));
                    candidate = COctet();
                    break;
                }
            }
        }

        // The commit. add() fails only for an entry whose certificate is empty, and every entry
        // here came out of a successful importDer(), so this loop cannot fail part way through
        // and leave out half-populated.
        for (const SCertEntry& entry : entries) {
            size_t index = 0;
            const ERetCode rc = out.add(entry, index);

            if (rc != ERET_OK) {
                return rc;
            }
        }

        return ERET_OK;
    }

    /* Writes a collection out as concatenated PEM blocks. */
    ERetCode CPemChainFormat::save(
        const CCertCollection& in, const SReadOnlyByteSpan& password, CBuffer& out
    ) const {
        (void)password; // PEM has no password -- see load()'s own comment and the class's.

        if (in.empty()) {
            return ERET_BADREQ;
        }

        CString text;

        for (size_t i = 0; i < in.count(); ++i) {
            SCertEntry entry;
            if (in.at(i, entry) != ERET_OK) {
                return ERET_BADREQ;
            }

            COctet der;
            const ERetCode rc = entry.cert.exportDer(der);
            if (rc != ERET_OK) {
                return rc; // ERET_INVAL for an empty certificate, which add() shouldn't allow.
            }

            if (entry.friendlyName.find('\n') >= 0 || entry.friendlyName.find('\r') >= 0) {
                // A one-line header can't carry it, and writing it anyway would produce a file
                // whose own "Bag Attributes" section runs into the certificate. Refusing says so;
                // truncating at the line break would lose data the caller deliberately set.
                return ERET_BADREQ;
            }

            appendAttributes(text, entry);

            if (!writeBlock(text, CERT_LABEL, der)) {
                return ERET_NOMEM;
            }

            if (!_withPrivateKeys) {
                continue;
            }

            // --> The certificate may already carry the key (CCert::privateKey(IPrivateKeyPtr&)
            // keeps a serialized copy, so every certificate read back out of a PEM file that had
            // one does), in which case there is nothing to attach and nothing to re-check. An
            // entry whose key lives only on the entry gets it attached to a local copy, which is
            // also what checks that the key really is this certificate's own -- the alternative
            // is writing out a file that pairs a certificate with a key that was never its own.
            CCert withKey = entry.cert;

            if (withKey.rawPrivateKey().empty()) {
                if (!entry.privateKey) {
                    continue;
                }

                crypto::IPrivateKeyPtr key = entry.privateKey;
                if (withKey.privateKey(key) != ERET_OK) {
                    return ERET_KEY_ERROR;
                }
            }

            if (!appendPrivateKeyBlock(text, withKey)) {
                return ERET_NOMEM;
            }
        }

        if (!out.store(reinterpret_cast<const uint8_t*>(text.toPtr()), text.size())) {
            return ERET_NOMEM;
        }

        return ERET_OK;
    }

} // namespace x509
} // namespace certpp
