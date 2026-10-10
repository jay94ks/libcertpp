#include <certpp/oid.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/decoder.hpp>

#include <cstring>
#include <atomic>

namespace certpp {

    /**
     * Cached Slot for each known OID.
     *
     * --> All null until first use. std::atomic has no user-provided constructor, so this is
     * zero-initialised before any dynamic initialisation runs: there is no window in which a
     * COid built during another translation unit's static init could read a garbage slot, and
     * no eager filling whose order would have to be argued about.
     */
    std::atomic<COid::Slot*> COid::CACHED[COid::MAX_KNOWN_OID_COUNT] = {};

    /**
     * Compares the current OID with another OID.
     *
     * @param other The SRawOid instance to compare with.
     * @return A negative value if the current OID is less than the other OID,
     *         zero if they are equal,
     *         a positive value if the current OID is greater than the other OID.
     */
    int32_t SRawOid::compare(const SRawOid& other) const {
        size_t n = std::min(count, other.count);

        for (size_t i = 0; i < n; ++i) {
            if (arcs[i] > other.arcs[i]) {
                return 1;
            }

            else if (arcs[i] < other.arcs[i]) {
                return -1;
            }
        }

        if (count < other.count) {
            return -1;
        }

        if (count > other.count) {
            return 1;
        }

        return 0;
    }

    /**
     * Parses a dotted-decimal OID string into its arc values.
     *
     * --> Built on CEncoder::parseOidArcs() rather than a second hand-rolled scanner: that
     * one already rejects a leading zero, an arc wider than a uint32_t and a trailing '.',
     * and the OID is only useful if it survives the encode that follows it. Two parsers
     * would disagree eventually, and the disagreement would be silent.
     *
     * A valid OID also needs its first two arcs to be legal: arcs[0] in 0..2, and arcs[1]
     * below 40 when arcs[0] is below 2. parseOidArcs() checks neither, because its caller
     * is the encoder and the encoder's own encodedOidSize() check happens later on a
     * buffer. Here there is no second check to lean on, so this one is the last stop.
     */
    ERetCode SRawOid::parse(SRawOid& out, const CString& str) {
        out.count = 0;
        std::memset(out.arcs, 0, sizeof(out.arcs));

        if (!asn1::CEncoder::parseOidArcs(str, TSpan<uint32_t>(out.arcs, MAX_OID_ARCS), out.count)) {
            out.count = 0;
            return ERET_BADREQ;
        }

        if (!out.count || out.count > MAX_OID_ARCS) {
            out.count = 0;
            return ERET_BADREQ;
        }

        if (out.arcs[0] > 2) {
            out.count = 0;
            return ERET_BADREQ; // first arc is 0, 1 or 2 (X.690 8.19.4)
        }

        if (out.arcs[0] < 2 && out.count > 1 && out.arcs[1] >= 40) {
            out.count = 0;
            return ERET_BADREQ; // 0.x and 1.x are jointly limited to 40 (X.690 8.19.4)
        }

        return ERET_OK;
    }

    /**
     * Parses a wide dotted-decimal OID string into its arc values; see the narrow overload.
     */
    ERetCode SRawOid::parse(SRawOid& out, const CWideString& str) {
        CString narrow;
        narrow.append(str);
        return parse(out, narrow);
    }

    /**
     * Converts the binary representation of the OID into its string form.
     *
     * The mirror image of parse(), and both directions are checked against each other round
     * trip in tests/oid.cpp. The digits are produced least-significant first and reversed
     * into the output, which is why the buffer is 10 wide: a uint32_t arc is at most 10
     * decimal digits.
     */
    void SRawOid::toString(CString& out) const {
        out.clear();

        for (size_t i = 0; i < count; ++i) {
            if (i) {
                out.append('.');
            }

            uint32_t value = arcs[i];
            char digits[10]; // uint32_t: at most 10 decimal digits
            size_t digitCount = 0;

            if (value == 0) {
                digits[digitCount++] = '0';
            } else {
                while (value) {
                    digits[digitCount++] = char('0' + (value % 10));
                    value /= 10;
                }
            }

            while (digitCount) {
                out.append(digits[--digitCount]);
            }
        }
    }

    /**
     * Converts the binary representation of the OID into its wide string form.
     */
    void SRawOid::toString(CWideString& out) const {
        CString narrow;
        toString(narrow);
        out.clear();
        out.append(narrow);
    }

    /**
     * Checks if the current known OID is equal to another known OID.
     *
     * --> The string's address, not its contents. Every entry in CERTPP_KNOWN_OIDS has its own
     * literal, so two different entries can never share one, and comparing the pointers settles
     * identity without a parse or a scan. Two spellings of the same OID would not be equal by
     * this test, which is correct here: the list is meant to hold each OID once, and a
     * duplicate is a bug in the list rather than a spelling to be tolerated. tests/oid.cpp
     * checks for duplicates on the parsed arcs, which is the comparison that would catch one.
     *
     * @param other The SKnownOid instance to compare with.
     * @return true if the current known OID is equal to the other known OID, false otherwise.
     */
    bool SKnownOid::equals(const SKnownOid& other) const {
        return s == other.s;
    }

    /**
     * Get or create a cached shared pointer to a Slot structure for a known OID.
     *
     * --> The cache is filled at run time, on the first COid built from each known OID,
     * rather than at static-initialisation time. A pre-filled cache has to be an array of
     * shared_ptr built from a macro list, which is a load-order dependency for no gain: the
     * arcs come out of a string literal either way, and filling on demand keeps them off the
     * load path entirely for a program that never names one.
     *
     * --> The fill is atomic rather than locked. A compare-exchange means the first thread to
     * publish wins and every later one takes its Slot, so a given nth always resolves to one
     * pointer -- which is what makes the pointer short-circuit in compare() sound. A mutex
     * would be correct too, but this is a contract that fits an atomic exactly, and the read
     * path is a single load rather than a lock acquire on every COid::SHA1.
     *
     * --> An out-of-range nth returns nullptr rather than indexing past the array. That
     * cannot happen for any entry in CERTPP_KNOWN_OIDS, whose index is on its own line in the
     * same list that sized the array -- but a caller that fabricated an SKnownOid by hand
     * must not be able to walk off the end, and saying so costs one compare.
     */
    std::shared_ptr<COid::Slot> COid::cacheFor(const SKnownOid& known) {
        if (known.nth >= MAX_KNOWN_OID_COUNT) {
            return nullptr;
        }

        // --> Acquire, so a Slot another thread published is fully visible: its CString's
        // buffer and the arcs it parsed were written before the pointer that refers to them.
        if (Slot* cached = CACHED[known.nth].load(std::memory_order_acquire)) {
            return std::shared_ptr<Slot>(cached, [](Slot*) { });
        }

        // --> new, not make_shared: this thread gives up ownership of the Slot to the cache
        // the moment it publishes it, and shared_ptr has no release(). The Slot is
        // deliberately never destroyed -- every COid built from a known OID aliases it
        // through a shared_ptr with a no-op deleter, so there is no count that could decide
        // when it is safe to free, and no reason to want one. One leaked Slot per known OID
        // the program actually uses, bounded by MAX_KNOWN_OID_COUNT.
        auto built = new Slot();
        built->str = known.s;

        // --> Parse the text here, where a COid is actually being built from it. A failure
        // leaves the Slot's arcs empty, which tests/oid.cpp catches: it builds a COid from
        // every known OID and requires each one to equal the same OID parsed from its text.
        SRawOid::parse(built->raw, CString(known.s));

        Slot* expected = nullptr;
        if (CACHED[known.nth].compare_exchange_strong(
                expected, built, std::memory_order_release, std::memory_order_acquire)) {
            return std::shared_ptr<Slot>(built, [](Slot*) { });
        }

        // --> Another thread won the race. Its Slot is the one every later caller will get, so
        // this one takes it too, and the copy this thread built is dropped. The Slot's CString
        // and arcs have not been touched by anyone else, so deleting it here is safe -- it is
        // a plain object until the winning store publishes the pointer, and nothing but this
        // thread holds a reference to it.
        delete built;

        return std::shared_ptr<Slot>(expected, [](Slot*) { });
    }

    /**
     * Constructs a COid from a NUL-terminated string.
     *
     * --> Out of line rather than inline in the header so the header does not have to name
     * CString's constructor. It exists so a string literal can be handed to COid without an
     * explicit wrap -- `COid("2.5.29.19")` reads the way the `const char*` OID constants the
     * x509 layer used to declare did.
     *
     * @param str The NUL-terminated OID string.
     */
    COid::COid(const char* str) : COid(CString(str)) {
    }

    /**
     * Assignment operator for a known OID.
     *
     * @param known The known OID to assign from.
     * @return A reference to the current COid instance.
     */
    COid& COid::operator=(const SKnownOid& known) {
        _slot = cacheFor(known);
        return *this;
    }

    /**
     * Compares the current COid instance with another COid instance.
     *
     * @param other The COid instance to compare with.
     * @return A negative value if the current instance is less than the other,
     *         zero if they are equal,
     *         a positive value if the current instance is greater than the other.
     */
    int32_t COid::compare(const COid& other) const {
        if (_slot == other._slot) {
            return 0;
        }

        int32_t dV = compareShared(_slot, other._slot);
        if (dV != 0) {
            return dV;
        }

        // --> One slot is null and the other is not. An empty COid sorts before any real OID,
        // which is what makes a sort over a range of OIDs total rather than dependent on
        // which one happened to be empty.
        if (!_slot) {
            return -1;
        }

        if (!other._slot) {
            return 1;
        }

        if (_slot->raw) {
            if (other._slot->raw) {
                return _slot->raw.compare(other._slot->raw);
            }

            return 1;
        }

        if (other._slot->raw) {
            return -1;
        }

        return 0;
    }

} // namespace certpp
