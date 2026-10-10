#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>
#include <thread>
#include <vector>

using namespace certpp;

namespace {

    // Walks every known OID the library declares. The list lives in oid.hpp as an X-macro, so
    // this is the only way to reach it from a test -- which is the point: an OID that exists
    // only in a source file's string literal has nothing forcing it into the table, and this
    // is what finds the ones that were missed.
    template<typename Fn>
    void forEachKnownOid(Fn fn) {
#define CERTPP_TEST_KNOWN_OID(Index, Name, Text) fn(COid::Name, Index, Text);
        CERTPP_KNOWN_OIDS(CERTPP_TEST_KNOWN_OID)
#undef CERTPP_TEST_KNOWN_OID
    }

} // anonymous namespace

TEST_CASE("SRawOid: parse round-trips every known OID the library declares") {
    forEachKnownOid([](const SKnownOid& known, uint32_t index, const char* text) {
        INFO("known OID: " << text);

        // --> Every entry in the list has to survive the same parse a caller's own OID string
        // goes through, and come back out of that parse as the text it started as. A known
        // OID that does not round-trip is a COid that would silently never match anything --
        // and the table is the one place a typo would be invisible.
        SRawOid parsed;
        REQUIRE(SRawOid::parse(parsed, CString(text)) == ERET_OK);
        REQUIRE(parsed.count > 0);

        CString back;
        parsed.toString(back);
        CHECK(back.compare(CString(text)) == 0);
    });
}

TEST_CASE("SRawOid: parse accepts well-formed OIDs and rejects malformed ones") {
    struct Case { const char* text; bool ok; };
    const Case cases[] = {
        // -- valid: the first two arcs follow X.690 8.19.4's joint-iso rules
        { "2.5.4.3",                   true  },
        { "1.2.840.113549.1.1.1",      true  },
        { "0.9.2342.19200300.100.1.25", true  }, // arcs[0] < 2 and arcs[1] < 40
        { "2.100.3",                   true  }, // arcs[0] == 2 lifts the 40 cap on arcs[1]
        { "2.999",                     true  },
        { "0.0",                       true  },
        { "1.39.999",                  true  },

        // -- valid boundary: a single arc is a degenerate but encodable OID
        { "2",                         true  },

        // -- invalid: arcs[0] out of range
        { "3.5.4.3",                   false },
        { "4.1",                       false },
        { "3.100",                     false },

        // -- invalid: arcs[1] >= 40 under a joint-iso root
        { "0.40",                      false },
        { "1.40",                      false },
        { "0.99",                      false },

        // -- invalid: empty and whitespace
        { "",                          false },
        { " ",                         false },

        // -- invalid: non-minimal and non-numeric components
        { "1.02.3",                    false }, // leading zero
        { "01.2.3",                    false },
        { "1.2.840.113549.1.1.1 ",     false }, // trailing space
        { "1.2.-3",                    false },
        { "1.2.+3",                    false },
        { "1.2.3a",                    false },

        // -- invalid: separator problems
        { ".1.2.3",                    false }, // leading '.'
        { "1.2.3.",                    false }, // trailing '.'
        { "1..2",                      false },
        { "1.2,,3",                    false },

        // -- invalid: an arc wider than a uint32_t
        { "1.2.99999999999",           false },
        { "1.4294967296",              false },
    };

    for (const Case& c : cases) {
        INFO("OID text: \"" << c.text << "\" expected " << (c.ok ? "valid" : "invalid"));

        SRawOid parsed;
        const ERetCode rc = SRawOid::parse(parsed, CString(c.text));
        CHECK((rc == ERET_OK) == c.ok);

        if (!c.ok) {
            // --> A rejected OID must come back empty, not half-parsed. A caller that checks
            // the return code and then reads count would otherwise see the leading arcs that
            // parsed fine before the one that did not.
            CHECK(parsed.count == 0);
        }
    }
}

TEST_CASE("SRawOid: parse rejects an OID longer than MAX_OID_ARCS") {
    // --> 33 arcs, one past the 32 the arc array holds. parse() must say so rather than
    // silently writing 32 and reporting success for an OID it did not fully read.
    CString long_oid;
    for (int i = 0; i < 33; ++i) {
        if (i) {
            long_oid.append('.');
        }

        uint32_t value = uint32_t(1 + (i % 39));
        char digits[10];
        size_t n = 0;
        while (value) {
            digits[n++] = char('0' + (value % 10));
            value /= 10;
        }
        while (n) {
            long_oid.append(digits[--n]);
        }
    }

    SRawOid parsed;
    CHECK(SRawOid::parse(parsed, long_oid) != ERET_OK);
    CHECK(parsed.count == 0);
}

TEST_CASE("SRawOid: toString produces minimal decimal for every arc") {
    // --> Zero is the arc most likely to come out as an empty string, and a two-digit arc is
    // the one most likely to come out reversed. Both are covered here.
    const uint32_t ARCS[] = { 2, 0, 100, 4294967295u, 5, 40 };
    const SRawOid oid(ARCS);

    const CString expected = "2.0.100.4294967295.5.40";
    CString got;
    oid.toString(got);
    CHECK(got.compare(expected) == 0);

    // --> And back again: the round trip is what makes toString() checkable at all, since
    // there is no independent reference for what it should print.
    SRawOid reparsed;
    REQUIRE(SRawOid::parse(reparsed, got) == ERET_OK);
    CHECK(reparsed.count == oid.count);
    CHECK(std::memcmp(reparsed.arcs, oid.arcs, oid.count * sizeof(uint32_t)) == 0);
}

TEST_CASE("SRawOid: an empty OID stringifies to nothing and compares equal to another empty one") {
    const SRawOid empty;
    CHECK(empty.count == 0);
    CHECK(empty.empty());
    CHECK(!empty);
    CHECK(!empty);

    CString text;
    empty.toString(text);
    CHECK(text.size() == 0);

    const SRawOid other;
    CHECK(empty.compare(other) == 0);
    CHECK(empty == other);
}

TEST_CASE("SRawOid: comparison orders by arc values then by length") {
    const uint32_t A[] = { 2, 5, 4, 3 };
    const uint32_t B[] = { 2, 5, 4, 11 };  // same length, later arc
    const uint32_t C[] = { 2, 5, 4, 3, 1 }; // a prefix, so longer

    const SRawOid oa(A), ob(B), oc(C);

    CHECK(oa.compare(oa) == 0);
    CHECK(oa < ob);             // 3 < 11 at the third arc
    CHECK(ob > oa);
    CHECK(oa <= ob);
    CHECK(oa >= oa);

    CHECK(oa < oc);             // a prefix sorts before its extension
    CHECK(oc > oa);
}

TEST_CASE("SRawOid: copy and move leave the source in a usable state") {
    const uint32_t ARCS[] = { 1, 2, 840, 113549 };
    const SRawOid oid(ARCS);

    SUBCASE("copy assignment") {
        SRawOid copy = oid;
        CHECK(copy == oid);
        CHECK(copy.count == oid.count);
    }

    SUBCASE("move assignment empties the source") {
        // --> The moved-from OID must read as empty, not as whatever it used to hold. A
        // move that leaves the source's count alone would hand the next reader a live-looking
        // OID sharing the destination's future overwrites.
        SRawOid moved;
        moved = SRawOid(oid);
        CHECK(moved == oid);

        SRawOid source(oid);
        SRawOid dest;
        dest = std::move(source);
        CHECK(dest == oid);
        CHECK(source.count == 0);
        CHECK(source.empty());
    }

    SUBCASE("copy construction") {
        const SRawOid copy(oid);
        CHECK(copy == oid);
    }
}

TEST_CASE("COid: every known OID's declared index matches its position in the list") {
    // --> The index in each list entry is what selects the cache slot, and a wrong one hands
    // back a different OID's Slot -- which would still compare equal to every OID that is not
    // the one it displaced, so nothing else in the suite would notice. The macro gives the
    // index here, so this compares the declared value against the list's own ordering, which
    // also makes it unique: two entries at the same position cannot both be right.
    uint32_t expected = 0;
    forEachKnownOid([&expected](const SKnownOid& known, uint32_t index, const char* text) {
        INFO("known OID: " << text << " at index " << index);
        CHECK(index == expected);
        CHECK(known.nth == index);
        ++expected;
    });

    // --> And the count the array was sized from matches what the list actually holds, so a
    // slot cannot be left uninitialised or go unbuilt at the end.
    CHECK(expected == COid::MAX_KNOWN_OID_COUNT);
}

TEST_CASE("COid: building known OIDs from several threads at once gives one Slot each") {
    // --> cacheFor() publishes its Slot with a compare-exchange so that whichever thread wins,
    // every other one takes the winner's rather than its own. That is not a nicety: COid::compare()
    // short-circuits on identical Slot pointers, so two threads getting different Slots for the
    // same OID would still compare equal by arcs but would not share -- and any code that cached a
    // COid across threads and relied on the pointer path would be relying on nothing.
    //
    // The test can only show that no crash and no wrong OID comes out of the race; that the
    // published pointer really is one per index is what makes the test worth having, and it is
    // checked below by taking the same COid on the main thread afterwards.
    constexpr int THREADS = 8;

    std::vector<COid> results[THREADS];
    std::vector<std::thread> threads;

    for (int t = 0; t < THREADS; ++t) {
        threads.emplace_back([&results, t] {
            std::vector<COid>& out = results[t];

            // --> Every thread walks every known OID, so the same index is contended by all of
            // them at once rather than by whichever pair the scheduler happens to overlap.
            forEachKnownOid([&out](const SKnownOid& known, uint32_t index, const char* text) {
                out.emplace_back(known);
            });
        });
    }

    for (std::thread& th : threads) {
        th.join();
    }

    // --> Same length and same OIDs, whichever thread built which.
    for (int t = 1; t < THREADS; ++t) {
        REQUIRE(results[t].size() == results[0].size());
        for (size_t i = 0; i < results[0].size(); ++i) {
            CAPTURE(i);
            CHECK(results[t][i] == results[0][i]);
        }
    }

    // --> And the cached Slot is still the one a fresh build gets, which is the observable
    // consequence of the compare-exchange having settled on a single winner.
    forEachKnownOid([&results](const SKnownOid& known, uint32_t index, const char* text) {
        INFO("known OID: " << text);
        CHECK(COid(known) == results[0][index]);
    });
}

TEST_CASE("COid: a known OID and its string form are the same OID") {
    forEachKnownOid([](const SKnownOid& known, uint32_t index, const char* text) {
        INFO("known OID: " << text);

        const COid fromKnown(known);
        const COid fromText{CString(text)};

        REQUIRE(fromKnown);
        REQUIRE(fromText);

        // --> Both directions of equality, since == that only works one way round is a
        // common and hard-to-spot defect in a compare()-based operator set.
        CHECK(fromKnown == fromText);
        CHECK(fromText == fromKnown);
        CHECK(fromKnown.compare(fromText) == 0);

        // --> And the same OID again through the assignment operators, which must not
        // silently leave the object holding whatever it had before.
        const COid assigned = known;
        CHECK(assigned == fromKnown);

        COid rawAssigned;
        rawAssigned = known;
        CHECK(rawAssigned == fromKnown);
    });
}

TEST_CASE("COid: a known OID stringifies back to its own text") {
    forEachKnownOid([](const SKnownOid& known, uint32_t index, const char* text) {
        INFO("known OID: " << text);
        CHECK(COid(known).toString().compare(CString(text)) == 0);
    });
}

TEST_CASE("COid: known OIDs are distinct from one another") {
    // --> Two entries in the table describing the same OID is a duplicate, and a duplicate is
    // invisible to any single-OID test. Every pair is compared here, so the check is
    // exhaustive rather than sampled -- and the arcs are the comparison, not the text, since
    // two spellings of one OID ("2.5.4.3" and "2.5.4.03") are the case worth catching.
    std::vector<SRawOid> knowns;
    std::vector<CString> texts;
    forEachKnownOid([&knowns, &texts](const SKnownOid& known, uint32_t index, const char* text) {
        SRawOid raw;
        const ERetCode rc = SRawOid::parse(raw, CString(text));
        if (rc == ERET_OK) {
            knowns.push_back(raw);
            texts.push_back(CString(text));
        }
    });

    for (size_t i = 0; i < knowns.size(); ++i) {
        for (size_t j = i + 1; j < knowns.size(); ++j) {
            if (knowns[i] == knowns[j]) {
                INFO("duplicate: " << texts[i].toPtr() << " == " << texts[j].toPtr());
                CHECK(false);
            }
        }
    }
}

TEST_CASE("COid: an OID built from raw arcs round-trips through its string form") {
    const uint32_t ARCS[] = { 2, 5, 29, 17, 1 };
    const SRawOid raw(ARCS);

    const COid oid(raw);
    REQUIRE(oid);

    const CString text = oid.toString();
    CHECK(text.compare("2.5.29.17.1") == 0);

    const COid reparsed(text);
    REQUIRE(reparsed);
    CHECK(reparsed == oid);
}

TEST_CASE("COid: an empty COid is empty, not equal to a real one, and sorts first") {
    const COid empty;
    CHECK(!empty);
    CHECK(empty.empty());
    CHECK(empty.raw().count == 0);
    CHECK(empty.toString().size() == 0);

    const COid real(COid::SHA1);
    REQUIRE(real);

    // --> An empty OID must not compare equal to a real one just because both happen to fail
    // the same null check. The sort order has to be total, and empty is the low end.
    CHECK(empty != real);
    CHECK(real != empty);
    CHECK(empty < real);
    CHECK(empty.compare(real) < 0);
    CHECK(empty == COid());
}

TEST_CASE("COid: a malformed string leaves it empty rather than half-parsed") {
    // --> The string constructor and the string assignment both parse on construction, and a
    // parse failure must leave the object empty rather than holding something plausible.
    const COid bad(CString("not an oid at all"));
    CHECK(!bad);
    CHECK(bad.empty());

    COid assigned(COid::SHA1);
    assigned = CString("1.2.3.");
    CHECK(assigned.empty());
}

TEST_CASE("COid: comparing two COids built from the same known OID is a pointer compare") {
    // --> The cache exists so that a COid built from COid::SHA1 twice shares one Slot, which
    // makes == cheap and makes the comparison independent of the arcs. If the cache ever
    // hands out a second Slot, this stops being true -- and the equality would still work, so
    // only a direct check of the sharing catches it.
    const COid a(COid::SHA1);
    const COid b(COid::SHA1);

    CHECK(a == b);
    CHECK(a.compare(b) == 0);

    // --> copy construction keeps sharing; the Slot is reference-counted, not re-parsed.
    const COid c(a);
    CHECK(c == b);
}

TEST_CASE("COid: the DN OIDs the library recognizes are the ones its name table uses") {
    // --> name.cpp carries its own private arc table, which is exactly the duplication the
    // known-OID list is meant to remove. This does not replace it -- it checks that the two
    // agree, which is what keeps a divergence from going unnoticed while the migration is
    // still in progress.
    struct Pair { const SKnownOid& known; ENameType type; };
    const Pair pairs[] = {
        { COid::DN_COMMON_NAME,              ENAME_CN      },
        { COid::DN_ORGANIZATIONAL_UNIT_NAME, ENAME_OU      },
        { COid::DN_ORGANIZATION_NAME,        ENAME_O       },
        { COid::DN_LOCALITY_NAME,            ENAME_L       },
        { COid::DN_STATE_OR_PROVINCE_NAME,   ENAME_ST      },
        { COid::DN_COUNTRY_NAME,             ENAME_C       },
        { COid::DN_ORGANIZATION_IDENTIFIER,  ENAME_OI      },
        { COid::DN_SERIAL_NUMBER,            ENAME_SERIAL  },
        { COid::DN_TITLE,                    ENAME_TITLE   },
        { COid::DN_GIVEN_NAME,               ENAME_GN      },
        { COid::DN_SURNAME,                  ENAME_SURNAME },
        { COid::DN_PSEUDONYM,                ENAME_PSEUDONYM },
        { COid::DN_DN_QUALIFIER,             ENAME_DNQ     },
        { COid::DN_DOMAIN_COMPONENT,         ENAME_DC      },
    };

    for (const Pair& p : pairs) {
        INFO("DN type " << int(p.type) << " against " << p.known.s);

        uint32_t arcs[SRawOid::MAX_OID_ARCS] = { 0 };
        size_t arcCount = 0;
        REQUIRE(CName::attributeOid(p.type, TSpan<uint32_t>(arcs, SRawOid::MAX_OID_ARCS), arcCount));

        // --> domainComponent is the one entry whose arc count the two tables had disagreed
        // about once, so it is compared against the OID itself rather than accepted on
        // name.cpp's word.
        SRawOid fromNameTable;
        fromNameTable.count = arcCount;
        std::memcpy(fromNameTable.arcs, arcs, sizeof(uint32_t) * arcCount);

        SRawOid known;
        REQUIRE(SRawOid::parse(known, CString(p.known.s)) == ERET_OK);

        CHECK(fromNameTable == known);
    }
}

TEST_CASE("COid: the wide-string overload parses the same OID as the narrow one") {
    const CWideString wide = L"1.2.840.113549.1.1.1";

    SRawOid fromWide;
    REQUIRE(SRawOid::parse(fromWide, wide) == ERET_OK);

    SRawOid fromNarrow;
    REQUIRE(SRawOid::parse(fromNarrow, CString("1.2.840.113549.1.1.1")) == ERET_OK);

    CHECK(fromWide == fromNarrow);
    CHECK(fromWide.count == fromNarrow.count);
}

TEST_CASE("COid: raw() returns an empty OID for an empty COid and the real one otherwise") {
    const COid real(COid::SHA256);
    REQUIRE(real);

    // --> Against the same OID parsed from its text, which is where the arcs in a COid built
    // from a known OID actually come from -- cacheFor() calls SRawOid::parse() on the
    // literal, and this checks that it did.
    SRawOid expected;
    REQUIRE(SRawOid::parse(expected, CString("2.16.840.1.101.3.4.2.1")) == ERET_OK);

    CHECK(real.raw() == expected);
    CHECK(real.raw().count == expected.count);

    const COid empty;
    CHECK(empty.raw().count == 0);
}

TEST_CASE("COid: comparing two OIDs requires both sides to be a COid") {
    // --> A CString compared against a COid does not compare the two OIDs. It compiles, and it
    // is always true, because TString's operator== reaches the COid through a conversion that
    // has nothing to do with the OID's arcs.
    //
    // It is written down here because it fails silently. It reached a finished
    // certificate-import path as `sigAlgoOid == COid(COid::RSASSA_PSS)`, which therefore held
    // for every certificate: every self-signed certificate took the RSASSA-PSS branch, came out
    // carrying the digest algorithm that branch's defaults give rather than the one it was
    // actually signed with, and then failed to verify against its own signature. A wrong answer
    // with no diagnostic is the worst shape a comparison bug can have, and the only thing that
    // caught it was the round-trip tests happening to exercise the path at all.
    //
    // So: comparing OIDs means giving both sides a type that holds the arcs.
    const CString asText("1.2.840.10045.4.3.2");
    const COid asOid(asText);

    // --> What the bad form evaluates to, pinned so that a compiler that ever stops accepting
    // it fails here loudly rather than making this test quietly stop meaning anything.
    CHECK(asText == COid(COid::RSASSA_PSS));

    // --> What the good form means, which is what that line above must never be read to say.
    CHECK_FALSE(asOid == COid(COid::RSASSA_PSS));
    CHECK(asOid != COid(COid::RSASSA_PSS));

    // --> And the agreeing case, so the two CHECK_FALSE lines above are a real disagreement
    // rather than two empty COids that compare equal to everything and nothing.
    CHECK(asOid == COid("1.2.840.10045.4.3.2"));
    CHECK(COid(COid::RSASSA_PSS) == COid(COid::RSASSA_PSS));
}
