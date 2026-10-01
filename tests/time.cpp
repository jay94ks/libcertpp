#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/time.hpp>
#include <ctime>

using namespace certpp;

// ---------------------------------------------------------------------------
// STimeSpan
// ---------------------------------------------------------------------------

TEST_CASE("STimeSpan default construction") {
    STimeSpan span;
    CHECK(span.milliseconds == 0);
}

TEST_CASE("STimeSpan::absolute") {
    CHECK(STimeSpan(-5000).absolute().milliseconds == 5000);
    CHECK(STimeSpan(5000).absolute().milliseconds == 5000);
    CHECK(STimeSpan(0).absolute().milliseconds == 0);
}

TEST_CASE("STimeSpan unit breakdown for a known duration") {
    // 1 week + 2 days + 3 hours + 4 minutes + 5 seconds + 6 ms.
    int64_t ms = ((((int64_t(1) * 7 + 2) * 24 + 3) * 60 + 4) * 60 + 5) * 1000 + 6;
    STimeSpan span(ms);

    CHECK(span.totalWeeks() == 1);
    CHECK(span.daysInWeek() == 2);
    CHECK(span.totalDays() == 9);
    CHECK(span.hours() == 3);
    CHECK(span.totalHours() == 219);
    CHECK(span.minutes() == 4);
    CHECK(span.totalMinutes() == 13144);
    CHECK(span.seconds() == 5);
    CHECK(span.totalSeconds() == 788645);
}

TEST_CASE("STimeSpan zero duration") {
    STimeSpan span(0);

    CHECK(span.totalWeeks() == 0);
    CHECK(span.daysInWeek() == 0);
    CHECK(span.totalDays() == 0);
    CHECK(span.hours() == 0);
    CHECK(span.totalHours() == 0);
    CHECK(span.minutes() == 0);
    CHECK(span.totalMinutes() == 0);
    CHECK(span.seconds() == 0);
    CHECK(span.totalSeconds() == 0);
}

TEST_CASE("STimeSpan accessors use the magnitude, ignoring sign") {
    // 1 day, 1 hour, 1 minute, 1 second.
    STimeSpan positive(90061000);
    STimeSpan negative(-90061000);

    CHECK(positive.totalSeconds() == negative.totalSeconds());
    CHECK(positive.totalHours() == negative.totalHours());
    CHECK(positive.hours() == negative.hours());
    CHECK(positive.minutes() == negative.minutes());
    CHECK(positive.seconds() == negative.seconds());

    // The raw field is the only place the sign survives.
    CHECK(positive.milliseconds == 90061000);
    CHECK(negative.milliseconds == -90061000);
}

TEST_CASE("STimeSpan arithmetic operators") {
    STimeSpan a(1000), b(400);

    CHECK((a + b).milliseconds == 1400);
    CHECK((a - b).milliseconds == 600);
    CHECK((-a).milliseconds == -1000);
    CHECK((-STimeSpan(-1000)).milliseconds == 1000);

    STimeSpan c = a;
    c += b;
    CHECK(c.milliseconds == 1400);

    STimeSpan d = a;
    d -= b;
    CHECK(d.milliseconds == 600);
}

TEST_CASE("STimeSpan comparison operators") {
    STimeSpan a(1000), b(2000), c(1000);

    CHECK(a == c);
    CHECK_FALSE(a == b);
    CHECK(a != b);
    CHECK_FALSE(a != c);

    CHECK(a < b);
    CHECK_FALSE(b < a);
    CHECK(a <= c);
    CHECK(a <= b);
    CHECK(b > a);
    CHECK_FALSE(a > b);
    CHECK(a >= c);
    CHECK(b >= a);
}

// STimeSpan's accessors and operators are constexpr; verify they're usable at compile time.
static_assert(STimeSpan(90061000).totalHours() == 25, "STimeSpan arithmetic must be usable at compile time");
static_assert(STimeSpan(90061000).hours() == 1, "STimeSpan arithmetic must be usable at compile time");
static_assert(STimeSpan(-90061000).totalHours() == 25, "STimeSpan::absolute() must apply at compile time too");
static_assert((STimeSpan(1000) + STimeSpan(400)).milliseconds == 1400, "STimeSpan operators must be constexpr");
static_assert(STimeSpan(1000) < STimeSpan(2000), "STimeSpan comparisons must be constexpr");

// ---------------------------------------------------------------------------
// SDateTime
// ---------------------------------------------------------------------------

TEST_CASE("SDateTime default construction") {
    SDateTime t;

    CHECK(t.year == 0);
    CHECK(t.month == 0);
    CHECK(t.day == 0);
    CHECK(t.hour == 0);
    CHECK(t.minute == 0);
    CHECK(t.second == 0);
    CHECK(t.millisecond == 0);
    CHECK_FALSE(t.isUtc);
}

TEST_CASE("SDateTime parameterized construction") {
    SDateTime t(2025, 1, 31, 12, 30, 45, 500, true);

    CHECK(t.year == 2025);
    CHECK(t.month == 1);
    CHECK(t.day == 31);
    CHECK(t.hour == 12);
    CHECK(t.minute == 30);
    CHECK(t.second == 45);
    CHECK(t.millisecond == 500);
    CHECK(t.isUtc);
}

TEST_CASE("SDateTime::isZero") {
    CHECK(SDateTime().isZero());
    CHECK(SDateTime(0, 0, 0, 0, 0, 0, 0, true).isZero()); // isUtc doesn't factor into "zero"
    CHECK_FALSE(SDateTime(2025, 1, 1, 0, 0, 0, 0, false).isZero());
    CHECK_FALSE(SDateTime(0, 0, 0, 0, 0, 0, 1, false).isZero()); // nonzero millisecond only
}

TEST_CASE("SDateTime::from(0, true) returns the Unix epoch in UTC") {
    SDateTime epoch = SDateTime::from(0, true);

    CHECK(epoch.year == 1970);
    CHECK(epoch.month == 1);
    CHECK(epoch.day == 1);
    CHECK(epoch.hour == 0);
    CHECK(epoch.minute == 0);
    CHECK(epoch.second == 0);
    CHECK(epoch.isUtc);
}

TEST_CASE("SDateTime::from(0) (asUtc defaults to false) returns the epoch in local time") {
    // The exact fields are timezone-dependent (the epoch instant, expressed locally), so only
    // isUtc and internal consistency with toLocal() are checked here, not specific field values.
    SDateTime local = SDateTime::from(0);
    SDateTime epochAsLocal = SDateTime::from(0, true).toLocal();

    CHECK_FALSE(local.isUtc);
    CHECK(local.year == epochAsLocal.year);
    CHECK(local.month == epochAsLocal.month);
    CHECK(local.day == epochAsLocal.day);
    CHECK(local.hour == epochAsLocal.hour);
    CHECK(local.minute == epochAsLocal.minute);
    CHECK(local.second == epochAsLocal.second);
}

TEST_CASE("SDateTime::from(ms, true) decodes milliseconds since the epoch directly") {
    // 2005-01-01 00:00:00 UTC = 1104537600 s after the epoch. asUtc=true never touches
    // mktime()/localtime(), so this doesn't depend on the local timezone.
    SDateTime t = SDateTime::from(uint64_t(1104537600) * 1000 + 250, true);

    REQUIRE(t.isUtc);
    CHECK(t.year == 2005);
    CHECK(t.month == 1);
    CHECK(t.day == 1);
    CHECK(t.hour == 0);
    CHECK(t.minute == 0);
    CHECK(t.second == 0);
    CHECK(t.millisecond == 250);
}

TEST_CASE("SDateTime::toUtc / toLocal are no-ops when already in the target representation") {
    SDateTime utc(2025, 1, 31, 12, 0, 0, 0, true);
    SDateTime local(2025, 1, 31, 12, 0, 0, 0, false);

    SDateTime utcResult = utc.toUtc();
    CHECK(utcResult.isUtc);
    CHECK(utcResult.year == utc.year);
    CHECK(utcResult.month == utc.month);
    CHECK(utcResult.day == utc.day);
    CHECK(utcResult.hour == utc.hour);
    CHECK(utcResult.minute == utc.minute);
    CHECK(utcResult.second == utc.second);

    SDateTime localResult = local.toLocal();
    CHECK_FALSE(localResult.isUtc);
    CHECK(localResult.year == local.year);
    CHECK(localResult.month == local.month);
    CHECK(localResult.day == local.day);
    CHECK(localResult.hour == local.hour);
    CHECK(localResult.minute == local.minute);
    CHECK(localResult.second == local.second);
}

TEST_CASE("SDateTime::toUtc / toLocal round-trip a local time back to itself") {
    // Whatever the machine's local timezone is, converting local -> UTC -> local
    // should reproduce the original wall-clock fields.
    SDateTime local(2025, 6, 15, 12, 0, 0, 0, false);

    SDateTime utc = local.toUtc();
    CHECK(utc.isUtc);

    SDateTime backToLocal = utc.toLocal();
    CHECK_FALSE(backToLocal.isUtc);
    CHECK(backToLocal.year == local.year);
    CHECK(backToLocal.month == local.month);
    CHECK(backToLocal.day == local.day);
    CHECK(backToLocal.hour == local.hour);
    CHECK(backToLocal.minute == local.minute);
    CHECK(backToLocal.second == local.second);
}

TEST_CASE("SDateTime::toSeconds returns the Unix epoch second count for a UTC time") {
    // Reference points chosen so this test doesn't depend on the local timezone.
    CHECK(SDateTime(1970, 1, 1, 0, 0, 0, 0, true).toSeconds() == 0);
    CHECK(SDateTime(1970, 1, 1, 0, 0, 1, 0, true).toSeconds() == 1);
    CHECK(SDateTime(2005, 1, 1, 0, 0, 0, 0, true).toSeconds() == 1104537600);
}

TEST_CASE("SDateTime::toMilliseconds adds the millisecond field to toSeconds()*1000") {
    SDateTime t(1970, 1, 1, 0, 0, 1, 500, true);
    CHECK(t.toMilliseconds() == t.toSeconds() * 1000 + 500);
}

TEST_CASE("SDateTime::diff computes the millisecond difference between two same-representation times") {
    // Both operands share isUtc and a nearby instant (same day, no DST boundary in between),
    // so this is robust even if toSeconds()'s absolute value is timezone-skewed.
    SDateTime a(2025, 3, 10, 12, 0, 10, 500, true);
    SDateTime b(2025, 3, 10, 12, 0, 5, 100, true);

    CHECK(a.diff(b).milliseconds == 5400); // 5.4 seconds
    CHECK(b.diff(a).milliseconds == -5400);
}

TEST_CASE("SDateTime::add / subtract(milliseconds) round-trip") {
    SDateTime start(2025, 6, 15, 12, 0, 0, 0, true);
    const uint64_t delta = 90061000; // 1d 1h 1m 1s

    SDateTime later = start.add(delta);
    CHECK(later.diff(start).milliseconds == int64_t(delta));

    SDateTime back = later.subtract(delta);
    CHECK(back.diff(start).milliseconds == 0);
}

TEST_CASE("SDateTime::add(0) / subtract(0) return the instance unchanged") {
    SDateTime t(2025, 6, 15, 12, 0, 0, 0, true);

    CHECK(t.add(uint64_t(0)).diff(t).milliseconds == 0);
    CHECK(t.subtract(uint64_t(0)).diff(t).milliseconds == 0);
}

TEST_CASE("STimeSpan-based add/subtract are consistent with the millisecond overloads") {
    SDateTime start(2025, 6, 15, 12, 0, 0, 0, true);
    STimeSpan span(5000);

    SDateTime viaSpan = start.add(span);
    SDateTime viaMs = start.add(uint64_t(5000));
    CHECK(viaSpan.diff(viaMs).milliseconds == 0);
    CHECK((start + span).diff(viaSpan).milliseconds == 0);

    SDateTime subViaSpan = start.subtract(span);
    SDateTime subViaMs = start.subtract(uint64_t(5000));
    CHECK(subViaSpan.diff(subViaMs).milliseconds == 0);
    CHECK((start - span).diff(subViaSpan).milliseconds == 0);

    SDateTime compound = start;
    compound += span;
    CHECK(compound.diff(viaSpan).milliseconds == 0);

    compound -= span;
    CHECK(compound.diff(start).milliseconds == 0);
}

TEST_CASE("SDateTime::now returns the actual current wall-clock time") {
    SDateTime local = SDateTime::now(false);
    SDateTime utc = SDateTime::now(true);

    CHECK_FALSE(local.isUtc);
    CHECK(utc.isUtc);

    // Compared against <ctime> directly (not SDateTime::toUtc()/toSeconds()) so this doesn't
    // depend on any other SDateTime conversion being correct. Only the year is checked for
    // equality (safe from flakiness around a day/DST boundary); month/day just get range checks.
    std::time_t now = std::time(nullptr);
    std::tm refLocal = *std::localtime(&now);
    std::tm refUtc = *std::gmtime(&now);

    CHECK(local.year == uint16_t(refLocal.tm_year + 1900));
    CHECK(local.month >= 1);
    CHECK(local.month <= 12);
    CHECK(local.day >= 1);
    CHECK(local.day <= 31);

    CHECK(utc.year == uint16_t(refUtc.tm_year + 1900));
    CHECK(utc.month >= 1);
    CHECK(utc.month <= 12);
    CHECK(utc.day >= 1);
    CHECK(utc.day <= 31);
}
