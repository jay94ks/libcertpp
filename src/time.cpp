#include <certpp/time.hpp>
#include <ctime>

namespace certpp {

    /* Thread-safe wrapper for gmtime. */
    bool SDateTime::gmtimeSafe(const std::time_t* time, std::tm* result) noexcept {
        #if defined(_WIN32) || defined(_WIN64)
            return gmtime_s(result, time) == 0;
        #else
            return gmtime_r(time, result) != nullptr;
        #endif
    }

    /* Thread-safe wrapper for localtime. */
    bool SDateTime::localtimeSafe(const std::time_t* time, std::tm* result) noexcept {
        #if defined(_WIN32) || defined(_WIN64)
            return localtime_s(result, time) == 0;
        #else
            return localtime_r(time, result) != nullptr;
        #endif
    }

    /* Converts a UTC-valued tm to a time_t -- the inverse of gmtime(), which mktime() is NOT
     * (mktime() always interprets its argument as local time). */
    bool SDateTime::mkgmtimeSafe(std::tm* time, std::time_t* result) noexcept {
        #if defined(_WIN32) || defined(_WIN64)
            *result = _mkgmtime(time);
        #else
            *result = timegm(time);
        #endif

        return *result != static_cast<std::time_t>(-1);
    }

    /* Returns the current time as an SDateTime instance. */
    SDateTime SDateTime::now(bool asUtc) noexcept {
        if (asUtc) {
            return now(false).toUtc();
        }

        std::time_t now = std::time(nullptr);
        std::tm tm;

        SDateTime ret;

        if (asUtc) {
            if (!gmtimeSafe(&now, &tm)) {
                return SDateTime();
            }

            ret.isUtc = true;
            ret.year = static_cast<uint16_t>(tm.tm_year + 1900);
            ret.month = static_cast<uint8_t>(tm.tm_mon + 1);
            ret.day = static_cast<uint8_t>(tm.tm_mday);
            ret.hour = static_cast<uint8_t>(tm.tm_hour);
            ret.minute = static_cast<uint8_t>(tm.tm_min);
            ret.second = static_cast<uint8_t>(tm.tm_sec);
            ret.millisecond = 0; // Milliseconds are not available from std::tm
        } else {
            if (!localtimeSafe(&now, &tm)) {
                return SDateTime();
            }

            ret.isUtc = false;
            ret.year = static_cast<uint16_t>(tm.tm_year + 1900);
            ret.month = static_cast<uint8_t>(tm.tm_mon + 1);
            ret.day = static_cast<uint8_t>(tm.tm_mday);
            ret.hour = static_cast<uint8_t>(tm.tm_hour);
            ret.minute = static_cast<uint8_t>(tm.tm_min);
            ret.second = static_cast<uint8_t>(tm.tm_sec);
            ret.millisecond = 0; // Milliseconds are not available from std::tm
        }

        return ret;
    }

    /* Constructs an SDateTime instance from the specified number of milliseconds from the Unix epoch (1970-01-01 00:00:00 UTC). */
    SDateTime SDateTime::from(uint64_t ms, bool asUtc) noexcept {
        if (ms == 0) {
            static constexpr SDateTime UNIX_EPOCH = { 1970, 1, 1, 0, 0, 0, 0, true };
            return asUtc ? UNIX_EPOCH : UNIX_EPOCH.toLocal();
        }

        std::time_t seconds = static_cast<std::time_t>(ms / 1000);
        std::tm tm;

        // --> seconds is already a real time_t for the target instant, so no mktime()
        // round-trip is needed either way: just ask for whichever representation is wanted.
        if (asUtc) {
            if (!gmtimeSafe(&seconds, &tm)) {
                return SDateTime(); // --> Return a default-constructed SDateTime instance if conversion fails.
            }
        } else {
            if (!localtimeSafe(&seconds, &tm)) {
                return SDateTime();
            }
        }

        SDateTime result;

        result.isUtc = asUtc;
        result.year = static_cast<uint16_t>(tm.tm_year + 1900);
        result.month = static_cast<uint8_t>(tm.tm_mon + 1);
        result.day = static_cast<uint8_t>(tm.tm_mday);
        result.hour = static_cast<uint8_t>(tm.tm_hour);
        result.minute = static_cast<uint8_t>(tm.tm_min);
        result.second = static_cast<uint8_t>(tm.tm_sec);
        result.millisecond = static_cast<uint16_t>(ms % 1000);

        return result;
    }

    /* Converts the SDateTime instance to UTC. */
    SDateTime SDateTime::toUtc() const noexcept {
        if (isUtc) {
            return *this;
        }

        if (year < 1900) {
            return SDateTime(); // --> Return a default-constructed SDateTime instance for invalid years.
        }

        std::tm localTm;

        // --> fill the localTm structure with the current SDateTime fields.
        localTm.tm_year = static_cast<int>(year) - 1900;
        localTm.tm_mon = static_cast<int>(month) - 1;
        localTm.tm_mday = static_cast<int>(day);
        localTm.tm_hour = static_cast<int>(hour);
        localTm.tm_min = static_cast<int>(minute);
        localTm.tm_sec = static_cast<int>(second);
        localTm.tm_isdst = -1;

        // --> then, convert it to a time_t representing UTC.
        std::time_t utc = std::mktime(&localTm);
        if (utc == -1) {
            return SDateTime(); // --> Return a default-constructed SDateTime instance if conversion fails.
        }

        std::tm utcTm;

        // --> fill the utcTm structure with the converted UTC time.
        if (!gmtimeSafe(&utc, &utcTm)) {
            return SDateTime(); // --> Return a default-constructed SDateTime instance if conversion fails.
        }

        SDateTime result;

        // --> fill the result SDateTime instance with the converted UTC time.
        result.isUtc = true;
        result.year = static_cast<uint16_t>(utcTm.tm_year + 1900);
        result.month = static_cast<uint8_t>(utcTm.tm_mon + 1);
        result.day = static_cast<uint8_t>(utcTm.tm_mday);
        result.hour = static_cast<uint8_t>(utcTm.tm_hour);
        result.minute = static_cast<uint8_t>(utcTm.tm_min);
        result.second = static_cast<uint8_t>(utcTm.tm_sec);

        // --> copy the millisecond value from the original SDateTime instance.
        result.millisecond = millisecond;

        return result;
    }

    /* Converts the SDateTime instance to local time. */
    SDateTime SDateTime::toLocal() const noexcept {
        if (!isUtc) {
            return *this;
        }

        if (year < 1900) {
            return SDateTime(); // --> Return a default-constructed SDateTime instance for invalid years.
        }

        std::tm utcTm;

        // --> fill the utcTm structure with the current SDateTime fields.
        utcTm.tm_year = static_cast<int>(year) - 1900;
        utcTm.tm_mon = static_cast<int>(month) - 1;
        utcTm.tm_mday = static_cast<int>(day);
        utcTm.tm_hour = static_cast<int>(hour);
        utcTm.tm_min = static_cast<int>(minute);
        utcTm.tm_sec = static_cast<int>(second);
        utcTm.tm_isdst = 0;

        // --> then, convert it (as UTC, not local -- utcTm holds UTC fields) to a time_t.
        std::time_t local;
        if (!mkgmtimeSafe(&utcTm, &local)) {
            return SDateTime(); // --> Return a default-constructed SDateTime instance if conversion fails.
        }

        std::tm localTm;

        // --> fill the localTm structure with the converted local time.
        if (!localtimeSafe(&local, &localTm)) {
            return SDateTime(); // --> Return a default-constructed SDateTime instance if conversion fails.
        }

        SDateTime result;

        // --> fill the result SDateTime instance with the converted local time.
        result.isUtc = false;
        result.year = static_cast<uint16_t>(localTm.tm_year + 1900);
        result.month = static_cast<uint8_t>(localTm.tm_mon + 1);
        result.day = static_cast<uint8_t>(localTm.tm_mday);
        result.hour = static_cast<uint8_t>(localTm.tm_hour);
        result.minute = static_cast<uint8_t>(localTm.tm_min);
        result.second = static_cast<uint8_t>(localTm.tm_sec);

        // --> copy the millisecond value from the original SDateTime instance.
        result.millisecond = millisecond;

        return result;
    }

    /* Converts the SDateTime instance to the number of seconds. */
    uint64_t SDateTime::toSeconds() const noexcept {
        std::tm tm;

        if (year < 1900) {
            return 0;
        }

        // --> fill the tm structure with the current SDateTime fields.
        tm.tm_year = static_cast<int>(year) - 1900;
        tm.tm_mon = static_cast<int>(month) - 1;
        tm.tm_mday = static_cast<int>(day);
        tm.tm_hour = static_cast<int>(hour);
        tm.tm_min = static_cast<int>(minute);
        tm.tm_sec = static_cast<int>(second);
        tm.tm_isdst = -1;

        // --> tm_isdst here genuinely matters: tm holds local fields, and mktime() is the
        // correct (local tm -> time_t) direction, so it's the one case that's already right.
        if (!isUtc) {
            std::time_t local = std::mktime(&tm);
            if (local == -1) {
                return 0;
            }

            return static_cast<uint64_t>(local);
        }

        // --> tm holds UTC fields here, so this needs the UTC (tm -> time_t) direction,
        // not mktime() (which would treat tm as local and apply the zone offset wrongly).
        std::time_t utc;
        if (!mkgmtimeSafe(&tm, &utc)) {
            return 0;
        }

        return static_cast<uint64_t>(utc);
    }

    /* Converts the SDateTime instance to the number of milliseconds. */
    uint64_t SDateTime::toMilliseconds() const noexcept {
        return toSeconds() * 1000 + uint64_t(millisecond);
    }

    void SDateTime::ensureResultDateTime(SDateTime& ret, const SDateTime& src) {
        if (ret.isZero()) {
            ret.isUtc = src.isUtc; // --> Preserve the original isUtc flag if the result is zero.
            return;
        }

        if (ret.isUtc == src.isUtc) {
            return; // --> No conversion needed if the UTC flags match.
        }

        if (src.isUtc) {
            ret = ret.toUtc();
        } else {
            ret = ret.toLocal();
        }
    }

    /* Adds the specified number of milliseconds to the SDateTime instance. */
    SDateTime SDateTime::add(uint64_t ms) const noexcept {
        if (ms == 0) {
            return *this; // --> If the number of milliseconds to add is zero, return the current instance.
        }

        // --> Convert the current SDateTime instance to milliseconds since the Unix epoch.
        uint64_t result = toMilliseconds();

        if ((result += ms) < ms) {
            result = UINT64_MAX; // --> Handle overflow by setting to the maximum possible value.
        }

        // --
        auto ret = SDateTime::from(result, true);
        ensureResultDateTime(ret, *this);

        return ret;
    }

    /* Subtracts the specified number of milliseconds from the SDateTime instance. */
    SDateTime SDateTime::subtract(uint64_t ms) const noexcept {
        if (ms == 0) {
            return *this; // --> If the number of milliseconds to subtract is zero, return the current instance.
        }

        // --> Convert the current SDateTime instance to milliseconds since the Unix epoch.
        uint64_t result = toMilliseconds();

        if (ms >= result) {
            return SDateTime(); // --> If the subtraction would result in a negative time, return a default SDateTime instance.
        }

        result -= ms;

        // --
        auto ret = SDateTime::from(result, true);
        ensureResultDateTime(ret, *this);

        return ret;
    }

    /* Adds a time span to the SDateTime instance. */
    SDateTime SDateTime::add(const STimeSpan& span) const noexcept {
        if (span.milliseconds == 0) {
            return *this; // --> If the time span is zero, return the current instance.
        }
        
        if (span.milliseconds > 0) {
            return add(static_cast<uint64_t>(span.milliseconds));
        }

        return subtract(static_cast<uint64_t>(-span.milliseconds));
    }

    /* Calculates the difference between the current SDateTime instance and another SDateTime instance. */
    STimeSpan SDateTime::diff(const SDateTime& other) const noexcept {
        int64_t sThis = int64_t(toSeconds());
        int64_t sOther = int64_t(other.toSeconds());
        
        int64_t dSec = (sThis - sOther) * 1000;
        dSec += (int64_t(millisecond) - int64_t(other.millisecond));

        return STimeSpan(dSec);
    }

} // namespace certpp