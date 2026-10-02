#ifndef __INCLUDE_CERTPP_TIME_HPP__
#define __INCLUDE_CERTPP_TIME_HPP__

#include <certpp/common.hpp>
#include <ctime>

namespace certpp {

    /**
     * Represents a time span or duration.
     * This structure represents a duration of time in terms of milliseconds.
     */
    struct STimeSpan {
        int64_t milliseconds;

        /**
         * Constructs an STimeSpan instance with the specified duration.
         */
        constexpr STimeSpan(int64_t ms = 0) noexcept
            : milliseconds(ms) {}

        /**
         * Returns the absolute value of the time span.
         * @return A new STimeSpan instance representing the absolute value of the duration.
         */
        constexpr STimeSpan absolute() const noexcept {
            return STimeSpan(milliseconds < 0 ? -milliseconds : milliseconds);
        }

        /**
         * Returns the total number of seconds represented by the time span.
         * @return The total number of seconds.
         */
        constexpr int64_t totalSeconds() const noexcept {
            return absolute().milliseconds / 1000;
        }

        /**
         * Returns the number of seconds represented by the time span, excluding complete minutes.
         * @return The number of seconds.
         */
        constexpr int64_t seconds() const noexcept {
            return totalSeconds() % 60;
        }

        /**
         * Returns the total number of minutes represented by the time span.
         * @return The total number of minutes.
         */
        constexpr int64_t totalMinutes() const noexcept {
            return absolute().milliseconds / (1000 * 60);
        }

        /**
         * Returns the number of minutes represented by the time span, excluding complete hours.
         * @return The number of minutes.
         */
        constexpr int64_t minutes() const noexcept {
            return totalMinutes() % 60;
        }
        
        /**
         * Returns the total number of hours represented by the time span.
         * @return The total number of hours.
         */
        constexpr int64_t totalHours() const noexcept {
            return absolute().milliseconds / (1000 * 60 * 60);
        }

        /**
         * Returns the number of hours represented by the time span, excluding complete days.
         * @return The number of hours.
         */
        constexpr int64_t hours() const noexcept {
            return totalHours() % 24;
        }
        
        /**
         * Returns the total number of days represented by the time span.
         * @return The total number of days.
         */
        constexpr int64_t totalDays() const noexcept {
            return absolute().milliseconds / (1000 * 60 * 60 * 24);
        }

        /**
         * Returns the number of days represented by the time span, excluding complete weeks.
         * @return The number of days.
         */
        constexpr int64_t daysInWeek() const noexcept {
            return totalDays() % 7;
        }

        /**
         * Returns the total number of weeks represented by the time span.
         * @return The total number of weeks.
         */
        constexpr int64_t totalWeeks() const noexcept {
            return absolute().milliseconds / (1000 * 60 * 60 * 24 * 7);
        }

        /**
         * Adds the specified time span to this time span.
         *
         * @param other The time span to add.
         * @return The resulting time span.
         */
        constexpr STimeSpan operator+(const STimeSpan& other) const noexcept {
            return STimeSpan(milliseconds + other.milliseconds);
        }

        /**
         * Subtracts the specified time span from this time span.
         *
         * @param other The time span to subtract.
         * @return The resulting time span.
         */
        constexpr STimeSpan operator-(const STimeSpan& other) const noexcept {
            return STimeSpan(milliseconds - other.milliseconds);
        }
        
        /**
         * Negates the time span.
         *
         * @return The resulting time span with the opposite sign.
         */
        constexpr STimeSpan operator-() const noexcept {
            return STimeSpan(-milliseconds);
        }

        /**
         * Adds the specified time span to this time span in-place.
         *
         * @param other The time span to add.
         * @return A reference to this time span after addition.
         */
        constexpr STimeSpan& operator+=(const STimeSpan& other) noexcept {
            milliseconds += other.milliseconds;
            return *this;
        }

        /**
         * Subtracts the specified time span from this time span in-place.
         *
         * @param other The time span to subtract.
         * @return A reference to this time span after subtraction.
         */
        constexpr STimeSpan& operator-=(const STimeSpan& other) noexcept {
            milliseconds -= other.milliseconds;
            return *this;
        }

        /**
         * Checks if this time span is equal to another time span.
         *
         * @param other The other time span to compare with.
         * @return True if the time spans are equal, false otherwise.
         */
        constexpr bool operator==(const STimeSpan& other) const noexcept {
            return milliseconds == other.milliseconds;
        }

        /**
         * Checks if this time span is not equal to another time span.
         *
         * @param other The other time span to compare with.
         * @return True if the time spans are not equal, false otherwise.
         */
        constexpr bool operator!=(const STimeSpan& other) const noexcept {
            return milliseconds != other.milliseconds;
        }

        /**
         * Checks if this time span is less than another time span.
         *
         * @param other The other time span to compare with.
         * @return True if this time span is less than the other time span, false otherwise.
         */
        constexpr bool operator<(const STimeSpan& other) const noexcept {
            return milliseconds < other.milliseconds;
        }

        /**
         * Checks if this time span is less than or equal to another time span.
         *
         * @param other The other time span to compare with.
         * @return True if this time span is less than or equal to the other time span, false otherwise.
         */
        constexpr bool operator<=(const STimeSpan& other) const noexcept {
            return milliseconds <= other.milliseconds;
        }

        /**
         * Checks if this time span is greater than another time span.
         *
         * @param other The other time span to compare with.
         * @return True if this time span is greater than the other time span, false otherwise.
         */
        constexpr bool operator>(const STimeSpan& other) const noexcept {
            return milliseconds > other.milliseconds;
        }

        /**
         * Checks if this time span is greater than or equal to another time span.
         *
         * @param other The other time span to compare with.
         * @return True if this time span is greater than or equal to the other time span, false otherwise.
         */
        constexpr bool operator>=(const STimeSpan& other) const noexcept {
            return milliseconds >= other.milliseconds;
        }
    };

    /**
     * Represents a point in time as decomposed calendar fields, as carried by
     * the ASN.1 UTCTime and GeneralizedTime types.
     */
    struct CERTPP_API SDateTime {
        uint16_t year;          // --> Full year (e.g. 2025). UTCTime's 2-digit year is expanded per RFC 5280 (>=50 -> 19xx, <50 -> 20xx).
        uint8_t month;          // --> 1-12.
        uint8_t day;            // --> 1-31.
        uint8_t hour;           // --> 0-23.
        uint8_t minute;         // --> 0-59.
        uint8_t second;         // --> 0-59.
        uint16_t millisecond;   // --> 0-999. Always 0 for UTCTime; GeneralizedTime only, from its optional fractional-seconds part.
        bool isUtc;             // --> True if the time is UTC ('Z' suffix). CEncoder only ever produces true (DER-canonical form).

        /**
         * Constructs an SDateTime instance with the specified fields.
         */
        constexpr SDateTime(uint16_t y = 0, uint8_t m = 0, uint8_t d = 0, uint8_t h = 0, uint8_t min = 0, uint8_t s = 0, uint16_t ms = 0, bool utc = false) noexcept
            : year(y), month(m), day(d), hour(h), minute(min), second(s), millisecond(ms), isUtc(utc) {}

        /**
         * Checks if this SDateTime instance represents the zero time (all fields are zero).
         *
         * @return True if all fields are zero, false otherwise.
         */
        constexpr bool isZero() const noexcept {
            return year == 0 && month == 0 && day == 0 && hour == 0 && minute == 0 && second == 0 && millisecond == 0;
        }

    private:
        /**
         * Thread-safe wrapper for gmtime.
         * @return True if the conversion was successful, false otherwise.
         */
        static bool gmtimeSafe(const std::time_t* time, std::tm* result) noexcept;

        /**
         * Thread-safe wrapper for localtime.
         * @return True if the conversion was successful, false otherwise.
         */
        static bool localtimeSafe(const std::time_t* time, std::tm* result) noexcept;

        /**
         * Converts a UTC-valued tm to a time_t -- the inverse of gmtime(), which mktime() is NOT
         * (mktime() always interprets its argument as local time). Uses _mkgmtime on MSVC and
         * the POSIX/glibc extension timegm() elsewhere.
         * @return True if the conversion was successful, false otherwise.
         */
        static bool mkgmtimeSafe(std::tm* time, std::time_t* result) noexcept;

        /**
         * Fills in ret's isUtc flag/UTC-vs-local representation to match what toUtc()/toLocal()
         * promise, given the original value src they were called on.
         */
        static void ensureResultDateTime(SDateTime& ret, const SDateTime& src);

    public:
        /**
         * Returns the current system time as an SDateTime instance, 
         * with the isUtc flag set to true.
         * @param asUtc If true, the returned SDateTime instance represents the current time in UTC. Otherwise, it represents the current local time.
         */
        static SDateTime now(bool asUtc = false) noexcept;

        /**
         * Constructs an SDateTime instance from the specified number of milliseconds from the Unix epoch (1970-01-01 00:00:00 UTC).
         * @param ms The number of milliseconds (unix timestamp).
         * @param asUtc If false, the returned SDateTime instance represents the local time. Otherwise, it represents the time in UTC.
         * @return A new SDateTime instance representing the specified point in time.
         */
        static SDateTime from(uint64_t ms, bool asUtc = false) noexcept;

        /**
         * Converts the SDateTime instance to UTC.
         * @return A new SDateTime instance representing the same point in time in UTC.
         */
        SDateTime toUtc() const noexcept;

        /**
         * Converts the SDateTime instance to the local time zone.
         * @return A new SDateTime instance representing the same point in time in the local time zone.
         */
        SDateTime toLocal() const noexcept;

        /**
         * Converts the SDateTime instance to the number of seconds.
         * @return The number of seconds (unix timestamp).
         */
        uint64_t toSeconds() const noexcept;

        /**
         * Converts the SDateTime instance to the number of milliseconds.
         * @return The number of milliseconds (unix timestamp style).
         */
        uint64_t toMilliseconds() const noexcept;

        /**
         * Adds the specified number of milliseconds to the SDateTime instance.
         * @param ms The number of milliseconds to add.
         * @return A new SDateTime instance representing the result of adding the milliseconds.
         */
        SDateTime add(uint64_t ms) const noexcept;

        /**
         * Subtracts the specified number of milliseconds from the SDateTime instance.
         * @param ms The number of milliseconds to subtract.
         * @return A new SDateTime instance representing the result of subtracting the milliseconds.
         */
        SDateTime subtract(uint64_t ms) const noexcept;

        /**
         * Adds a time span to the SDateTime instance.
         * @param span The time span to add.
         * @return A new SDateTime instance representing the result of adding the time span.
         */
        SDateTime add(const STimeSpan& span) const noexcept;

        /**
         * Subtracts a time span from the SDateTime instance.
         * @param span The time span to subtract.
         * @return A new SDateTime instance representing the result of subtracting the time span.
         */
        inline SDateTime subtract(const STimeSpan& span) const noexcept {
            return add(-span);
        }

        /**
         * Calculates the difference between the current SDateTime instance and another SDateTime instance.
         * @param other The other SDateTime instance to compare with.
         * @return A STimeSpan instance representing the difference between the two SDateTime instances.
         */
        STimeSpan diff(const SDateTime& other) const noexcept;

        /**
         * Adds a time span to the current SDateTime instance using the + operator.
         * @param span The time span to add.
         * @return A new SDateTime instance representing the result of adding the time span.
         */
        inline SDateTime operator+(const STimeSpan& span) const noexcept {
            return add(span);
        }

        /**
         * Subtracts a time span from the current SDateTime instance using the - operator.
         * @param span The time span to subtract.
         * @return A new SDateTime instance representing the result of subtracting the time span.
         */
        inline SDateTime operator-(const STimeSpan& span) const noexcept {
            return subtract(span);
        }

        /**
         * Adds a time span to the current SDateTime instance using the += operator.
         * @param span The time span to add.
         * @return A reference to the current SDateTime instance after adding the time span.
         */
        inline SDateTime operator+=(const STimeSpan& span) noexcept {
            *this = add(span);
            return *this;
        }

        /**
         * Subtracts a time span from the current SDateTime instance using the -= operator.
         * @param span The time span to subtract.
         * @return A reference to the current SDateTime instance after subtracting the time span.
         */
        inline SDateTime operator-=(const STimeSpan& span) noexcept {
            *this = subtract(span);
            return *this;
        }
    };

} // namespace certpp

#endif
