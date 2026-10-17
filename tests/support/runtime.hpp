#ifndef __TESTS_SUPPORT_RUNTIME_HPP__
#define __TESTS_SUPPORT_RUNTIME_HPP__

/* Forced into every test translation unit by CMake. Test failures must remain non-interactive:
 * a CRT assertion or abort in a CTest child process is diagnostic output, not a Windows dialog
 * that waits for somebody to press a button. */
#include <cstdlib>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOCRYPT
#define NOCRYPT
#endif
#if defined(_MSC_VER)
#include <crtdbg.h>
#endif
#include <windows.h>
#endif

namespace certpp_test_support {

    inline void configureNonInteractiveFailures() {
#if defined(_WIN32)
        SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS |
                     SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

#if defined(_MSC_VER)
        _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
        _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
        _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);

        // Keep abort() on stderr and prevent it from invoking Windows Error Reporting.
        _set_abort_behavior(_WRITE_ABORT_MSG, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#endif
    }

    struct RuntimeConfiguration {
        RuntimeConfiguration() {
            configureNonInteractiveFailures();
        }
    };

    // Internal linkage gives every test process a startup initializer even if no assertion fires.
    [[maybe_unused]] static const RuntimeConfiguration runtimeConfiguration;

} // namespace certpp_test_support

#endif // __TESTS_SUPPORT_RUNTIME_HPP__
