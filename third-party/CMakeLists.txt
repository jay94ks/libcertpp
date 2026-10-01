# doctest (https://github.com/doctest/doctest) is vendored as a single
# header under doctest/doctest.h. It's exposed as an INTERFACE target so
# test executables can `target_link_libraries(... PRIVATE doctest)` and
# `#include <doctest/doctest.h>` without CMake reaching outside this
# directory.
add_library(doctest INTERFACE)

target_include_directories(doctest INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
