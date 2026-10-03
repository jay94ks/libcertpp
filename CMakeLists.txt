cmake_minimum_required(VERSION 3.15)

project(certpp
    VERSION 1.0.0
    DESCRIPTION "libcertpp - a C++17 certificate handling library"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

option(CERTPP_BUILD_SHARED "Build certpp as a shared library" ON)
option(CERTPP_RNG_FALLBACK "Allow crypto::CRng to fall back to std::random_device if the OS CSPRNG is unavailable" OFF)
option(CERTPP_DISABLE_HWACCEL_SIMD "Disable CPU SIMD/extended-instruction hardware acceleration (PCLMULQDQ for CGf2m, ADX/BMI2 for CBigNum -- and, transitively, every asymmetric algorithm built on them), always using the portable implementation instead" OFF)
option(CERTPP_DISABLE_HWACCEL_SHA "Disable CPU SHA-extension hardware acceleration (SHA-NI for SHA1/SHA256), always using the portable implementation instead" OFF)
option(CERTPP_DISABLE_HWACCEL_AES "Disable CPU AES-extension hardware acceleration (AES-NI for the AES block cipher), always using the portable implementation instead" OFF)

file(GLOB_RECURSE CERTPP_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
)

if(CERTPP_BUILD_SHARED)
    add_library(certpp SHARED ${CERTPP_SOURCES})
else()
    add_library(certpp STATIC ${CERTPP_SOURCES})
endif()

add_library(certpp::certpp ALIAS certpp)

# crypto/rng.cpp calls BCryptGenRandom (Windows CNG API) directly on Windows.
if(WIN32)
    target_link_libraries(certpp PRIVATE bcrypt)
endif()

target_include_directories(certpp
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# __COMPILES_LIBCERTPP__ marks translation units built as part of the
# library itself, so common.hpp switches CERTPP_API to dllexport instead
# of dllimport on MSVC. __SHARED_LIBCERTPP__ must match how the library
# was built for consumers, so it is propagated as a PUBLIC definition.
target_compile_definitions(certpp
    PRIVATE
        __COMPILES_LIBCERTPP__=1
        $<$<BOOL:${CERTPP_RNG_FALLBACK}>:CERTPP_RNG_FALLBACK=1>
        $<$<BOOL:${CERTPP_DISABLE_HWACCEL_SIMD}>:CERTPP_DISABLE_HWACCEL_SIMD=1>
        $<$<BOOL:${CERTPP_DISABLE_HWACCEL_SHA}>:CERTPP_DISABLE_HWACCEL_SHA=1>
        $<$<BOOL:${CERTPP_DISABLE_HWACCEL_AES}>:CERTPP_DISABLE_HWACCEL_AES=1>
    PUBLIC
        $<$<BOOL:${CERTPP_BUILD_SHARED}>:__SHARED_LIBCERTPP__=1>
)

set_target_properties(certpp PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

include(GNUInstallDirs)

install(TARGETS certpp
    EXPORT certpp-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT certpp-targets
    FILE certpp-targets.cmake
    NAMESPACE certpp::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/certpp
)

option(CERTPP_BUILD_TESTS "Build certpp test executables" ON)

if(CERTPP_BUILD_TESTS)
    enable_testing()

    # third-party/ vendors the doctest single header; its CMakeLists.txt
    # exposes it as the INTERFACE target `doctest`.
    add_subdirectory(third-party)

    # Each tests/**/<name>.cpp becomes its own executable and CTest case,
    # named after its path relative to tests/ (e.g. tests/asn1/decoder.cpp ->
    # certpp_test_asn1_decoder / ctest case "asn1_decoder"), mirroring the
    # include/src path it exercises.
    file(GLOB_RECURSE CERTPP_TEST_SOURCES CONFIGURE_DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp
    )

    foreach(CERTPP_TEST_SOURCE ${CERTPP_TEST_SOURCES})
        file(RELATIVE_PATH CERTPP_TEST_REL ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CERTPP_TEST_SOURCE})
        string(REGEX REPLACE "\\.cpp$" "" CERTPP_TEST_REL ${CERTPP_TEST_REL})
        string(REPLACE "/" "_" CERTPP_TEST_NAME ${CERTPP_TEST_REL})

        add_executable(certpp_test_${CERTPP_TEST_NAME} ${CERTPP_TEST_SOURCE})
        target_link_libraries(certpp_test_${CERTPP_TEST_NAME} PRIVATE certpp::certpp doctest)

        # Some tests exercise implementation units that are deliberately private to the library:
        # the lattice arithmetic and wire encoding behind ML-KEM and ML-DSA have no public API, so
        # those classes carry no CERTPP_API and are not exported from the shared object. Linking
        # cannot reach them, so such a test compiles the units it needs directly into its own
        # executable instead. That is safe precisely *because* the symbols aren't exported -- the
        # test's copy can never collide with certpp's own. Each also gets src/ on its include path,
        # so it can use the same "crypto/..." form the library's own sources do rather than a
        # relative climb.
        #
        # Everything else is tested through the public surface, as DesCore/KeccakCore/
        # CbcTransformer are (via ISymmetric/IHasher). This is the exception for code that has no
        # public surface to be reached through yet, not a general licence to test internals.
        #
        # The lists are written out rather than globbed, and deliberately exclude mlkem.cpp and
        # mlkemsampler.cpp: those implement the exported CMlKem/CMlKemSampler/MLKEM, so compiling
        # them here as well would define symbols the test already imports from certpp. Only units
        # with no public header belong, and a new one has to be added by hand -- which is the
        # point, since the alternative fails confusingly at link time.
        set(CERTPP_TEST_PRIVATE_SOURCES "")

        if(CERTPP_TEST_REL MATCHES "^crypto/kems/")
            list(APPEND CERTPP_TEST_PRIVATE_SOURCES
                ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/kems/mlkemring.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/kems/mlkemcodec.cpp
            )
        endif()

        # Scoped to the one test rather than to crypto/asyms/, which holds two dozen others that
        # have no business compiling ML-DSA's ring in.
        if(CERTPP_TEST_REL STREQUAL "crypto/asyms/mldsaring")
            list(APPEND CERTPP_TEST_PRIVATE_SOURCES
                ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/asyms/mldsaring.cpp
            )
        endif()

        if(CERTPP_TEST_REL STREQUAL "crypto/asyms/mldsarounding")
            list(APPEND CERTPP_TEST_PRIVATE_SOURCES
                ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/asyms/mldsaring.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/asyms/mldsarounding.cpp
            )
        endif()

        if(CERTPP_TEST_REL STREQUAL "crypto/asyms/mldsacodec")
            list(APPEND CERTPP_TEST_PRIVATE_SOURCES
                ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/asyms/mldsaring.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/asyms/mldsacodec.cpp
            )
        endif()

        if(CERTPP_TEST_REL STREQUAL "crypto/asyms/mldsasampler")
            list(APPEND CERTPP_TEST_PRIVATE_SOURCES
                ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/asyms/mldsaring.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/asyms/mldsacodec.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/asyms/mldsasampler.cpp
            )
        endif()

        if(CERTPP_TEST_PRIVATE_SOURCES)
            target_sources(certpp_test_${CERTPP_TEST_NAME} PRIVATE ${CERTPP_TEST_PRIVATE_SOURCES})
            target_include_directories(certpp_test_${CERTPP_TEST_NAME} PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src
            )
        endif()

        # CERTPP_TEST_DIR: absolute path to the directory containing this test's own .cpp file,
        # so a test needing on-disk fixture data (e.g. tests/x509/realcerts.cpp's certs/) can
        # find it reliably regardless of the working directory the test happens to run from
        # (ctest's default differs from running the .exe directly).
        get_filename_component(CERTPP_TEST_SOURCE_DIR ${CERTPP_TEST_SOURCE} DIRECTORY)
        # --> Windows native paths use backslashes, which corrupt a C string literal embedded
        # directly (e.g. "\t"); normalize to forward slashes, which Windows accepts equally well
        # as a path separator, before injecting.
        file(TO_CMAKE_PATH "${CERTPP_TEST_SOURCE_DIR}" CERTPP_TEST_SOURCE_DIR)
        target_compile_definitions(certpp_test_${CERTPP_TEST_NAME} PRIVATE
            CERTPP_TEST_DIR="${CERTPP_TEST_SOURCE_DIR}"
        )

        add_test(NAME ${CERTPP_TEST_NAME} COMMAND certpp_test_${CERTPP_TEST_NAME})
    endforeach()
endif()

option(CERTPP_BUILD_EXAMPLES "Build certpp example programs" ON)

if(CERTPP_BUILD_EXAMPLES)
    # Each examples/<name>.cpp (examples/common.hpp is shared support code, not an example of
    # its own) becomes its own executable, named after its path relative to examples/ (e.g.
    # examples/01_issue_ca_root.cpp -> certpp_example_01_issue_ca_root).
    file(GLOB CERTPP_EXAMPLE_SOURCES CONFIGURE_DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/*.cpp
    )

    # Where the certificates these examples produce/consume actually land -- fixed and
    # gitignored, so the examples work the same regardless of the working directory they're run
    # from, and chain together (each one after the first loads the previous one's output).
    set(CERTPP_EXAMPLE_OUTPUT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/examples/output)
    file(MAKE_DIRECTORY ${CERTPP_EXAMPLE_OUTPUT_DIR})

    foreach(CERTPP_EXAMPLE_SOURCE ${CERTPP_EXAMPLE_SOURCES})
        get_filename_component(CERTPP_EXAMPLE_NAME ${CERTPP_EXAMPLE_SOURCE} NAME_WE)

        add_executable(certpp_example_${CERTPP_EXAMPLE_NAME} ${CERTPP_EXAMPLE_SOURCE})
        target_link_libraries(certpp_example_${CERTPP_EXAMPLE_NAME} PRIVATE certpp::certpp)
        target_compile_definitions(certpp_example_${CERTPP_EXAMPLE_NAME} PRIVATE
            CERTPP_EXAMPLE_OUTPUT_DIR="${CERTPP_EXAMPLE_OUTPUT_DIR}"
        )
    endforeach()
endif()
