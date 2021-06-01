cmake_minimum_required(VERSION 3.11)

project("MC^2 Utils" LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)

# Fetch spdlog
include(FetchContent)
set(FETCHCONTENT_QUIET OFF)
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY git@github.com:opaque-systems/spdlog.git
)
FetchContent_MakeAvailable(spdlog)

# Add necessary compiler flags and headers for spdlog dependency
add_compile_definitions(SPDLOG_NO_THREAD_ID FMT_USE_INT128=0)
include_directories(${spdlog_SOURCE_DIR}/include)

find_package(OpenEnclave CONFIG REQUIRED)

set(OPAQUE_UTILS_SOURCES
    src/crypto.cpp
    src/attestation.cpp
    src/error.cpp)

# We compile the library under two different target names depending on the HOST
# flag. This allows for a single CMake build to use both enclave and host
# versions of this library
option(HOST "Build for an untrusted environment" OFF)
if (HOST)
    add_library(mc2_utils_h STATIC ${OPAQUE_UTILS_SOURCES})

    target_compile_definitions(mc2_utils_h
        PUBLIC OE_API_VERSION=2 HOST MBEDTLS_FS_IO)

    target_include_directories(mc2_utils_h
        PRIVATE ${OE_INCLUDEDIR}/openenclave/3rdparty
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

    target_link_libraries(mc2_utils_h
        PRIVATE openenclave::oehost mbedtls mbedcrypto)

    set_target_properties(mc2_utils_h PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED ON
        VERSION 0.1)

    add_dependencies(mc2_utils_h spdlog)
else()
    add_library(mc2_utils_e STATIC ${OPAQUE_UTILS_SOURCES})

    target_compile_definitions(mc2_utils_e PUBLIC OE_API_VERSION=2)

    target_include_directories(mc2_utils_e PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

    if (LVI_MITIGATION MATCHES ControlFlow)
      # Helper to enable compiler options for LVI mitigation.
      apply_lvi_mitigation(enclave)
      # Link against LVI-mitigated libraries.
      target_link_libraries(
        mc2_utils_e
        PRIVATE
        openenclave::oeenclave-lvi-cfg openenclave::oelibcxx-lvi-cfg openenclave::oecore)
    else()
      target_link_libraries(
        mc2_utils_e
        PRIVATE
        openenclave::oeenclave openenclave::oelibcxx openenclave::oecore)
    endif()

    set_target_properties(mc2_utils_e PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED ON
        VERSION 0.1)

    add_dependencies(mc2_utils_e spdlog)
endif()
