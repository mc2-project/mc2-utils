# Fetch the google testing framework
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest/
)
FetchContent_MakeAvailable(googletest)
include(GoogleTest)

add_executable(tests tests.cpp)
if (HOST)
    target_link_libraries(tests mc2_utils_h)
else()
    message(FATAL_ERROR "Unittests can only be run in Host mode currently" )
endif()
target_link_libraries(tests gtest_main)
gtest_discover_tests(tests)
