# mc2-utils

This repo contains utilities used across the `mc2` ecosystem. 

## Overview

`mc2-utils` contains the following:
* [`src/attestation.{h/cpp}`](src/): Class for generating and verifying attestation evidence. In a host (non-enclave) environment, this library only supports verifying attestation evidence.
* [`src/crypto.{h/cpp}`](src/): Class for performing cryptographic operations.
* [`src/error.{h/cpp}`](src/): Helper functions for logging OpenEnclave and MbedTLS errors.

Additionally, `mc2-utils` will build a version of the [`spdlog`](https://github.com/gabime/spdlog) logging library which is compatible with OpenEnclave.

## Building

### Building for an enclave environment

To build `mc2-utils` for an enclave, add the following to your `CMakeLists.txt` file:

```CMake
include(FetchContent)
FetchContent_Declare(
  mc2_utils_e
  GIT_REPOSITORY https//github.com/mc2-systems/mc2-utils.git
)
set(FETCHCONTENT_QUIET OFF)

# This line is only necessary when building mc2-utils for both
# trusted and untrusted environments in the same CMake build.
set(HOST OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(mc2_utils_e)
```

### Building for a host environment

To build `mc2-utils` for a host, add the following to your `CMakeLists.txt` file:

```CMake
include(FetchContent)
FetchContent_Declare(
  mc2_utils_h
  GIT_REPOSITORY git@github.com:mc2-systems/mc2-utils.git
)
set(FETCHCONTENT_QUIET OFF)
set(HOST ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(mc2_utils_h)
```

### Unittests

`mc2-utils` additionally includes a set of unittests.  To build and run these unittests, use the following commands:
```bash
mkdir build
cd build
cmake .. -DHOST="ON" -DUNITTEST="ON"
make -j 8
make test
```
For a more verbose output, run `ctest -V` instead of `make test`


## Usage

After building, the `mc2_utils_{e/h}` libraries can be linked to, and `spdlog` can be added as a dependency.

Headers from `mc2_utils` can be imported directly (e.g. `#include "crypto.h"`) and `spdlog` should be imported as `#include "spdlog/spdlog.h"`.
