#pragma once
#include <string>

#include "openenclave/bits/result.h"

/**
 * Convert Open Enclave return code to string
 * https://github.com/openenclave/openenclave/blob/master/include/openenclave/bits/result.h
 */
std::string to_string(oe_result_t err);

/**
 * Convert Mbed TLS return code to string
 */
std::string to_string(int err);
