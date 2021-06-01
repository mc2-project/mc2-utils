#include "mbedtls/error.h"

#include "error.h"

std::string to_string(oe_result_t err) {
    const char* err_str = oe_result_str(err);
    return std::string(err_str);
}

std::string to_string(int err) {
    char error_buf[200];
    mbedtls_strerror(err, error_buf, 200);
    return std::string(error_buf);
}
