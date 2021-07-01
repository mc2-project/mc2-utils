#pragma once
#include "mbedtls/cipher.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"

// All sizes are in bytes
#define CIPHER_KEY_SIZE 32
#define CIPHER_IV_SIZE 12
#define CIPHER_TAG_SIZE 16
#define SHA_DIGEST_SIZE 32
#define RSA_MOD_SIZE 256
#define RSA_EXPONENT 65537
// https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.1
#define RSA_MAX_MESSAGE_SIZE RSA_MOD_SIZE - 2 * SHA_DIGEST_SIZE - 2
// The PEM encoding size of an RSA key with a modulus of 2048 bits
// and exponent 65537
#define CIPHER_PK_SIZE 452

class Crypto {
   private:
    mbedtls_ctr_drbg_context m_ctr_drbg_context;
    mbedtls_entropy_context m_entropy_context;
    mbedtls_pk_context m_pk_context;
    bool m_initialized;
    size_t rsa_modulus_size;

   public:
    Crypto();
    ~Crypto();

    // Ensure only a single Crypto object exists to avoid insecure behavior
    // with the RNG
    Crypto(Crypto const&) = delete;
    void operator=(Crypto const&) = delete;

    /*
     * Return the required size of a buffer to be used for asymmetric
     * signing. This assumes that the RSA key has a modulus of size
     * RSA_MOD_SIZE.
     */
    size_t AsymEncSize(size_t data_size);

    /*
     * Return the required size of a buffer to be used for asymmetric
     * decryption. This assumes that the RSA key has a modulus of size
     * RSA_MOD_SIZE.
     */
    size_t AsymDecSize(size_t enc_data_size);

    /*
     * Return the required size of a buffer to be used for asymmetric
     * signing (`RSA_MOD_SIZE`).
     */
    size_t AsymSignSize();

    /*
     * Return the required size of a buffer to be used for symmetric
     * encryption: `data_size + CIPHER_IV_SIZE + CIPHER_TAG_SIZE`
     */
    size_t SymEncSize(size_t data_size);

    /*
     * Return the required size of a buffer to be used for symmetric
     * encryption: `enc_data_size - CIPHER_IV_SIZE - CIPHER_TAG_SIZE`
     */
    size_t SymDecSize(size_t enc_data_size);

    /**
     * Copy the enclave public key into `buf`.
     */
    int WritePublicKey(uint8_t (&buf)[CIPHER_PK_SIZE]);

    /**
     * Fill `buf` with random bytes
     */
    int RandGen(uint8_t* buf, size_t buf_len);

    /**
     * Encrypt `data` using RSA encryption with .pem-formatted public key
     * `pem_public_key`.
     *
     * The resulting ciphertext is stored in the `enc_data` buffer which
     * must have at least `AsymEncSize(data_size)` bytes allocated.
     *
     * If `data_size` > RSA_MAX_MESSAGE_SIZE then `enc_data` will hold multiple
     * ciphertexts.  In order to mitigate re-ordering attacks, a counter
     * is included in the label section of each ciphertext.
     */
    int AsymEnc(const uint8_t* pem_public_key,
                const uint8_t* data,
                uint8_t* enc_data,
                size_t data_size);

    /**
     * Decrypt `enc_data` using RSA encryption with internal private key.
     * Resulting plaintext is stored in `data`.
     *
     * The resulting data is stored in the `data` buffer which must have
     * at least `enc_data_size` bytes allocated. The final plaintext size
     * (which may be less than `enc_data_size`) is stored in `data_size`.
     */
    int AsymDec(const uint8_t* enc_data,
                uint8_t* data,
                size_t enc_data_size,
                size_t* data_size);

    /**
     * Encrypt `data` using GCM encryption with symmetric key `sym_key`.
     *
     * Additional information can be placed in `aad` and will be used in
     * generating the ciphertext tag but _not_ included in the ciphertext
     * itself (i.e. the decryptor must also know this information to validate
     * the tag)
     *
     * The resulting ciphertext is stored in `enc_data` buffer which must have
     * at least CIPHER_IV_SIZE + CIPHER_TAG_SIZE + `data_size` bytes allocated.
     *
     * The ciphertext has the following structure:
     *
     *     IV || TAG || ENCRYPTED DATA
     */
    int SymEnc(const uint8_t* sym_key,
               const uint8_t* data,
               const uint8_t* aad,
               uint8_t* enc_data,
               size_t data_size,
               size_t aad_size);

    /*
     * Decrypt `enc_data` using GCM decryption with symmetric key `sym_key` and
     * additional authenticated data `aad`.
     *
     * The resulting data is stored in the `data` buffer which must have at
     * least `enc_data_size` - CIPHER_IV_SIZE - CIPHER_TAG_SIZE bytes allocated.
     */
    int SymDec(const uint8_t* sym_key,
               const uint8_t* enc_data,
               const uint8_t* aad,
               uint8_t* data,
               size_t enc_data_size,
               size_t aad_size);

    /*
     * Output the SHA256 hash of `data` into `output`
     */
    int Hash(const uint8_t* data,
             uint8_t (&output)[SHA_DIGEST_SIZE],
             size_t data_size);

    /*
     * Generate an RSA signature of `data` using the internal private key.
     *
     * The resulting signature is stored in the `sig` buffer which must have
     * at least `RSA_MOD_SIZE` bytes allocated.
     */
    int Sign(const uint8_t* data, uint8_t* sig, size_t data_size);

#ifdef HOST
    /*
     * Generate an RSA signature of `data` using the private key located at
     * `keyfile` which must be an RSA key with modulus size `RSA_MOD_SIZE`.
     *
     * The resulting signature is stored in the `sig` buffer which must have
     * at least `RSA_MOD_SIZE` bytes allocated.
     */
    int SignUsingKeyfile(const char* keyfile,
                         const uint8_t* data,
                         uint8_t* sig,
                         size_t data_size);
#endif

    /*
     * Verify an RSA signature `sig` over `data` using .pem-formatted public key
     * `pem_public_key`.
     */
    int Verify(const uint8_t* pem_public_key,
               const uint8_t* data,
               const uint8_t* sig,
               size_t data_size);

   private:
    /*
     * Helper function to consolidate the shared computation of `Sign` and
     * `SignUsingKeyfile`
     */
    int sign_helper(mbedtls_pk_context* pk,
                    const uint8_t* data,
                    uint8_t* sig,
                    size_t data_size);
};
