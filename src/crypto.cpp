#include <math.h>

#include "spdlog/spdlog.h"

#include "crypto.h"
#include "error.h"

Crypto::Crypto(): m_initialized(false)
{
    int res = -1;

#ifdef HOST
    spdlog::set_pattern("%Y-%m-%d %H:%M:%S - HOST - %l - %v");
#else
    spdlog::set_pattern("%Y-%m-%d %H:%M:%S - ENCLAVE - %l - %v");
#endif

    mbedtls_ctr_drbg_init(&m_ctr_drbg_context);
    mbedtls_entropy_init(&m_entropy_context);
    mbedtls_pk_init(&m_pk_context);

    // Initialize entropy.
    std::string seed = "MC^2 entropy seed";
    res = mbedtls_ctr_drbg_seed(
        &m_ctr_drbg_context,
        mbedtls_entropy_func,
        &m_entropy_context,
        (unsigned char *)seed.c_str(),
        seed.size());
    if (res != 0) {
        spdlog::error("Failed to initialize entropy.");
        spdlog::error("Returned error: {}", to_string(res));
        return;
    }

    // Setup RSA context.
    res = mbedtls_pk_setup(
        &m_pk_context,
        mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (res != 0) {
        spdlog::error("Failed to set up RSA context.");
        spdlog::error("Returned error: {}", to_string(res));
        return;
    }
    mbedtls_rsa_init(
        mbedtls_pk_rsa(m_pk_context),
        MBEDTLS_RSA_PKCS_V21,
        MBEDTLS_MD_SHA256);

    // Generate an ephemeral 2048-bit RSA key pair with
    // exponent 65537.
    res = mbedtls_rsa_gen_key(
        mbedtls_pk_rsa(m_pk_context),
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_context,
        RSA_MOD_SIZE * 8,
        RSA_EXPONENT);
    if (res != 0) {
        spdlog::error("Failed to generate RSA key pair");
        spdlog::error("Returned error: {}", to_string(res));
        return;
    }

    m_initialized = true;
    spdlog::info("Successfully initialized cryptography module.");
}


Crypto::~Crypto()
{
    // Free mbedtls contexts
    mbedtls_pk_free(&m_pk_context);
    mbedtls_entropy_free(&m_entropy_context);
    mbedtls_ctr_drbg_free(&m_ctr_drbg_context);
    spdlog::info("Successfully freed relevant cryptography contexts.");
}


size_t Crypto::AsymEncSize(size_t data_size) {
    return ceil(double(data_size) / double(RSA_MAX_MESSAGE_SIZE)) * RSA_MOD_SIZE;
}


size_t Crypto::AsymDecSize(size_t enc_data_size) {
    return ceil(enc_data_size / RSA_MOD_SIZE) * RSA_MAX_MESSAGE_SIZE;
}


size_t Crypto::AsymSignSize() {
    return RSA_MOD_SIZE;
}


size_t Crypto::SymEncSize(size_t data_size) {
    return data_size + CIPHER_IV_SIZE + CIPHER_TAG_SIZE;
}


size_t Crypto::SymDecSize(size_t enc_data_size) {
    return enc_data_size - CIPHER_IV_SIZE - CIPHER_TAG_SIZE;
}


/*
 * Helper function to check that an externally-generated key has compatible
 * RSA parameters
 */
int check_rsa_key(mbedtls_pk_context* pk) {
    int res = -1;

    // This function returns 1 if the context can do operations on the given type,
    // 0 if the context cannot
    res = mbedtls_pk_can_do(pk, MBEDTLS_PK_RSA);
    if (!res) {
        spdlog::error("Given private key is not an RSA key.");
        return res;
    }

    // Assert that the key has the correct modulus size
    if (mbedtls_pk_rsa(*pk)->len != RSA_MOD_SIZE) {
        spdlog::error("Given key has incorrect RSA modulus size.");
        return res;
    }
    return 0;
}


int Crypto::WritePublicKey(uint8_t (&buf)[CIPHER_PK_SIZE]) {
    int res = -1;
    
    if (!m_initialized)
        return res;

    // Write out the public key in PEM format.
    res = mbedtls_pk_write_pubkey_pem(&m_pk_context, buf, CIPHER_PK_SIZE);
    if (res != 0) {
        spdlog::error("Failed to write out enclave public key in PEM format.");
        spdlog::error("Returned error: {}", to_string(res));
    }

    return res;
}


int Crypto::RandGen(uint8_t* buf, size_t buf_len) {
    int res = -1;
    
    if (!m_initialized)
        return res;

    res = mbedtls_ctr_drbg_random(&m_ctr_drbg_context, buf, buf_len);
    if (res != 0) {
        spdlog::error("Failed to generate random buffer of length {}", buf_len);
        spdlog::error("Returned error: {}", to_string(res));
    }
    return res;
}


int Crypto::AsymEnc(
    const uint8_t* pem_public_key,
    const uint8_t* data,
    uint8_t*       enc_data,
    size_t         data_size
) {
    int res = -1;
    mbedtls_rsa_context* rsa_context;
    mbedtls_pk_context key;
    // Include the NULL terminator since this is passed to C
    size_t key_size = strlen((const char*)pem_public_key) + 1;    

    if (!m_initialized)
        return res;

    // Read the given public key.
    mbedtls_pk_init(&key);
    res = mbedtls_pk_parse_public_key(&key, pem_public_key, key_size);
    if (res != 0) {
        spdlog::error("Failed to read public key during public key encryption.");
        spdlog::error("Returned error: {}", to_string(res));
        return res;
    }

    // Check the paramters of the key
    res = check_rsa_key(&key);
    if (res != 0) {
        spdlog::error("Encryption failed - invalid public key");
        return res;
    }

    // Construct the RSA context
    rsa_context = mbedtls_pk_rsa(key);
    rsa_context->padding = MBEDTLS_RSA_PKCS_V21;
    rsa_context->hash_id = MBEDTLS_MD_SHA256;

    uint8_t* remaining_data = const_cast<uint8_t*>(data);
    size_t remaining_data_size = data_size;
    size_t data_encrypted_size = 0;

    size_t num_cts = ceil(double(data_size) / double(RSA_MAX_MESSAGE_SIZE));
    for (size_t i = 0; i < num_cts; i++) {
        // Calculate how much data we want to encrypt
        size_t data_to_encrypt_size;
        if (remaining_data_size <= RSA_MAX_MESSAGE_SIZE) {
            data_to_encrypt_size = remaining_data_size;
            remaining_data_size = 0;
        } else {
            data_to_encrypt_size = RSA_MAX_MESSAGE_SIZE;
            remaining_data_size -= RSA_MAX_MESSAGE_SIZE;
        }

        // The sequence number for the current ciphertext
        std::vector<uint8_t> seq(sizeof(i));
        memcpy(seq.data(), &i, sizeof(i));

        // Encrypt the data.
        res = mbedtls_rsa_rsaes_oaep_encrypt(
            rsa_context,
            mbedtls_ctr_drbg_random,
            &m_ctr_drbg_context,
            MBEDTLS_RSA_PUBLIC,
            seq.data(),
            seq.size(),
            data_to_encrypt_size,
            remaining_data,
            enc_data + data_encrypted_size);

        if (res != 0) {
            spdlog::error("Failed to perform public key encryption.");
            spdlog::error("Returned error: {}", to_string(res));
            return res;
        }

        // Get the next chunk of data to encrypt
        remaining_data += data_to_encrypt_size;

        // Track how much data we've encrypted thus far
        data_encrypted_size += RSA_MOD_SIZE;
    }
    
    // Free the allocated context
    mbedtls_pk_free(&key);
    return res;
}


int Crypto::AsymDec(
    const uint8_t* enc_data,
    uint8_t*       data,
    size_t         enc_data_size,
    size_t*        data_size
) {
    int res = -1;
    mbedtls_rsa_context* rsa_context = mbedtls_pk_rsa(m_pk_context);

    if (!m_initialized)
        return res;

    // Pointers to the next ciphertext to decrypt and position to output
    // the resulting plaintext
    uint8_t* next_ct = const_cast<uint8_t*>(enc_data);
    uint8_t* next_pt = data;

    // Total decrypted plaintext thus far
    *data_size = 0;

    // Decrypt each ciphertext in `enc_data`
    for (size_t i = 0; i < enc_data_size / RSA_MOD_SIZE; i++) {
        // The size of the current plaintext
        size_t pt_size = 0;

        // The sequence number for the current ciphertext
        std::vector<uint8_t> seq(sizeof(i));
        memcpy(seq.data(), &i, sizeof(i));

        // Decrypt the ciphertext.
        res = mbedtls_rsa_rsaes_oaep_decrypt(
            rsa_context,
            mbedtls_ctr_drbg_random,
            &m_ctr_drbg_context,
            MBEDTLS_RSA_PRIVATE,
            seq.data(),
            seq.size(),
            &pt_size,
            next_ct,
            next_pt,
            RSA_MOD_SIZE);
        if (res != 0) {
            spdlog::error("Failed to perform public key decryption.");
            spdlog::error("Returned error: {}", to_string(res));
        }

        next_ct += RSA_MOD_SIZE;
        next_pt += pt_size;
        *data_size += pt_size;
    }
    return res;
}


int Crypto::SymEnc(
    const uint8_t* sym_key,
    const uint8_t* data,
    const uint8_t* aad,
    uint8_t*       enc_data,
    size_t         data_size,
    size_t         aad_size
) {
    int res = -1;

    // Initialize GCM context
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    
    // Set the pointers so that the ciphertext is formatted as:
    //     IV || TAG || ENCRYPTED DATA
    uint8_t* iv = enc_data;
    uint8_t* tag = iv + CIPHER_IV_SIZE;
    uint8_t* output = tag + CIPHER_TAG_SIZE;

    // Add `sym_key` and AES cipher to the current GCM context
    res = mbedtls_gcm_setkey(
        &ctx,
        MBEDTLS_CIPHER_ID_AES,
        sym_key,
        CIPHER_KEY_SIZE * 8); // Key size is given in bits
    if( res != 0 ) {
        mbedtls_gcm_free(&ctx);
        spdlog::error("Failed to set symmetric key during symmetric key encryption.");
        spdlog::error("Returned error: {}", to_string(res));
        return res;
    }

    // Sample randomness for the IV
    res = RandGen(iv, CIPHER_IV_SIZE);
    if( res != 0 ) {
        mbedtls_gcm_free(&ctx);
        spdlog::error("Failed to generate IV during symmetric key encryption.");
        spdlog::error("Returned error: {}", to_string(res));
        return res;
    }

    // Encrypt data
    res = mbedtls_gcm_crypt_and_tag( 
        &ctx,
        MBEDTLS_GCM_ENCRYPT,
        data_size,
        iv,
        CIPHER_IV_SIZE,
        aad,
        aad_size,
        data,
        output,
        CIPHER_TAG_SIZE,
        tag);
    if( res != 0 ) {
        mbedtls_gcm_free(&ctx);
        spdlog::error("Failed to perform symmetric key encryption.");
        spdlog::error("Returned error: {}", to_string(res));
    }
    
    // Free the GCM context
    mbedtls_gcm_free(&ctx);
    
    return res;
}


int Crypto::SymDec(
    const uint8_t* sym_key,
    const uint8_t* enc_data,
    const uint8_t* aad,
    uint8_t*       data,
    size_t         enc_data_size,
    size_t         aad_size
) {
    int res = -1;

    // Initialize GCM context
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    // Add `sym_key` and AES cipher to the current GCM context
    res = mbedtls_gcm_setkey(
        &ctx,
        MBEDTLS_CIPHER_ID_AES,
        sym_key,
        CIPHER_KEY_SIZE * 8); // Key size is given in bits
    if( res != 0 ) {
        mbedtls_gcm_free(&ctx);
        spdlog::error("Failed to set symmetric key during symmetric key decryption.");
        spdlog::error("Returned error: {}", to_string(res));
        return res;
    }
    
    // Set the appropiate pointers since the ciphertext is formatted as:
    //     IV || TAG || ENCRYPTED DATA
    const uint8_t* iv = enc_data;
    const uint8_t* tag = iv + CIPHER_IV_SIZE;
    const uint8_t* ciphertext = tag + CIPHER_TAG_SIZE;

    // Decrypt the data
    res = mbedtls_gcm_auth_decrypt(
        &ctx,
        enc_data_size - CIPHER_IV_SIZE - CIPHER_TAG_SIZE,
        iv,
        CIPHER_IV_SIZE,
        aad,
        aad_size,
        tag,
        CIPHER_TAG_SIZE,
        ciphertext,
        data);
    if (res != 0) {
        mbedtls_gcm_free(&ctx);
        spdlog::error("Failed to perform symmetric key decryption.");
        spdlog::error("Returned error: {}", to_string(res));
    }
    
    // Free the GCM context
    mbedtls_gcm_free(&ctx);

    return res;
}


int Crypto::Hash(
    const uint8_t* data,
    uint8_t        (&output)[SHA_DIGEST_SIZE],
    size_t         data_size
) {
    int res = -1;

    // Initialize SHA256 context
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

// Macro to simplify error handling
#define safe_sha(call) {                                 \
  res = (call);                                          \
  if (res) {                                             \
    mbedtls_sha256_free(&ctx);                           \
    spdlog::error("Failed to hash");                     \
    spdlog::error("Returned error: {}", to_string(res)); \
    return res;                                          \
  }                                                      \
}
    // Compute the hash
    safe_sha(mbedtls_sha256_starts_ret(&ctx, 0));
    safe_sha(mbedtls_sha256_update_ret(&ctx, data, data_size));
    safe_sha(mbedtls_sha256_finish_ret(&ctx, output));

    // Free the hash context
    mbedtls_sha256_free(&ctx);

    return res;
}


int Crypto::sign_helper(
    mbedtls_pk_context* pk,
    const uint8_t*      data,
    uint8_t*            sig,
    size_t              data_size
) {
    int res = -1;
    uint8_t hash[SHA_DIGEST_SIZE];

    // Get the RSA context from `pk`
    mbedtls_rsa_context* rsa_ctx = mbedtls_pk_rsa(*pk);

    // Hash the message
    res = Hash(data, hash, data_size);
    if(res != 0) {
        spdlog::error("Failed to hash message when signing data");
        spdlog::error("Returned error: {}", to_string(res));
        return res;
    }

    // Generate the signature
    res = mbedtls_rsa_rsassa_pss_sign(
        rsa_ctx,
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_context,
        MBEDTLS_RSA_PRIVATE,
        MBEDTLS_MD_SHA256,
        0,
        hash,
        sig);

    if(res != 0) {
        spdlog::error("Failed to generate signature");
        spdlog::error("Returned error: {}", to_string(res));
        return res;
    }
    return res;
}


int Crypto::Sign(
    const uint8_t* data,
    uint8_t*       sig,
    size_t         data_size
) {
    int res = -1;
    if (!m_initialized)
        return res;

    return sign_helper(&m_pk_context, data, sig, data_size);
}


#ifdef HOST
int Crypto::SignUsingKeyfile(
    char*          keyfile,
    const uint8_t* data,
    uint8_t*       sig,
    size_t         data_size
) {
    int res = -1;
    if (!m_initialized)
        return res;

    // Get the key stored in `keyfile`
    mbedtls_pk_context pk;
    mbedtls_pk_init( &pk );
    res = mbedtls_pk_parse_keyfile( &pk, keyfile, "");
    if(res != 0) {
        spdlog::error("Failed to read private keyfile");
        spdlog::error("Returned error: {}", to_string(res));
        return res;
    }

    // Check the paramters of the key
    res = check_rsa_key(&pk);
    if (res != 0) {
        spdlog::error("Signing failed - invalid private key");
        return res;
    }

    // Construct the RSA context
    auto rsa_ctx = mbedtls_pk_rsa(pk);
    rsa_ctx->padding = MBEDTLS_RSA_PKCS_V21;
    rsa_ctx->hash_id = MBEDTLS_MD_SHA256;

    return sign_helper(&pk, data, sig, data_size);
}
#endif


int Crypto::Verify(
    const uint8_t* pem_public_key,
    const uint8_t* data,
    const uint8_t* sig,
    size_t         data_size
) {
    int res = -1;
    uint8_t hash[SHA_DIGEST_SIZE];
    mbedtls_rsa_context* rsa_context;
    mbedtls_pk_context key;
    // Include the NULL terminator since this is passed to C
    size_t key_size = strlen((const char*)pem_public_key) + 1;

    if (!m_initialized)
        return res;

    // Read the given public key.
    mbedtls_pk_init(&key);
    res = mbedtls_pk_parse_public_key(&key, pem_public_key, key_size);
    if (res != 0) {
        spdlog::error("Failed to read public key during public key encryption.");
        spdlog::error("Returned error: {}", to_string(res));
        return res;
    }

    // Check the paramters of the key
    res = check_rsa_key(&key);
    if (res != 0) {
        spdlog::error("Signature verification failed - invalid key parameters");
        return res;
    }

    // Construct the RSA context
    rsa_context = mbedtls_pk_rsa(key);
    rsa_context->padding = MBEDTLS_RSA_PKCS_V21;
    rsa_context->hash_id = MBEDTLS_MD_SHA256;

    // Hash the message
    res = Hash(data, hash, data_size);
    if(res != 0) {
        spdlog::error("Failed to hash message during signature verification.");
        spdlog::error("Returned error: {}", to_string(res));
        return res;
    }

    // Verify the provided signature
    res = mbedtls_rsa_pkcs1_verify(
        rsa_context,
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_context,
        MBEDTLS_RSA_PUBLIC,
        MBEDTLS_MD_SHA256,
        0,
        hash,
        sig);
    if (res != 0) {
        spdlog::error("Failed to verify signature");
        spdlog::error("Returned error: {}", to_string(res));
    }

    return res;
}
