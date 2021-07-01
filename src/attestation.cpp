#ifndef HOST
#include "openenclave/attestation/attester.h"
#endif
#include "openenclave/attestation/custom_claims.h"
#include "openenclave/attestation/sgx/report.h"
#include "openenclave/attestation/verifier.h"
#include "spdlog/spdlog.h"

#include "attestation.h"
#include "error.h"


int Attestation::GetFormatSettings(const oe_uuid_t* format_id,
                                   uint8_t** format_settings,
                                   size_t* format_settings_size) {
    // Intialize verifier to get enclave's format settings.
    oe_result_t oe_res = oe_verifier_initialize();
    if (oe_res != OE_OK) {
        spdlog::error(
            "Failed to initialize verifier when getting enclave "
            "format settings.");
        spdlog::error("Returned error: {}", to_string(oe_res));
        return -1;
    }

    // Use the plugin.
    oe_res = oe_verifier_get_format_settings(format_id, format_settings,
                                             format_settings_size);
    if (oe_res != OE_OK) {
        spdlog::error("Failed to get enclave format settings.");
        spdlog::error("Returned error: {}", to_string(oe_res));
        return -1;
    }
    return 0;
}


#ifndef HOST
int Attestation::GenerateEvidence(const oe_uuid_t* format_id,
                                  const uint8_t* format_settings,
                                  uint8_t** evidence,
                                  const uint8_t* pem_public_key,
                                  const uint8_t* nonce,
                                  size_t format_settings_size,
                                  size_t* evidence_size,
                                  size_t pem_key_size) {
    int res = -1;
    oe_result_t oe_res = OE_OK;
    // A buffer to hold the hash of the public key
    uint8_t hash[SHA_DIGEST_SIZE];
    // A buffer to copy the nonce into
    uint8_t nonce_buf[CIPHER_IV_SIZE];
    // A buffer to hold the serialized public key hash and nonce
    uint8_t* claims_buf = nullptr;
    size_t claims_buf_size = 0;

    // Initialize attester and use the plugin.
    oe_res = oe_attester_initialize();
    if (oe_res != OE_OK) {
        spdlog::error(
            "Failed to initialize attester when generating "
            "attestation evidence.");
        spdlog::error("Returned error: {}", to_string(oe_res));
        return -1;
    }

    // Hash the public key
    res = m_crypto->Hash(pem_public_key, hash, pem_key_size);
    if (res != 0) {
        spdlog::error(
            "Failed to hash TMS enclave public key during "
            "attestation evidence generation.");
        return res;
    }
    // Copy `nonce` to `nonce_buf`
    std::memcpy(nonce_buf, nonce, CIPHER_IV_SIZE);

    // Serialize the additional data to be attested
    char claim1_name[] = "Nonce";
    char claim2_name[] = "Public key";
    oe_claim_t claims[2] = {
        {.name = claim1_name,
         .value = nonce_buf,
         .value_size = sizeof(nonce_buf)},
        {.name = claim2_name, .value = hash, .value_size = sizeof(hash)}};
    oe_res =
        oe_serialize_custom_claims(claims, 2, &claims_buf, &claims_buf_size);
    if (oe_res != OE_OK) {
        spdlog::error(
            "Failed to serialize custom claims during attestation "
            "evidence generation.");
        spdlog::error("Returned error: {}", to_string(oe_res));
        return -1;
    }

    // Generate evidence
    oe_res = oe_get_evidence(format_id, 0, claims_buf, claims_buf_size,
                             format_settings, format_settings_size, evidence,
                             evidence_size, nullptr, 0);
    if (oe_res != OE_OK) {
        spdlog::error("Failed to generate attestation evidence.");
        spdlog::error("Returned error: {}", to_string(res));
        return -1;
    }
    return res;
}
#endif

/**
 * Helper function used to make the claim-finding process more convenient. Given
 * the claim name, claim list, and its size, returns the claim with that claim
 * name in the list.
 */
static const oe_claim_t* _find_claim(const oe_claim_t* claims,
                                     size_t claims_size,
                                     const char* name) {
    for (size_t i = 0; i < claims_size; i++) {
        if (strcmp(claims[i].name, name) == 0)
            return &(claims[i]);
    }
    return nullptr;
}

/**
 * Attest the given evidence and accompanying data. It consists of the
 * following three steps:
 *
 * 1) The evidence is first attested using the oe_verify_evidence API.
 * This ensures the authenticity of the enclave that generated the evidence.
 * 2) Next, to establish trust in the enclave that generated the
 * evidence, the signer_id, product_id, and security version values are
 * checked to see if they are predefined trusted values.
 * 3) Once the enclave's trust has been established,
 * the validity of accompanying data is ensured by comparing its SHA256 digest
 * against the OE_CLAIM_CUSTOM_CLAIMS_BUFFER claim.
 */

int Attestation::AttestEvidence(const oe_uuid_t* format_id,
                                const uint8_t* enclave_signer_pem,
                                const uint8_t* evidence,
                                const uint8_t* pem_public_key,
                                const uint8_t* nonce,
                                size_t enclave_signer_pem_size,
                                size_t evidence_size,
                                size_t pem_key_size) {
    oe_result_t result = OE_OK;

    // Initialize the verifier. This will do nothing if the verifier is already
    // initialized but ensures verification still works even if
    // `GetFormatSettings` hasn't been called.
    oe_result_t oe_res = oe_verifier_initialize();

#ifndef HOST
    // While attesting, the evidence being attested must not be tampered
    // with. Ensure that it has been copied over to the enclave if in an
    // untrusted environment.
    if (!oe_is_within_enclave(evidence, evidence_size)) {
        spdlog::error("Evidence to attest is not within enclave.");
        oe_attester_shutdown();
        oe_verifier_shutdown();
        return -1;
    }
#endif

// Macro to simplify error handling
#ifdef HOST
#define free_and_return(val)                   \
    {                                          \
        oe_free_claims(claims, claims_length); \
        oe_verifier_shutdown();                \
        return val;                            \
    }
#else
#define free_and_return(val)                   \
    {                                          \
        oe_free_claims(claims, claims_length); \
        oe_attester_shutdown();                \
        oe_verifier_shutdown();                \
        return val;                            \
    }
#endif

    // 1) Validate the evidence's trustworthiness
    oe_claim_t* claims = nullptr;
    size_t claims_length = 0;
    result = oe_verify_evidence(format_id, evidence, evidence_size, nullptr, 0,
                                nullptr, 0, &claims, &claims_length);
    if (result != OE_OK) {
        spdlog::error("Attestation evidence verification failed.");
        spdlog::error("Returned error: {}", to_string(result));
        free_and_return(-1);
    }

    // 2) Validate the enclave identity's signer_id is the hash of the public
    // signing key that was used to sign an enclave. Check that the enclave was
    // signed by an trusted entity.
    const oe_claim_t* claim;
    // Validate the signer id.
    if ((claim = _find_claim(claims, claims_length, OE_CLAIM_SIGNER_ID)) ==
        nullptr) {
        spdlog::error(
            "During evidence attestation, couldn't find enclave signer ID.");
        free_and_return(-1);
    };

    if (claim->value_size != OE_SIGNER_ID_SIZE) {
        spdlog::error(
            "During evidence attestation, OE_CLAIM_SIGNER_ID size "
            "didn't match OE_SIGNER_ID_SIZE.");
        free_and_return(-1);
    }

    // MR_SIGNER value is the SHA256 hash of the public key used to sign the
    // enclave
    uint8_t mr_signer[32];
    size_t mr_signer_size = sizeof(mr_signer);
    result = oe_sgx_get_signer_id_from_public_key(
        reinterpret_cast<const char*>(enclave_signer_pem),
        enclave_signer_pem_size, mr_signer, &mr_signer_size);
    if (result != OE_OK) {
        spdlog::error("Failed to get MR_SIGNER from signer's public key.");
        spdlog::error("Returned error: {}", to_string(result));
        free_and_return(-1);
    }

    if (memcmp(claim->value, mr_signer, OE_SIGNER_ID_SIZE) != 0) {
        spdlog::error("Evidence contains an invalid MR_SIGNER value");
        free_and_return(-1);
    }

    // Check the enclave's product id.
    if ((claim = _find_claim(claims, claims_length, OE_CLAIM_PRODUCT_ID)) ==
        nullptr) {
        spdlog::error(
            "During evidence attestation, couldn't find enclave product ID.");
        free_and_return(-1);
    };

    if (claim->value_size != OE_PRODUCT_ID_SIZE) {
        spdlog::error(
            "During evidence attestation, OE_CLAIM_PRODUCT_ID size "
            "didn't match OE_PRODUCT_ID_SIZE.");
        free_and_return(-1);
    }

    if (*(claim->value) != 1) {
        spdlog::error(
            "During evidence attestation, product ID verification failed.");
        free_and_return(-1);
    }

    // Check the enclave's security version.
    if ((claim = _find_claim(claims, claims_length,
                             OE_CLAIM_SECURITY_VERSION)) == nullptr) {
        spdlog::error(
            "During evidence attestation, couldn't find enclave "
            "security version.");
        free_and_return(-1);
    };

    if (claim->value_size != sizeof(uint32_t)) {
        spdlog::error(
            "During evidence attestation, OE_CLAIM_SECURITY_VERSION "
            "size is incorrect.");
        free_and_return(-1);
    }

    if (*(claim->value) < 1) {
        spdlog::error(
            "During evidence attestation, enclave security version "
            "verification failed.");
        free_and_return(-1);
    }

    // 3) Validate the custom claims buffer
    //    Deserialize the custom claims buffer to custom claims list, then fetch
    //    the hash value of the data held in custom_claims[1].
    if ((claim = _find_claim(claims, claims_length,
                             OE_CLAIM_CUSTOM_CLAIMS_BUFFER)) == nullptr) {
        spdlog::error(
            "During evidence attestation, couldn't find "
            "OE_CLAIM_CUSTOM_CLAIMS_BUFFER.");
        free_and_return(-1);
    }

    uint8_t hash[SHA_DIGEST_SIZE];
    if (m_crypto->Hash(pem_public_key, hash, pem_key_size) != 0) {
        spdlog::error(
            "During evidence attestation, couldn't hash enclave public key.");
        free_and_return(-1);
    }

    // Deserialize the custom claims buffer
    oe_claim_t* custom_claims = nullptr;
    size_t custom_claims_length = 0;
    if (oe_deserialize_custom_claims(claim->value, claim->value_size,
                                     &custom_claims,
                                     &custom_claims_length) != OE_OK) {
        spdlog::error(
            "During evidence attestation, failed to deserialize "
            "custom claims buffer.");
        free_and_return(-1);
    }

    if (custom_claims[0].value_size != CIPHER_IV_SIZE ||
        memcmp(custom_claims[0].value, nonce, CIPHER_IV_SIZE) != 0) {
        spdlog::error(
            "During evidence attestation, the nonce received from the client "
            "as part of the custom claim was not the expected nonce.");
        free_and_return(-1);
    }

    if (custom_claims[1].value_size != sizeof(hash) ||
        memcmp(custom_claims[1].value, hash, sizeof(hash)) != 0) {
        spdlog::error(
            "During evidence attestation, the hash received from the client as "
            "part of the custom claim was not the expected hash.");
        free_and_return(-1);
    }

    free_and_return(0);
}
