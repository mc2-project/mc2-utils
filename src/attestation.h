#pragma once
#include <string>
#include <vector>

#ifndef HOST
#include "openenclave/enclave.h"
#endif
#include "openenclave/bits/evidence.h"

#include "crypto.h"

class Attestation
{
  private:
    Crypto* m_crypto;

  public:
    Attestation(Crypto* crypto): m_crypto(crypto) {};

    /**
     * Get format settings for the given enclave.
     */
    int GetFormatSettings(
        const     oe_uuid_t* format_id,
        uint8_t** format_settings,
        size_t*   format_settings_size);

#ifndef HOST
    /**
     * Generate evidence for the given public key and nonce.
     */
    int GenerateEvidence(
        const          oe_uuid_t* format_id,
        const uint8_t* format_settings,
        uint8_t**      evidence,
        const uint8_t* pem_public_key,
        const uint8_t* nonce,
        size_t         format_settings_size,
        size_t*        evidence_size,
        size_t         pem_key_size);
#endif

    /**
     * Attest the given evidence and accompanying data. The evidence
     * is first attested using the oe_verify_evidence API. This ensures the
     * authenticity of the enclave that generated the evidence. Next the enclave
     * signer_id and unique_id values are tested to establish trust of the
     * enclave that generated the evidence.
     */
    int AttestEvidence(
        const          oe_uuid_t* format_id,
        const uint8_t* enclave_signer_pem,
        const uint8_t* evidence,
        const uint8_t* pem_public_key,
        const uint8_t* nonce,
        size_t         enclave_signer_pem_size,
        size_t         evidence_size,
        size_t         pem_key_size);
};
