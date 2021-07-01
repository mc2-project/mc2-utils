#include <stdlib.h>
#include <fstream>

#include "gtest/gtest.h"
#include "openenclave/attestation/sgx/evidence.h"

#include "attestation.h"
#include "crypto.h"

// SGX Remote Attestation UUID.
static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

// Change a random byte in the provided buffer to a different random byte
void perturb(std::vector<uint8_t>& buf) {
    // Sample a random index
    auto idx = rand() % buf.size();

    // Sample a new, different value for that index
    uint8_t new_val = (uint8_t)rand() % 256;
    while (new_val == buf[idx])
        new_val = (uint8_t)rand() % 256;

    // Set the new value
    buf[idx] = new_val;
}

// Swap chunks of size `block_size` in the provided buffer
void swap_blocks(std::vector<uint8_t>& buf, size_t block_size) {
    size_t num_blocks = buf.size() / block_size;

    ASSERT_GT(num_blocks, 2)
        << "Invalid parameters: message must be at least two blocks in length";

    // Sample two, unique indices for swapping
    auto idx_1 = rand() % num_blocks;
    auto idx_2 = rand() % num_blocks;
    while (idx_1 == idx_2)
        idx_2 = rand() % num_blocks;

    // Swap the two blocks
    for (int i = 0; i < block_size; i++) {
        auto tmp = buf[idx_1 * block_size + i];
        buf[idx_1 * block_size + i] = buf[idx_2 * block_size + i];
        buf[idx_2 * block_size + i] = tmp;
    }
}

// Loads a file into the provided buffer
void load_file(std::string path, std::vector<uint8_t>& buf) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    buf = std::vector<uint8_t>(file.tellg());
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buf.data()), buf.size());
}

namespace {

    /*
     * Shared cryptographic state used across tests
     */
    class UtilsTest : public testing::Test {
       protected:
        void SetUp() override {
            // Generate a random symmetric key
            crypto.RandGen(sym_key, CIPHER_KEY_SIZE);

            // Write the public key to PEM format
            crypto.WritePublicKey(pem_key);

            // Generate a random message
            msg = std::vector<uint8_t>(1024);
            crypto.RandGen(msg.data(), msg.size());

            attestation =
                std::unique_ptr<Attestation>(new Attestation(&crypto));
        }

        Crypto crypto;
        std::unique_ptr<Attestation> attestation;
        uint8_t sym_key[CIPHER_KEY_SIZE];
        uint8_t pem_key[CIPHER_PK_SIZE];
        std::vector<uint8_t> msg;
    };

    // ##############################
    // ##### COMPLETENESS TESTS #####
    // ##############################

    // Dummy class to create a new test suite
    class CompletenessTest : public UtilsTest {};

    TEST_F(CompletenessTest, SymEnc) {
        // Encrypt the message along with the additionally-authenticated string
        // "aad"
        std::vector<uint8_t> ct(crypto.SymEncSize(msg.size()));
        ASSERT_EQ(0, crypto.SymEnc(sym_key, msg.data(),
                                   reinterpret_cast<const uint8_t*>("aad"),
                                   ct.data(), msg.size(), strlen("aad")));

        // Decrypt the message
        std::vector<uint8_t> pt(crypto.SymDecSize(ct.size()));
        ASSERT_EQ(0, crypto.SymDec(sym_key, ct.data(),
                                   reinterpret_cast<const uint8_t*>("aad"),
                                   pt.data(), ct.size(), strlen("aad")));

        for (int i = 0; i < msg.size(); i++)
            ASSERT_EQ(msg[i], pt[i]) << "Message and plaintext do not match";
    }

    TEST_F(CompletenessTest, AsymEnc) {
        // Encrypt the message
        std::vector<uint8_t> ct(crypto.AsymEncSize(msg.size()));
        ASSERT_EQ(0,
                  crypto.AsymEnc(pem_key, msg.data(), ct.data(), msg.size()));

        // Decrypt the message
        std::vector<uint8_t> pt(crypto.AsymDecSize(ct.size()));
        size_t _pt_size;
        ASSERT_EQ(0,
                  crypto.AsymDec(ct.data(), pt.data(), ct.size(), &_pt_size));

        for (int i = 0; i < msg.size(); i++)
            ASSERT_EQ(msg[i], pt[i]) << "Message and plaintext do not match";
    }

    TEST_F(CompletenessTest, Sig) {
        // Sign the message
        std::vector<uint8_t> sig(crypto.AsymSignSize());
        ASSERT_EQ(0, crypto.Sign(msg.data(), sig.data(), msg.size()));

        // Verify the signature
        ASSERT_EQ(0, crypto.Verify(pem_key, msg.data(), sig.data(), msg.size()))
            << "Signature failed to verify";
    }

#ifdef HOST
    TEST_F(CompletenessTest, SigUsingKeyfile) {
        // Sign the message
        std::vector<uint8_t> sig(crypto.AsymSignSize());
        ASSERT_EQ(0,
                  crypto.SignUsingKeyfile("../../tests/data/private.pem",
                                          msg.data(), sig.data(), msg.size()));

        // Load public verification key from file
        std::vector<uint8_t> pub_key;
        load_file(std::string("../../tests/data/public.pub"), pub_key);

        // Verify the signature
        ASSERT_EQ(0, crypto.Verify(pub_key.data(), msg.data(), sig.data(),
                                   msg.size()));
    }
#endif

    TEST_F(CompletenessTest, Attestation) {
        // Currently the unittests only support building for the host, so we
        // can't generate evidence. Instead we verify pre-generated evidence.

        // Load nonce, public key, enclave signing key, and evidence from file.
        // The evidence was generated using this particular nonce, public key,
        // and enclave signing key.
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> pub_key;
        std::vector<uint8_t> signing_key;
        std::vector<uint8_t> evidence;
        load_file(std::string("../../tests/data/nonce"), nonce);
        load_file(std::string("../../tests/data/report_key.pub"), pub_key);
        load_file(std::string("../../tests/data/signing_key.pub"), signing_key);
        load_file(std::string("../../tests/data/evidence"), evidence);

        // Verify the evidence
        ASSERT_EQ(0, attestation->AttestEvidence(
                         &sgx_remote_uuid, signing_key.data(), evidence.data(),
                         pub_key.data(), nonce.data(), signing_key.size() + 1,
                         evidence.size(), pub_key.size()));
    }

    // ###########################
    // ##### SOUNDNESS TESTS #####
    // ###########################

    // Dummy class to create a new test suite
    class SoundnessTest : public UtilsTest {};

    TEST_F(SoundnessTest, SymEnc) {
        // Encrypt the message along with the additionally-authenticated string
        // "aad"
        std::vector<uint8_t> ct(crypto.SymEncSize(msg.size()));
        ASSERT_EQ(0, crypto.SymEnc(sym_key, msg.data(),
                                   reinterpret_cast<const uint8_t*>("aad"),
                                   ct.data(), msg.size(), strlen("aad")));

        // We don't care about the value of the decryptions (they all should
        // fail) so we can use the same plaintext vector for each decryption
        std::vector<uint8_t> pt(crypto.SymDecSize(ct.size()));

        // 1) Make random pertubations in the ciphertexts
        for (int i = 0; i < 100; i++) {
            std::vector<uint8_t> perturbed_ct(ct);
            perturb(perturbed_ct);
            ASSERT_NE(
                0, crypto.SymDec(sym_key, perturbed_ct.data(),
                                 reinterpret_cast<const uint8_t*>("aad"),
                                 pt.data(), perturbed_ct.size(), strlen("aad")))
                << "Perturbed ciphertext decrypted successfully";
        }

        // 2) Change the IV
        uint8_t new_iv[CIPHER_IV_SIZE];
        crypto.RandGen(new_iv, CIPHER_IV_SIZE);

        std::vector<uint8_t> perturbed_ct(ct);
        for (int i = 0; i < CIPHER_IV_SIZE; i++) {
            perturbed_ct[i] = new_iv[i];
        }
        ASSERT_NE(
            0, crypto.SymDec(sym_key, perturbed_ct.data(),
                             reinterpret_cast<const uint8_t*>("aad"), pt.data(),
                             perturbed_ct.size(), strlen("aad")))
            << "Ciphertext with invalid IV decrypted successfully";

        // 3) Use incorrect AAD
        ASSERT_NE(0, crypto.SymDec(sym_key, ct.data(),
                                   reinterpret_cast<const uint8_t*>("aa"),
                                   pt.data(), ct.size(), strlen("aa")))
            << "Ciphertext with invalid AAD decrypted successfully";

        // 4) Decrypt with the wrong key
        uint8_t new_key[CIPHER_KEY_SIZE];
        crypto.RandGen(new_key, CIPHER_KEY_SIZE);

        ASSERT_NE(0, crypto.SymDec(new_key, ct.data(),
                                   reinterpret_cast<const uint8_t*>("aad"),
                                   pt.data(), ct.size(), strlen("aad")))
            << "Ciphertext decrypted successfully with incorrect key";

        // 5) Remove last block of ciphertext
        perturbed_ct = std::vector<uint8_t>(ct);
        perturbed_ct.resize(perturbed_ct.size() - CIPHER_KEY_SIZE);

        ASSERT_NE(
            0, crypto.SymDec(sym_key, perturbed_ct.data(),
                             reinterpret_cast<const uint8_t*>("aad"), pt.data(),
                             perturbed_ct.size(), strlen("aad")))
            << "Truncated ciphertext decrypted successfully";

        // 6) Swap random blocks in the ciphertext
        //
        // Each ciphertext is formated as:
        //      IV || TAG || ENCRYPTED BLOCK || ENCRYPTED BLOCK || ...
        //
        // We modify the part of the ciphertext including only the encrypted
        // blocks (not the IV or tag) by swapping the ordering of these blocks
        // before attempting decryption.
        for (int i = 0; i < 100; i++) {
            perturbed_ct = std::vector<uint8_t>(ct);
            std::vector<uint8_t> ct_blocks(
                perturbed_ct.begin() + CIPHER_IV_SIZE + CIPHER_TAG_SIZE,
                perturbed_ct.end());
            swap_blocks(ct_blocks, CIPHER_KEY_SIZE);
            for (int j = CIPHER_IV_SIZE + CIPHER_TAG_SIZE;
                 j < perturbed_ct.size(); j++) {
                perturbed_ct[j] = ct_blocks[j];
            }

            ASSERT_NE(
                0, crypto.SymDec(sym_key, perturbed_ct.data(),
                                 reinterpret_cast<const uint8_t*>("aad"),
                                 pt.data(), perturbed_ct.size(), strlen("aad")))
                << "Ciphertext decrypted successfully with swapped blocks";
        }
    }

    TEST_F(SoundnessTest, AsymEnc) {
        // Encrypt the message
        std::vector<uint8_t> ct(crypto.AsymEncSize(msg.size()));
        ASSERT_EQ(0,
                  crypto.AsymEnc(pem_key, msg.data(), ct.data(), msg.size()));

        // We don't care about the value of the decryptions (they all should
        // fail) so we can use the same plaintext vector for each decryption
        std::vector<uint8_t> pt(crypto.AsymDecSize(ct.size()));
        size_t _pt_size;

        // 1) Make random pertubations in the ciphertexts
        for (int i = 0; i < 100; i++) {
            std::vector<uint8_t> perturbed_ct(ct);
            perturb(perturbed_ct);
            ASSERT_NE(0, crypto.AsymDec(perturbed_ct.data(), pt.data(),
                                        perturbed_ct.size(), &_pt_size))
                << "Perturbed ciphertext decrypted successfully";
        }

        // 2) Decrypt with the wrong key
        // Load a public key from file - this is a public key belonging to a
        // different keypair than the one that `crypto` interally generated.
        std::vector<uint8_t> new_key;
        load_file(std::string("../../tests/data/public.pub"), new_key);

        // Encrypt a ct with the new key
        std::vector<uint8_t> new_ct(crypto.AsymEncSize(msg.size()));
        ASSERT_EQ(0, crypto.AsymEnc(new_key.data(), msg.data(), new_ct.data(),
                                    msg.size()));

        // Attempt to decrypt the ciphertext using the incorrect private key.
        // `AsymDec` uses an internally generated private key that is different
        // than the corresponding private key of `new_key`.
        ASSERT_NE(0, crypto.AsymDec(new_ct.data(), pt.data(), new_ct.size(),
                                    &_pt_size))
            << "Ciphertext decrypted successfully with incorrect key";

        // 3) Remove last block of ciphertext
        std::vector<uint8_t> perturbed_ct(ct);
        perturbed_ct.resize(perturbed_ct.size() - RSA_MOD_SIZE);

        ASSERT_NE(0, crypto.AsymDec(perturbed_ct.data(), pt.data(),
                                    perturbed_ct.size(), &_pt_size))
            << "Truncated ciphertext decrypted successfully";

        // 4) Swap random blocks in the ciphertext.
        //
        // Each ciphertext is a sequence of encrypted blocks of equal size.
        // We swap the ordering of these blocks before attempting decryption.
        for (int i = 0; i < 100; i++) {
            std::vector<uint8_t> perturbed_ct(ct);
            swap_blocks(perturbed_ct, RSA_MOD_SIZE);
            ASSERT_NE(0, crypto.AsymDec(perturbed_ct.data(), pt.data(),
                                        perturbed_ct.size(), &_pt_size))
                << "Ciphertext decrypted successfully with swapped blocks";
        }
    }

    TEST_F(SoundnessTest, Sig) {
        // Sign the message
        std::vector<uint8_t> sig(crypto.AsymSignSize());
        ASSERT_EQ(0, crypto.Sign(msg.data(), sig.data(), msg.size()));

        // 1) Make random pertubations in the signature
        for (int i = 0; i < 100; i++) {
            std::vector<uint8_t> perturbed_sig(sig);
            perturb(perturbed_sig);
            ASSERT_NE(0, crypto.Verify(pem_key, msg.data(),
                                       perturbed_sig.data(), msg.size()))
                << "Perturbed signature verified successfully";
        }

        // 2) Make random pertubations in the message
        for (int i = 0; i < 100; i++) {
            std::vector<uint8_t> perturbed_msg(msg);
            perturb(perturbed_msg);
            ASSERT_NE(0, crypto.Verify(pem_key, perturbed_msg.data(),
                                       sig.data(), perturbed_msg.size()))
                << "Perturbed message verified successfully";
        }

        // 3) Verify with the wrong key
        // Load public key from file
        std::vector<uint8_t> new_key;
        load_file(std::string("../../tests/data/public.pub"), new_key);

        ASSERT_NE(0, crypto.Verify(new_key.data(), msg.data(), sig.data(),
                                   msg.size()))
            << "Message verified with the incorrect key";
    }

    TEST_F(SoundnessTest, Attestation) {
        // Currently the unittests only support building for the host, so we
        // can't generate evidence. Instead we modify pre-generated evidence

        // Load nonce, public key, enclave signing key, and evidence from file.
        // The evidence was generated using this particular nonce, public key,
        // and enclave signing key.
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> pub_key;
        std::vector<uint8_t> signing_key;
        std::vector<uint8_t> evidence;
        load_file(std::string("../../tests/data/nonce"), nonce);
        load_file(std::string("../../tests/data/report_key.pub"), pub_key);
        load_file(std::string("../../tests/data/signing_key.pub"), signing_key);
        load_file(std::string("../../tests/data/evidence"), evidence);

        // Make random pertubations in the evidence
        for (int i = 0; i < 100; i++) {
            std::vector<uint8_t> perturbed_evidence(evidence);
            perturb(perturbed_evidence);
            ASSERT_NE(0, attestation->AttestEvidence(
                             &sgx_remote_uuid, signing_key.data(),
                             perturbed_evidence.data(), pub_key.data(),
                             nonce.data(), signing_key.size() + 1,
                             perturbed_evidence.size(), pub_key.size()))
                << "Perturbed evidence verified successfully";
        }

        // Use a different nonce
        uint8_t new_nonce[CIPHER_IV_SIZE];
        crypto.RandGen(new_nonce, CIPHER_IV_SIZE);

        ASSERT_NE(0, attestation->AttestEvidence(
                         &sgx_remote_uuid, signing_key.data(), evidence.data(),
                         pub_key.data(), new_nonce, signing_key.size() + 1,
                         evidence.size(), pub_key.size()))
            << "Evidence verified successfully with invalid nonce";

        // Use an incorrect public key. The evidence was generate using
        // `pub_key`, but we instead attempt to verify the evidence with the
        // randomly-generated `pem_key`.
        ASSERT_NE(0, attestation->AttestEvidence(
                         &sgx_remote_uuid, signing_key.data(), evidence.data(),
                         pem_key, new_nonce, signing_key.size() + 1,
                         evidence.size(), CIPHER_PK_SIZE))
            << "Evidence verified successfully with invalid public key";

        // Use an invalid enclave signing key
        ASSERT_NE(0, attestation->AttestEvidence(
                         &sgx_remote_uuid, pem_key, evidence.data(),
                         pub_key.data(), new_nonce, CIPHER_PK_SIZE + 1,
                         evidence.size(), pub_key.size()))
            << "Evidence verified successfully with invalid signing key";
    }

}  // namespace
