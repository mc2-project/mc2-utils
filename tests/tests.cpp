#include <stdlib.h>
#include <fstream>

#include "crypto.h"
#include "gtest/gtest.h"

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

// Loads the public keyfile in the tests/ directory into the provided buffer
void load_pub_key(std::vector<uint8_t>& pem_key) {
  std::ifstream pem_file("../../tests/public.pub",
                         std::ios::binary | std::ios::ate);
  pem_key = std::vector<uint8_t>(pem_file.tellg());
  pem_file.seekg(0, std::ios::beg);
  pem_file.read(reinterpret_cast<char*>(pem_key.data()), pem_key.size());
}

namespace {

/*
 * Shared cryptographic state used across tests
 */
class CryptoTest : public testing::Test {
 protected:
  void SetUp() override {
    // Generate a random symmetric key
    crypto.RandGen(sym_key, CIPHER_KEY_SIZE);

    // Write the public key to PEM format
    crypto.WritePublicKey(pem_key);

    // Generate a random message
    msg = std::vector<uint8_t>(1024);
    crypto.RandGen(msg.data(), msg.size());
  }

  Crypto crypto;
  uint8_t sym_key[CIPHER_KEY_SIZE];
  uint8_t pem_key[CIPHER_PK_SIZE];
  std::vector<uint8_t> msg;
};

// ##############################
// ##### COMPLETENESS TESTS #####
// ##############################

// Dummy class to create a new test suite
class CompletenessTest : public CryptoTest {};

TEST_F(CompletenessTest, SymEnc) {
  // Encrypt the message
  std::vector<uint8_t> ct(crypto.SymEncSize(msg.size()));
  ASSERT_EQ(0, crypto.SymEnc(sym_key, msg.data(),
                             reinterpret_cast<const uint8_t*>("aad"), ct.data(),
                             msg.size(), strlen("aad")));

  // Decrypt the message
  std::vector<uint8_t> pt(crypto.SymDecSize(ct.size()));
  ASSERT_EQ(0, crypto.SymDec(sym_key, ct.data(),
                             reinterpret_cast<const uint8_t*>("aad"), pt.data(),
                             ct.size(), strlen("aad")));

  for (int i = 0; i < msg.size(); i++)
    ASSERT_EQ(msg[i], pt[i]) << "Message and plaintext do not match";
}

TEST_F(CompletenessTest, AsymEnc) {
  // Encrypt the message
  std::vector<uint8_t> ct(crypto.AsymEncSize(msg.size()));
  ASSERT_EQ(0, crypto.AsymEnc(pem_key, msg.data(), ct.data(), msg.size()));

  // Decrypt the message
  std::vector<uint8_t> pt(crypto.AsymDecSize(ct.size()));
  size_t _pt_size;
  ASSERT_EQ(0, crypto.AsymDec(ct.data(), pt.data(), ct.size(), &_pt_size));

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
  ASSERT_EQ(0, crypto.SignUsingKeyfile("../../tests/private.pem", msg.data(),
                                       sig.data(), msg.size()));

  // Load public verification key from file
  std::vector<uint8_t> pub_key;
  load_pub_key(pub_key);

  // Verify the signature
  ASSERT_EQ(0,
            crypto.Verify(pub_key.data(), msg.data(), sig.data(), msg.size()));
}
#endif

// ###########################
// ##### SOUNDNESS TESTS #####
// ###########################

// Dummy class to create a new test suite
class SoundnessTest : public CryptoTest {};

TEST_F(SoundnessTest, SymEnc) {
  // Encrypt the message
  std::vector<uint8_t> ct(crypto.SymEncSize(msg.size()));
  ASSERT_EQ(0, crypto.SymEnc(sym_key, msg.data(),
                             reinterpret_cast<const uint8_t*>("aad"), ct.data(),
                             msg.size(), strlen("aad")));

  // We don't care about the value of the decryptions (they all should fail)
  // so we can use the same plaintext vector for each decryption
  std::vector<uint8_t> pt(crypto.SymDecSize(ct.size()));

  // 1) Make random pertubations in the ciphertexts
  for (int i = 0; i < 100; i++) {
    std::vector<uint8_t> perturbed_ct(ct);
    perturb(perturbed_ct);
    ASSERT_NE(0, crypto.SymDec(sym_key, perturbed_ct.data(),
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
  ASSERT_NE(0, crypto.SymDec(sym_key, perturbed_ct.data(),
                             reinterpret_cast<const uint8_t*>("aad"), pt.data(),
                             perturbed_ct.size(), strlen("aad")))
      << "Ciphertext with invalid IV decrypted successfully";

  // 3) Use incorrect AAD
  ASSERT_NE(0, crypto.SymDec(sym_key, ct.data(),
                             reinterpret_cast<const uint8_t*>("aa"), pt.data(),
                             ct.size(), strlen("aa")))
      << "Ciphertext with invalid AAD decrypted successfully";

  // 4) Decrypt with the wrong key
  uint8_t new_key[CIPHER_KEY_SIZE];
  crypto.RandGen(new_key, CIPHER_KEY_SIZE);

  ASSERT_NE(0, crypto.SymDec(new_key, ct.data(),
                             reinterpret_cast<const uint8_t*>("aad"), pt.data(),
                             ct.size(), strlen("aad")))
      << "Ciphertext decrypted successfully with incorrect key";

  // 5) Remove last block of ciphertext
  perturbed_ct = std::vector<uint8_t>(ct);
  perturbed_ct.resize(perturbed_ct.size() - CIPHER_KEY_SIZE);

  ASSERT_NE(0, crypto.SymDec(sym_key, perturbed_ct.data(),
                             reinterpret_cast<const uint8_t*>("aad"), pt.data(),
                             perturbed_ct.size(), strlen("aad")))
      << "Truncated ciphertext decrypted successfully";

  // 6) Swap random blocks in the ciphertext
  for (int i = 0; i < 100; i++) {
    perturbed_ct = std::vector<uint8_t>(ct);
    std::vector<uint8_t> ct_blocks(
        perturbed_ct.begin() + CIPHER_IV_SIZE + CIPHER_TAG_SIZE,
        perturbed_ct.end());
    swap_blocks(ct_blocks, CIPHER_KEY_SIZE);
    for (int j = CIPHER_IV_SIZE + CIPHER_TAG_SIZE; j < perturbed_ct.size();
         j++) {
      perturbed_ct[j] = ct_blocks[j];
    }

    ASSERT_NE(0, crypto.SymDec(sym_key, perturbed_ct.data(),
                               reinterpret_cast<const uint8_t*>("aad"),
                               pt.data(), perturbed_ct.size(), strlen("aad")))
        << "Ciphertext decrypted successfully with swapped blocks";
  }
}

TEST_F(SoundnessTest, AsymEnc) {
  // TODO: Make a random pertubation in the ciphertext
  // TODO: Decrypt with the wrong key
  // TODO: Remove last block - I believe this will actually pass
  // TODO: swap blocks

  // Encrypt the message
  std::vector<uint8_t> ct(crypto.AsymEncSize(msg.size()));
  ASSERT_EQ(0, crypto.AsymEnc(pem_key, msg.data(), ct.data(), msg.size()));

  // We don't care about the value of the decryptions (they all should fail)
  // so we can use the same plaintext vector for each decryption
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
  // Load public key from file
  std::vector<uint8_t> new_key;
  load_pub_key(new_key);

  // Encrypt a ct with the new key
  std::vector<uint8_t> new_ct(crypto.AsymEncSize(msg.size()));
  ASSERT_EQ(
      0, crypto.AsymEnc(new_key.data(), msg.data(), new_ct.data(), msg.size()));

  ASSERT_NE(0,
            crypto.AsymDec(new_ct.data(), pt.data(), new_ct.size(), &_pt_size))
      << "Ciphertext decrypted successfully with incorrect key";

  // 3) Remove last block of ciphertext
  std::vector<uint8_t> perturbed_ct(ct);
  perturbed_ct.resize(perturbed_ct.size() - RSA_MOD_SIZE);

  ASSERT_NE(0, crypto.AsymDec(perturbed_ct.data(), pt.data(),
                              perturbed_ct.size(), &_pt_size))
      << "Truncated ciphertext decrypted successfully";

  // 4) Swap random blocks in the ciphertext
  for (int i = 0; i < 100; i++) {
    std::vector<uint8_t> perturbed_ct(ct);
    swap_blocks(perturbed_ct, RSA_MOD_SIZE);
    ASSERT_NE(0, crypto.AsymDec(perturbed_ct.data(), pt.data(),
                                perturbed_ct.size(), &_pt_size))
        << "Ciphertext decrypted successfully with swapped blocks";
  }
}

TEST_F(SoundnessTest, Sig) {
  // TODO: Malleate a signature
  // TODO: Verify with the wrong key
  // TODO: Verify a different message

  // Sign the message
  std::vector<uint8_t> sig(crypto.AsymSignSize());
  ASSERT_EQ(0, crypto.Sign(msg.data(), sig.data(), msg.size()));

  // 1) Make random pertubations in the signature
  for (int i = 0; i < 100; i++) {
    std::vector<uint8_t> perturbed_sig(sig);
    perturb(perturbed_sig);
    ASSERT_NE(
        0, crypto.Verify(pem_key, msg.data(), perturbed_sig.data(), msg.size()))
        << "Perturbed signature verified successfully";
  }

  // 2) Make random pertubations in the message
  for (int i = 0; i < 100; i++) {
    std::vector<uint8_t> perturbed_msg(msg);
    perturb(perturbed_msg);
    ASSERT_NE(0, crypto.Verify(pem_key, perturbed_msg.data(), sig.data(),
                               perturbed_msg.size()))
        << "Perturbed message verified successfully";
  }

  // 3) Verify with the wrong key
  // Load public key from file
  std::vector<uint8_t> new_key;
  load_pub_key(new_key);

  ASSERT_NE(0,
            crypto.Verify(new_key.data(), msg.data(), sig.data(), msg.size()))
      << "Message verified with the incorrect key";
}

}  // namespace
