// #include <ofstream>
// #include <iostream>
#include <cstdlib>
#include <iostream>
#include <gtest/gtest.h>
#include "base/crypto.h"

using namespace crypto;

namespace {

class RSAKeysTest : public testing::Test {
 protected:
  RsaKeyPair rsakp;
  RSAKeysTest() : rsakp() {}
};

class CryptoTest : public testing::Test {
 protected:
  Crypto ct;
  CryptoTest() : ct() {}
};

// a tool to generate random length of string
std::string RandomString(int len){
  std::string str;
  for ( int i = 0 ; i < len ; ++i ){
    int num;
    num = rand()%122;
    if ( 48 > num )
      num += 48;
      if ( ( 57 < num ) && ( 65 > num ) )
        num += 7;
      if ( ( 90 < num ) && ( 97 > num ) )
        num += 6;
      str += (char)num;
  }
  return str;
}

} // namespace

//  Obfuscation tests
TEST_F(CryptoTest, FUNC_BASE_ObfuscatDiffSizes) {
  std::string obfuscated = ct.Obfuscate(RandomString(1024),RandomString(1234),XOR);
  ASSERT_TRUE(obfuscated == ""); // To be checked, empty string means error = operation not performed because
                                 // otherwise it returns a non empty string
}
TEST_F(CryptoTest, BEH_BASE_Obfuscation) {
  std::string str1 = RandomString(1024);
  std::string str2 = RandomString(1024);
  std::string obfuscated = ct.Obfuscate(str1,str2,XOR);
  std::string teststr2 = ct.Obfuscate(obfuscated,str1,XOR);
  std::string teststr1 = ct.Obfuscate(obfuscated,str2,XOR);
  ASSERT_TRUE(teststr1 == str1) << "First string not reformed correctly";
  ASSERT_TRUE(teststr2 == str2) << "Second string not reformed correctly";
}

//  Password generation
TEST_F(CryptoTest, BEH_BASE_SecurePasswordGeneration) {
    ASSERT_FALSE(ct.SecurePassword("oreja80",1000) == "") << "Password empty";
    // TODO: Include the test with industry standard data
}

//  Hashing
TEST_F(CryptoTest, BEH_BASE_SetAlgorithm) {
    ct.set_hash_algorithm("SHA512");
    ASSERT_EQ("SHA512",ct.hash_algorithm()) << "Set Failed";
    ct.set_hash_algorithm("SHA1");
    ASSERT_EQ("SHA1",ct.hash_algorithm()) << "Set Failed";
}
TEST_F(CryptoTest, BEH_BASE_GetAlgorithm) {
  ct.set_hash_algorithm("SHA512");
  ASSERT_FALSE(ct.hash_algorithm() == "") << "Hash algorithm empty";
}
TEST_F(CryptoTest, BEH_BASE_Hash) {
    ASSERT_TRUE(ct.Hash(RandomString(10*1024*1024),"",STRING_STRING, true) == "");
    ct.set_hash_algorithm("SHA512");
    ASSERT_FALSE(ct.Hash(RandomString(10*1024*1024),"",STRING_STRING, true) == "") << "Output data empty";
    // Industry Standards
    ASSERT_EQ(ct.Hash("abc","", STRING_STRING, true),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    ASSERT_EQ(ct.Hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "", STRING_STRING, true),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    ct.set_hash_algorithm("SHA1");
    ASSERT_EQ(ct.Hash("abc","", STRING_STRING, true),
        "a9993e364706816aba3e25717850c26c9cd0d89d");
    ASSERT_EQ(ct.Hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "", STRING_STRING, true),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    ct.set_hash_algorithm("SHA256");
    ASSERT_EQ(ct.Hash("abc","", STRING_STRING, true),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    ASSERT_EQ(ct.Hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "", STRING_STRING, true),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    ct.set_hash_algorithm("SHA384");
    ASSERT_EQ(ct.Hash("abc","", STRING_STRING, true),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    ASSERT_EQ(ct.Hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "", STRING_STRING, true),
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
}

//  Symmetric Encryption
TEST_F(CryptoTest, BEH_BASE_SetSymmAlgorithm) {
    ASSERT_TRUE(ct.set_symm_algorithm("AES_256")) << "SetSymmAlgorithm Failed";
    ASSERT_TRUE(ct.symm_algorithm() == "AES_256") << "GetSymmAlgorithm Failed";
}

TEST_F(CryptoTest, BEH_BASE_SymmEncrypt) {
    std::string key = "some key";
    std::string data = RandomString(10*1024*1024);
    ASSERT_TRUE(ct.SymmEncrypt(data,"",STRING_STRING,key) == "") << "Output data empty";
    ASSERT_TRUE(ct.SymmDecrypt(data,"",STRING_STRING,key) == "") << "Output data empty";
    EXPECT_TRUE(ct.set_symm_algorithm("AES_256"));
    std::string cipher_data = ct.SymmEncrypt(data,"",STRING_STRING,key);
    ASSERT_NE(cipher_data, "") << "Output data empty";
    ASSERT_EQ(data, ct.SymmDecrypt(cipher_data, "", STRING_STRING, key)) << "Error decrypting data";
    ASSERT_NE(data, ct.SymmDecrypt(cipher_data, "", STRING_STRING, "bad key"));
    // TODO: Include the test with industry standard data
}

//  Asymmetric Encryption
TEST_F(CryptoTest, BEH_BASE_AsymEncrypt) {
    std::string data = RandomString(100);
    ASSERT_EQ("", ct.AsymEncrypt(data,"",RandomString(2048),STRING_STRING)) << "Tried to encrypt with something that is not a public key";
    RsaKeyPair rsakp;
    rsakp.GenerateKeys(4096);
    std::string ciphertext = ct.AsymEncrypt(data,"",rsakp.public_key(),STRING_STRING);
    ASSERT_NE("", ciphertext) << "Returned empty string";
    // trying to decrypt
    ASSERT_EQ(data, ct.AsymDecrypt(ciphertext, "",rsakp.private_key(),STRING_STRING)) << "Failed to decrypt";
    // trying to decrypt with wrong private key
    rsakp.ClearKeys();
    rsakp.GenerateKeys(4096);
    ASSERT_EQ("", ct.AsymDecrypt(ciphertext, "",rsakp.private_key(),STRING_STRING));

    // TODO: Check maximum size of data we can encrypt
}
TEST_F(CryptoTest, BEH_BASE_AsymSign) {
    std::string data = RandomString(10*1024);
    ASSERT_EQ("", ct.AsymSign(data , "", RandomString(2048), STRING_STRING)) <<"Tried to sign with a string that is not a private key";
    RsaKeyPair rsakp;
    rsakp.GenerateKeys(4096);
    std::string signed_data = ct.AsymSign(data , "", rsakp.private_key(), STRING_STRING);
    ASSERT_NE("", signed_data);
    // Validating the signature
    ASSERT_TRUE(ct.AsymCheckSig(data, signed_data, rsakp.public_key(), STRING_STRING));
    // Trying to validate with another public key
    rsakp.ClearKeys();
    rsakp.GenerateKeys(4096);
    ASSERT_FALSE(ct.AsymCheckSig(data, signed_data, rsakp.public_key(), STRING_STRING));
}

//  RSA Key Pairs
TEST_F(RSAKeysTest, BEH_BASE_SetPublicKey) {
    std::string pub_key = RandomString(4096);
    rsakp.set_public_key(pub_key);
    ASSERT_TRUE(rsakp.public_key() == pub_key) << "GetPublicKey Failed";
}
TEST_F(RSAKeysTest, BEH_BASE_SetPrivateKey) {
    std::string pri_key = RandomString(4096);
    rsakp.set_private_key(pri_key);
    ASSERT_TRUE(rsakp.private_key() == pri_key) << "GetPrivateKey Failed";
}
TEST_F(RSAKeysTest, BEH_BASE_KeyGeneration) {
    rsakp.GenerateKeys(4096);
    ASSERT_NE("", rsakp.private_key()) << "Key generation Failed";
    ASSERT_NE("", rsakp.public_key()) << "Key generation Failed";
}
TEST_F(RSAKeysTest, BEH_BASE_ClearKeys) {
    rsakp.GenerateKeys(4096);
    EXPECT_NE("", rsakp.private_key());
    EXPECT_NE("", rsakp.public_key());
    rsakp.ClearKeys();
    ASSERT_EQ("", rsakp.private_key());
    ASSERT_EQ("", rsakp.public_key());
}
