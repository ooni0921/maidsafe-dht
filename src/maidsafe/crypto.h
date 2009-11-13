/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef MAIDSAFE_CRYPTO_H_
#define MAIDSAFE_CRYPTO_H_
#include <string>

namespace crypto {

const int AES256_KeySize = 32;  // size in bytes
const int AES256_IVSize = 16;   // in bytes

enum operationtype {FILE_FILE, STRING_FILE, FILE_STRING, STRING_STRING };
enum hashtype {SHA_512, SHA_1, /*SHA_224, */SHA_256, SHA_384};
enum symmtype {AES_256};
enum obfuscationtype {XOR};

class Crypto {
 public:
  Crypto() : hash_algorithm_(SHA_512), symm_algorithm_(AES_256) {}
  std::string Obfuscate(const std::string &first,
                        const std::string &second,
                        obfuscationtype obt);
  std::string SecurePassword(const std::string &password, int pin);
  inline void set_hash_algorithm(hashtype type) {hash_algorithm_ = type;}
  inline hashtype hash_algorithm() const {return hash_algorithm_;}
  //   The Hash function returns an empty string if the input from a file
  //   could not be read or cannot write the output to a file
  std::string Hash(const std::string &input,
                   const std::string &output,
                   operationtype ot,
                   bool hex);
  //  Encryption and Decryption return an empty string if the input from
  //  a file could not be read or cannot write the output to a file
  inline void set_symm_algorithm(symmtype type) {symm_algorithm_ = type;}
  inline symmtype symm_algorithm() const {return symm_algorithm_;}
  std::string SymmEncrypt(const std::string &input,
                          const std::string &output,
                          operationtype ot,
                          const std::string &key);
  std::string SymmDecrypt(const std::string &input,
                          const std::string &output,
                          operationtype ot,
                          const std::string &key);
  //  ASYMMETRIC ENCRYPTION (RSA)
  //  Encryption, Decryption and Sign return an empty string if the string
  //  passed for key is not a valid key or the type (public/private) is
  //  incorrect for the operation.  It also returns an empty string if the input
  //  from a file could not be read or cannot write the output to a file.
  //  AsymmEncrypt -- key is a public key.
  std::string AsymEncrypt(const std::string &input,
                          const std::string &output,
                          const std::string &key,
                          operationtype ot);
  // AsymDecrypt -- key is a private key
  std::string AsymDecrypt(const std::string &input,
                          const std::string &output,
                          const std::string &key,
                          operationtype ot);
  // AsymSign -- key is a private key.  Dependinging on the operation type, the
  // function returns either the 512 bit signature or the path to output file
  // which contains the signature.
  std::string AsymSign(const std::string &input,
                       const std::string &output,
                       const std::string &key,
                       operationtype ot);
  // AsymCheckSig -- key is a public key
  // The operations only take into consideration the INPUT, where both
  // input_data and input_signature must be of the same type (STRING / FILE).
  bool AsymCheckSig(const std::string &input_data,
                    const std::string &input_signature,
                    const std::string &key,
                    operationtype ot);
  // String or file compression using gzip.  Compression level must be between 0
  // and 9 inclusive or function returns "".  It also returns an empty string if
  // input from a file could not be read or cannot write the output to a file.
  std::string Compress(const std::string &input,
                       const std::string &output,
                       int compression_level,
                       operationtype ot);
  std::string Uncompress(const std::string &input,
                         const std::string &output,
                         operationtype ot);
 private:
  std::string XOROperation(const std::string &first,
                           const std::string &second);
  template <class T>
  std::string HashFunc(const std::string &input,
                       const std::string &output,
                       operationtype ot,
                       bool hex,
                       T hash);
  hashtype hash_algorithm_;
  symmtype symm_algorithm_;
};

class RsaKeyPair {
 public:
  RsaKeyPair() : public_key_(""), private_key_("") {}
  inline std::string public_key() {return public_key_;}
  inline std::string private_key() {return private_key_;}
  inline void set_public_key(std::string publickey) {
    public_key_ = publickey;
  }
  inline void set_private_key(std::string privatekey) {
    private_key_ = privatekey;
  }
  inline void ClearKeys() {private_key_ = public_key_ = "";}
  void GenerateKeys(unsigned int keySize);  // keySize in bits
 private:
  std::string public_key_;
  std::string private_key_;
};

}   // namespace crypto
#endif  // MAIDSAFE_CRYPTO_H_

