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

#include <gtest/gtest.h>
#include "maidsafe/maidsafe-dht.h"

bool InRange(const std::string &key, const kad::BigInt &min_range,
    const kad::BigInt &max_range) {
  std::string key_enc;
  base::encode_to_hex(key, key_enc);
  key_enc = "0x" + key_enc;
  kad::BigInt key_val(key_enc);
  return static_cast<bool>((min_range <= key_val && key_val <= max_range));
}

TEST(KadRandomId, BEH_KAD_InRange) {
  kad::BigInt min_range(2);
  kad::BigInt max_range(2);
  min_range.pow(510);
  max_range.pow(512);
  std::string id = kad::random_kademlia_id(min_range, max_range);
  std::string enc_id;
  base::encode_to_hex(id, enc_id);
  enc_id = "0x" + enc_id;
  kad::BigInt id_val(enc_id);
  ASSERT_GE(id_val, min_range);
  ASSERT_GE(max_range, id_val);
  ASSERT_TRUE(InRange(id, min_range, max_range));
}

TEST(KadRandomId, BEH_KAD_InRangeKadEnv) {
  kad::BigInt min_range(0);
  kad::BigInt max_range(2);
  max_range.pow(kad::kKeySizeBytes*8);
  max_range--;
  for (int i = 0; i < 7; i++) {
    kad::BigInt x(2);
    x.pow(i);
    kad::BigInt y(2);
    y.pow(i+1);
    std::string id = kad::random_kademlia_id(max_range/y, max_range/x);
    std::string enc_id;
    base::encode_to_hex(id, enc_id);
    enc_id = "0x" + enc_id;
    kad::BigInt id_val(enc_id);
    ASSERT_GE(id_val, max_range/y);
    ASSERT_GE(max_range/x, id_val);
    ASSERT_TRUE(InRange(id, max_range/y, max_range/x));
  }
  kad::BigInt x(2);
  x.pow(7);
  std::string id = kad::random_kademlia_id(min_range, max_range/x);
  std::string enc_id;
  base::encode_to_hex(id, enc_id);
  enc_id = "0x" + enc_id;
  kad::BigInt id_val(enc_id);
  ASSERT_GE(id_val, min_range);
  ASSERT_GE(max_range, id_val);
  for (int i = 1; i < 512; i++) {
    kad::BigInt x(2);
    x.pow(i);
    std::string id = kad::random_kademlia_id(min_range, x);
    std::string enc_id;
    base::encode_to_hex(id, enc_id);
    enc_id = "0x" + enc_id;
    kad::BigInt id_val(enc_id);
    if (enc_id == "0x00")
      id_val = 0;
    ASSERT_GE(id_val, min_range);
    ASSERT_GE(max_range, id_val);
  }
}

TEST(KadDistance, BEH_KAD_DistanceTest) {
  kad::BigInt x(0);
  kad::BigInt y(2);
  y.pow(512);
  y--;
  std::string id1 = kad::random_kademlia_id(x, y);
  std::string id2 = kad::random_kademlia_id(x, y);
  while (id1 == id2)
    id2 = kad::random_kademlia_id(x, y);
  ASSERT_NE(id1, id2);
  kad::BigInt res = kad::kademlia_distance(id1, id1);
  kad::BigInt zero(0);
  ASSERT_EQ(zero, res);
  ASSERT_LT(zero, kad::kademlia_distance(id1, id2));
  ASSERT_EQ(kad::kademlia_distance(id1, id2),
    kad::kademlia_distance(id2, id1));
}

TEST(ClientNodeId, FUNC_KAD_ClientCreateId) {
  std::string id = kad::client_node_id();
  ASSERT_EQ(kad::kKeySizeBytes, static_cast<int>(id.size()));
  for (int i = 0; i < kad::kKeySizeBytes; i++)
    ASSERT_EQ(id[i], '\0');
  std::string enc_id;
  base::encode_to_hex(id, enc_id);
  for (int i = 0; i < kad::kKeySizeBytes*2; i++)
    ASSERT_EQ(enc_id[i], '0');
  kad::BigInt exp_value(0);
  enc_id = "0x"+enc_id;
  kad::BigInt id_value(enc_id);
  kad::BigInt res = id_value-exp_value;
  ASSERT_EQ(exp_value, res);
}

TEST(VaultNodeId, FUNC_KAD_VaultCreateId) {
  std::string id;
  kad::BigInt min_range(0);
  kad::BigInt max_range(2);
  max_range.pow(kad::kKeySizeBytes*8);
  max_range--;
  for (int i = 0; i < 50; i++) {
    id = kad::vault_random_id();
    ASSERT_TRUE(InRange(id, min_range, max_range));
    base::sleep(1);
  }
}
