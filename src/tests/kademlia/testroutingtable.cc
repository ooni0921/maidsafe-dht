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
#include "base/crypto.h"
#include "kademlia/kbucket.h"
#include "kademlia/kadutils.h"
#include "kademlia/routingtable.h"
#include "maidsafe/maidsafe-dht.h"

bool TestInRange(const std::string &key, const kad::BigInt &min_range,
    const kad::BigInt &max_range) {
  std::string key_enc;
  base::encode_to_hex(key, key_enc);
  key_enc = "0x"+key_enc;
  kad::BigInt key_val(key_enc);
  if (min_range > key_val) {
    std::cout << "under min range\n";
    std::cout << "val " << key_val << std::endl;
  }
  if (key_val > max_range) {
    std::cout << "above max range\n";
    std::cout << "val " << key_val << std::endl;
  }
  return static_cast<bool>(min_range <= key_val && key_val <= max_range);
}


class TestRoutingTable : public testing::Test {
 public:
  TestRoutingTable() : cry_obj() {}
 protected:
    void SetUp() {
      cry_obj.set_symm_algorithm("AES_256");
      cry_obj.set_hash_algorithm("SHA512");
    }
    crypto::Crypto cry_obj;
};


TEST_F(TestRoutingTable, BEH_KAD_AddContact) {
  std::string enc_id = "ef420cd03b20acc07f79441c6560b8e8953f0b601a968d71311abe6"
    "f1f5feb2611692309c66f77f93ffdac4adbeddb3a28fe3b0b92d1d23592ad9847f49580df";
  std::string holder_id;
  base::decode_from_hex(enc_id, holder_id);
  kad::RoutingTable routingtable(holder_id);
  std::string ip = "127.0.0.1";
  unsigned short port = 8888;
  std::string ids[16];
  ids[0] = "461b69b40db1800f0b9a6cc13c257c6a06043b57841149fbbbca4dea3bcbf9119ff"
    "7cd13be0e752cf65c57b1d5abe05e5f936c9bbe1fd04fed50e97482918bae";
  ids[1] = "9e4ac275d0c0fc00fa106d9aa9db0db4e687ae2044cfbf8fcb3f371c3cb8c0d9e72"
    "583a68dc8a3ed8909b9e757d58485f654d596fd334902ca00d5ead44a87d5";
  ids[2] = "b13b8119e8d71d161b8c8e51e98326c5b82732c62f7e24be38deac1cc52ef184d78"
    "df907ff69a958a4810d7dfe22185c1798738dfee47cc194e7ca4a02d06e65";
  ids[3] = "1168eb6f58212ae41fe12fc69feb72463411754a57b83fdc7d296fcd75bdfceb539"
    "3469bf720ab0ed9f90cd10394991dcdaa133aa44a4e83b29dde66c0b716cb";
  ids[4] = "279a0166dba744ae67afff262f243e835acd795a25a122fa1c1c22a63030e013abf"
    "532fbeb4c9289e06bd478df22e255970b21f40c300bdf416b9ebcc1c8bf11";
  ids[5] = "e1f923b3defffeb6984c7c4570c99065432bd04bc0dc14fcc856bcc7472ef50a9eb"
    "15dc961e995e990f2621c43aaa259f8adfc65f74cef33a07045711073b1a1";
  ids[6] = "833b754224a2e351e40fc929d97b342f3468c0cfbea72e091370cf1a2fef7ccd4c2"
    "a0319ed0b1d808c071cc9671aa3eccafd4953c32d099b76bd2477ab9dd421";
  ids[7] = "6d5b6b3b10eebc0dfa9116059e30bf05e028fd6e4d4dfc80a3d56ce914f0d465f27"
    "baeb73d58f231530d7e72b15d2b5a59e6a2a746177d155d4e65b3a98f502c";
  ids[8] = "b9226326f7cb561e3a96e16989a1132d278a9443704c9da7b2925906d3ec80d4a21"
    "d84d5f8c52ea32626a5725cabd487bee4ded843388d65adb43112bf9b3bfa";
  ids[9] = "1f5630997a272e79d1e7091d275e5b9e115c1e2c34a5626954fba571c51b2ca29e1"
    "1dc56d60481cdf96bfdca6d0ddca016479b5ef27bba55504069e694ead957";
  ids[10] = "c05074e15f4ce0621b400d1d3da43061089294812431aaf36cab4089262eddc606"
    "bbffcd9505c277b568de4bac3e6140ce56c5e5a51b162b18127b50faa83bd7";
  ids[11] = "3dfa8a4321609f53acb492b725d9bbca32a23b14b55da092768b1d42bb36049c24"
    "7ba90ca77fa254c04e5d32be101face6285617adc32e5c92255579487f9b73";
  ids[12] = "2e6338ae33ec9a3dccc453591bc3ae3faf9ef568c66a9531d2911426d05cfe9cc8"
    "7d0922652b7d0c8544800952cc4c7669ac2eac6cd63c2da46072583b9ca835";
  ids[13] = "914aed585420dea515780906a5222e7d3848945708d497d598a41c0732a7427e75"
    "dedd698081d5ac7c09f3e2cbd5c58f466865752fac961e89e731b2c4f59c09";
  ids[14] = "b18bc05200319ce0339a68881cca8672af639ee11945188608553885330428850a"
    "4f81c8f289dd080e1f929c029810cf1ffdc82cdfd4331238f0e6a940862f1c";
  ids[15] = "a27b24b72c37e7862613b29e86502dae6f863170eb1621a04a06f909588348427b"
    "2c3bc623d7ef1bf59bd3efa010c69b19a1d8732c8512ff8510ea46176ad383";
  for (int i = 0; i < 16 && i < kad::K; i++) {
    std::string id;
    base::decode_from_hex(ids[i], id);
    kad::Contact contact(id, ip, port + i, ip, port + i);
    ASSERT_EQ(0, routingtable.AddContact(contact));
}
}

TEST_F(TestRoutingTable, BEH_KAD_Add_Get_Contact) {
  std::string holder_id = kad::vault_random_id();
  kad::RoutingTable routingtable(holder_id);
  int id = rand();  // NOLINT
  std::cout << "id: "<< id << std::endl;
  std::string contact_id = cry_obj.Hash(base::itos(id), "",
    crypto::STRING_STRING, false);
  std::string ip = "127.0.0.1";
  unsigned short port = 8888;
  kad::Contact contact(contact_id, ip, port, ip, port);
  ASSERT_EQ(0, routingtable.AddContact(contact));
  kad::Contact rec_contact;
  ASSERT_TRUE(routingtable.GetContact(contact_id, &rec_contact));
  ASSERT_TRUE(contact == rec_contact);
  std::cout << "Recoverd contact " << rec_contact.ToString();
}

TEST_F(TestRoutingTable, BEH_KAD_Add_Remove_Contact) {
  std::string holder_id = kad::vault_random_id();
  kad::RoutingTable routingtable(holder_id);
  int id = rand();  // NOLINT
  std::string contact_id = cry_obj.Hash(base::itos(id), "",
    crypto::STRING_STRING, false);
  std::string ip = "127.0.0.1";
  unsigned short port = 8888;
  kad::Contact contact(contact_id, ip, port, ip, port);
  ASSERT_EQ(0, routingtable.AddContact(contact));

  for (int i = 0; i < kad::kFailedRpc; i++) {
    routingtable.RemoveContact(contact_id, false);
    kad::Contact rec_contact;
    ASSERT_TRUE(routingtable.GetContact(contact_id, &rec_contact));
    ASSERT_EQ(i+1, rec_contact.failed_rpc());
  }

  routingtable.RemoveContact(contact_id, false);
  kad::Contact rec_contact1;
  ASSERT_FALSE(routingtable.GetContact(contact_id, &rec_contact1));
}

TEST_F(TestRoutingTable, BEH_KAD_Add_Remove_Add_Contact) {
  std::string holder_id = kad::vault_random_id();
  kad::RoutingTable routingtable(holder_id);
  int id = rand();  // NOLINT
  std::string contact_id = cry_obj.Hash(base::itos(id), "",
    crypto::STRING_STRING, false);
  std::string ip = "127.0.0.1";
  unsigned short port = 8888;
  kad::Contact contact(contact_id, ip, port, ip, port);
  ASSERT_EQ(0, routingtable.AddContact(contact));

  routingtable.RemoveContact(contact_id, false);
  kad::Contact rec_contact;
  ASSERT_FALSE(routingtable.GetContact(contact_id, &rec_contact));
}

TEST_F(TestRoutingTable, BEH_KAD_SplitKBucket) {
  std::string holder_id = kad::vault_random_id();
  kad::RoutingTable routingtable(holder_id);
  int id[kad::K+1];
  kad::Contact contacts[kad::K+1];
  id[0] = base::random_32bit_uinteger() %5000 +1;
  for (int i = 0; i < kad::K+1; i++)
    id[i] = id[0] + i;
  std::string contact_id;
  std::string ip = "127.0.0.1";
  unsigned short port = 8880;
  for (int i = 0; i < kad::K+1; i++) {
    contact_id = cry_obj.Hash(base::itos(id[i]), "", crypto::STRING_STRING,
        false);
    port++;
    kad::Contact contact(contact_id, ip, port, ip, port);
    contacts[i] = contact;
    ASSERT_EQ(0, routingtable.AddContact(contact));
  }
  for (int i = 0; i < kad::K+1; i++) {
    contact_id = cry_obj.Hash(base::itos(id[i]), "", crypto::STRING_STRING,
        false);
    kad::Contact rec_contact;
    ASSERT_TRUE(routingtable.GetContact(contact_id, &rec_contact));
    ASSERT_TRUE(contacts[i] == rec_contact);
  }
}

TEST_F(TestRoutingTable, BEH_KAD_NoSplitKBucket) {
  std::string enc_holder_id;
  for (int i = 0; i < kad::kKeySizeBytes*2; i++)
    enc_holder_id += "1";
  std::string holder_id;
  base::decode_from_hex(enc_holder_id, holder_id);
  kad::RoutingTable routingtable(holder_id);
  std::string contacts_id[kad::K+1];
  kad::Contact contacts[kad::K+1];
  for (int i = 0; i < kad::K+1; i++) {
    for (int j = 0; j < kad::kKeySizeBytes*2; j++)
      contacts_id[i] += "d";
  }
  for (int i = 0; i < kad::K+1; i++) {
    std::string rep;
    for (int j = 0; j < i; j++)
      rep+="f";
    contacts_id[i].replace(0, i, rep);
  }
  std::string contact_id;
  std::string ip = "127.0.0.1";
  unsigned short port = 8880;
  for (int i = 0; i < kad::K; i++) {
    contact_id = "";
    base::decode_from_hex(contacts_id[i], contact_id);
    port++;
    kad::Contact contact(contact_id, ip, port, ip, port);
    contacts[i] = contact;
    ASSERT_EQ(0, routingtable.AddContact(contact));
  }

  contact_id = "";
  base::decode_from_hex(contacts_id[kad::K], contact_id);
  port++;
  kad::Contact contact1(contact_id, ip, port, ip, port);
  ASSERT_LT(0, routingtable.AddContact(contact1));
  kad::Contact rec_contact;
  ASSERT_FALSE(routingtable.GetContact(contact_id, &rec_contact));
}

TEST_F(TestRoutingTable, BEH_KAD_RefreshList_Touch) {
  std::string holder_id;
  kad::BigInt min_range(0);
  kad::BigInt max_range(2);
  max_range.pow(kad::kKeySizeBytes*8);
  max_range--;
  kad::BigInt max_range1(2);
  max_range1.pow((kad::kKeySizeBytes*8)-1);
  max_range1--;
  kad::BigInt max_range2(2);
  max_range2.pow((kad::kKeySizeBytes*8)-2);
  max_range2--;
  kad::BigInt max_range3(2);
  max_range3.pow((kad::kKeySizeBytes*8)-3);
  max_range3--;
  holder_id = kad::random_kademlia_id(min_range, max_range3);
  kad::RoutingTable routingtable(holder_id);
  ASSERT_TRUE(max_range > max_range1);

  std::vector<std::string> ids;
  for (int i = 0; i < kad::K; i++) {
    std::string id = kad::random_kademlia_id(max_range1, max_range);
    while (!TestInRange(id, max_range1, max_range))
      id = kad::random_kademlia_id(max_range1, max_range);
    for (int j = 0; j < static_cast<int>(ids.size()); j++) {
      while (ids[j] == id || !TestInRange(id, max_range1, max_range)) {
        id = kad::random_kademlia_id(max_range1, max_range);
      }
    }
    ids.push_back(id);
  }
  unsigned short port = 8880;
  std::string ip = "127.0.0.1";
  for (int i = 0; i < static_cast<int>(ids.size());i++) {
    kad::Contact contact(ids[i], ip, port, ip, port);
    ASSERT_EQ(0, routingtable.AddContact(contact));
    port++;
  }
  ids.clear();

  for (int i = 0; i < kad::K; i++) {
    std::string id = kad::random_kademlia_id(max_range2, max_range1);
    while (!TestInRange(id, max_range2, max_range1))
      id = kad::random_kademlia_id(max_range2, max_range1);
    for (int j = 0; j < static_cast<int>(ids.size()); j++) {
      while (ids[j] == id || !TestInRange(id, max_range2, max_range1)) {
        id = kad::random_kademlia_id(max_range2, max_range1);
      }
    }
    ids.push_back(id);
  }
  for (int i = 0; i < static_cast<int>(ids.size()); i++) {
    kad::Contact contact(ids[i], ip, port, ip, port);
    ASSERT_EQ(0, routingtable.AddContact(contact));
    port++;
  }
  ids.clear();
  for (int i = 0; i < kad::K; i++) {
    std::string id = kad::random_kademlia_id(max_range3, max_range2);
    while (!TestInRange(id, max_range3, max_range2))
      id = kad::random_kademlia_id(max_range3, max_range2);
    for (int j = 0; j < static_cast<int>(ids.size()); j++) {
      while (ids[j] == id || !TestInRange(id, max_range3, max_range2)) {
        id = kad::random_kademlia_id(max_range3, max_range2);
      }
    }
    ids.push_back(id);
  }
  for (int i = 0; i < static_cast<int>(ids.size());i++) {
    kad::Contact contact(ids[i], ip, port, ip, port);
    ASSERT_EQ(0, routingtable.AddContact(contact));
    port++;
  }
  ids.clear();

  for (int i = 0; i < kad::K+1; i++) {
    std::string id = kad::random_kademlia_id(min_range, max_range3);
    while (!TestInRange(id, min_range, max_range3))
      id = kad::random_kademlia_id(min_range, max_range3);
    for (int j = 0; j < static_cast<int>(ids.size()); j++) {
      while (ids[j] == id || !TestInRange(id, min_range, max_range3)) {
        id = kad::random_kademlia_id(min_range, max_range3);
      }
    }
    ids.push_back(id);
  }
  for (int i = 0; i < static_cast<int>(ids.size()); i++) {
    kad::Contact contact(ids[i], ip, port, ip, port);
    ASSERT_EQ(0, routingtable.AddContact(contact));
    port++;
  }

  std::vector<std::string> refresh_ids;
  routingtable.GetRefreshList(&refresh_ids, 0 , false);
  ASSERT_EQ(5, static_cast<int>(refresh_ids.size()));
  ASSERT_TRUE(TestInRange(refresh_ids[0], min_range, max_range3));
  ASSERT_TRUE(TestInRange(refresh_ids[1], min_range, max_range3));
  ASSERT_TRUE(TestInRange(refresh_ids[2], max_range3, max_range2));
  ASSERT_TRUE(TestInRange(refresh_ids[3], max_range2, max_range1));
  ASSERT_TRUE(TestInRange(refresh_ids[4], max_range1, max_range));
  routingtable.TouchKBucket(refresh_ids[1]);
  routingtable.TouchKBucket(refresh_ids[2]);
  refresh_ids.clear();
  routingtable.GetRefreshList(&refresh_ids, 0 , false);
  ASSERT_EQ(3, static_cast<int>(refresh_ids.size()));
  ASSERT_TRUE(TestInRange(refresh_ids[0], min_range, max_range3));
  ASSERT_TRUE(TestInRange(refresh_ids[1], max_range2, max_range1));
  ASSERT_TRUE(TestInRange(refresh_ids[2], max_range1, max_range));
  refresh_ids.clear();
  routingtable.GetRefreshList(&refresh_ids, 0, true);
  ASSERT_EQ(5, static_cast<int>(refresh_ids.size()));
}

TEST_F(TestRoutingTable, BEH_KAD_GetCloseContacts) {
  std::string holder_id;
  kad::BigInt min_range(0);
  kad::BigInt max_range(2);
  max_range.pow(kad::kKeySizeBytes*8);
  max_range--;
  kad::BigInt max_range1(2);
  max_range1.pow((kad::kKeySizeBytes*8)-1);
  max_range1--;
  kad::BigInt max_range2(2);
  max_range2.pow((kad::kKeySizeBytes*8)-2);
  max_range2--;
  kad::BigInt max_range3(2);
  max_range3.pow((kad::kKeySizeBytes*8)-3);
  max_range3--;
  holder_id = kad::random_kademlia_id(min_range, max_range2);
  kad::RoutingTable routingtable(holder_id);
  ASSERT_TRUE(max_range > max_range1);

  std::vector<std::string> ids;
  for (int i = 0; i < kad::K; i++) {
    std::string id = kad::random_kademlia_id(max_range1, max_range);
    while (!TestInRange(id, max_range1, max_range))
      id = kad::random_kademlia_id(max_range1, max_range);
    for (int j = 0; j < static_cast<int>(ids.size()); j++) {
      while (ids[j] == id || !TestInRange(id, max_range1, max_range)) {
        id = kad::random_kademlia_id(max_range1, max_range);
      }
    }
    ids.push_back(id);
  }
  unsigned short port = 8880;
  std::string ip = "127.0.0.1";
  for (int i = 0; i < static_cast<int>(ids.size());i++) {
    kad::Contact contact(ids[i], ip, port, ip, port);
    ASSERT_EQ(0, routingtable.AddContact(contact));
    port++;
  }
  ids.clear();

  for (int i = 0; i < kad::K; i++) {
    std::string id = kad::random_kademlia_id(max_range2, max_range1);
    while (!TestInRange(id, max_range2, max_range1))
      id = kad::random_kademlia_id(max_range2, max_range1);
    for (int j = 0; j < static_cast<int>(ids.size()); j++) {
      while (ids[j] == id || !TestInRange(id, max_range2, max_range1)) {
        id = kad::random_kademlia_id(max_range2, max_range1);
      }
    }
    ids.push_back(id);
  }
  for (int i = 0; i < static_cast<int>(ids.size()); i++) {
    kad::Contact contact(ids[i], ip, port, ip, port);
    ASSERT_EQ(0, routingtable.AddContact(contact));
    port++;
  }
  ids.clear();

  std::vector<kad::Contact> close_nodes, ex_contacts;
//  boost::this_thread::sleep(boost::posix_time::seconds(0));
  std::string search_id = kad::random_kademlia_id(max_range1, max_range);
  routingtable.FindCloseNodes(search_id, kad::K-1, &close_nodes, ex_contacts);
  ASSERT_EQ(kad::K-1, static_cast<int>(close_nodes.size()));
  for (int i = 0; i < kad::K-1; i++)
    ASSERT_TRUE(TestInRange(close_nodes[i].node_id(), max_range1, max_range));
}

TEST_F(TestRoutingTable, BEH_KAD_ClearRoutingTable) {
  std::string enc_id = "ef420cd03b20acc07f79441c6560b8e8953f0b601a968d71311abe6"
    "f1f5feb2611692309c66f77f93ffdac4adbeddb3a28fe3b0b92d1d23592ad9847f49580df";
  std::string holder_id;
  base::decode_from_hex(enc_id, holder_id);
  kad::RoutingTable routingtable(holder_id);
  std::string ip = "127.0.0.1";
  unsigned short port = 8888;
  std::string ids[16];
  ids[0] = "461b69b40db1800f0b9a6cc13c257c6a06043b57841149fbbbca4dea3bcbf9119ff"
    "7cd13be0e752cf65c57b1d5abe05e5f936c9bbe1fd04fed50e97482918bae";
  ids[1] = "9e4ac275d0c0fc00fa106d9aa9db0db4e687ae2044cfbf8fcb3f371c3cb8c0d9e72"
    "583a68dc8a3ed8909b9e757d58485f654d596fd334902ca00d5ead44a87d5";
  ids[2] = "b13b8119e8d71d161b8c8e51e98326c5b82732c62f7e24be38deac1cc52ef184d78"
    "df907ff69a958a4810d7dfe22185c1798738dfee47cc194e7ca4a02d06e65";
  ids[3] = "1168eb6f58212ae41fe12fc69feb72463411754a57b83fdc7d296fcd75bdfceb539"
    "3469bf720ab0ed9f90cd10394991dcdaa133aa44a4e83b29dde66c0b716cb";
  ids[4] = "279a0166dba744ae67afff262f243e835acd795a25a122fa1c1c22a63030e013abf"
    "532fbeb4c9289e06bd478df22e255970b21f40c300bdf416b9ebcc1c8bf11";
  ids[5] = "e1f923b3defffeb6984c7c4570c99065432bd04bc0dc14fcc856bcc7472ef50a9eb"
    "15dc961e995e990f2621c43aaa259f8adfc65f74cef33a07045711073b1a1";
  ids[6] = "833b754224a2e351e40fc929d97b342f3468c0cfbea72e091370cf1a2fef7ccd4c2"
    "a0319ed0b1d808c071cc9671aa3eccafd4953c32d099b76bd2477ab9dd421";
  ids[7] = "6d5b6b3b10eebc0dfa9116059e30bf05e028fd6e4d4dfc80a3d56ce914f0d465f27"
    "baeb73d58f231530d7e72b15d2b5a59e6a2a746177d155d4e65b3a98f502c";
  ids[8] = "b9226326f7cb561e3a96e16989a1132d278a9443704c9da7b2925906d3ec80d4a21"
    "d84d5f8c52ea32626a5725cabd487bee4ded843388d65adb43112bf9b3bfa";
  ids[9] = "1f5630997a272e79d1e7091d275e5b9e115c1e2c34a5626954fba571c51b2ca29e1"
    "1dc56d60481cdf96bfdca6d0ddca016479b5ef27bba55504069e694ead957";
  ids[10] = "c05074e15f4ce0621b400d1d3da43061089294812431aaf36cab4089262eddc606"
    "bbffcd9505c277b568de4bac3e6140ce56c5e5a51b162b18127b50faa83bd7";
  ids[11] = "3dfa8a4321609f53acb492b725d9bbca32a23b14b55da092768b1d42bb36049c24"
    "7ba90ca77fa254c04e5d32be101face6285617adc32e5c92255579487f9b73";
  ids[12] = "2e6338ae33ec9a3dccc453591bc3ae3faf9ef568c66a9531d2911426d05cfe9cc8"
    "7d0922652b7d0c8544800952cc4c7669ac2eac6cd63c2da46072583b9ca835";
  ids[13] = "914aed585420dea515780906a5222e7d3848945708d497d598a41c0732a7427e75"
    "dedd698081d5ac7c09f3e2cbd5c58f466865752fac961e89e731b2c4f59c09";
  ids[14] = "b18bc05200319ce0339a68881cca8672af639ee11945188608553885330428850a"
    "4f81c8f289dd080e1f929c029810cf1ffdc82cdfd4331238f0e6a940862f1c";
  ids[15] = "a27b24b72c37e7862613b29e86502dae6f863170eb1621a04a06f909588348427b"
    "2c3bc623d7ef1bf59bd3efa010c69b19a1d8732c8512ff8510ea46176ad383";
  for (int i = 0; i < 16&&i < kad::K; i++) {
    std::string id;
    base::decode_from_hex(ids[i], id);
    kad::Contact contact(id, ip, port + i, ip, port + i);
    ASSERT_EQ(0, routingtable.AddContact(contact));
  }
  if (kad::K > 16)
    ASSERT_EQ(16, routingtable.Size());
  else
    ASSERT_EQ(kad::K, routingtable.Size());
  routingtable.Clear();
  ASSERT_EQ(0, routingtable.Size());
}

TEST_F(TestRoutingTable, BEH_KAD_ForceK) {
  std::string holder_id;
  kad::BigInt range1(0);
  kad::BigInt range2(2);
  range2.pow((kad::kKeySizeBytes*8)-3);
  range2--;
  kad::BigInt range3(2);
  range3.pow((kad::kKeySizeBytes*8)-2);
  range3--;
  kad::BigInt range4(2);
  range4.pow((kad::kKeySizeBytes*8)-1);
  range4--;
  kad::BigInt range5(2);
  range5.pow((kad::kKeySizeBytes*8));
  range5--;
  ASSERT_TRUE(range5 > range4);
  ASSERT_TRUE(range4 > range3);
  ASSERT_TRUE(range3 > range2);
  ASSERT_TRUE(range2 > range1);
  holder_id = kad::random_kademlia_id(range1, range1 + 10);
  kad::RoutingTable routingtable(holder_id);
  boost::uint64_t now = base::get_epoch_milliseconds();
  // fill the first bucket
  std::string ip = "127.0.0.1";
  unsigned short port = 8888;
  for (int i = 0; i < kad::K - 1; i++) {
    port++;
    std::string id = kad::random_kademlia_id(range1, range2);
    kad::Contact new_contact(id, ip, port, ip, port);
    ASSERT_EQ(0, routingtable.AddContact(new_contact));
  }
  ASSERT_EQ(kad::K - 1, routingtable.Size());
  // fill the second bucket
  for (int i = 0; i < kad::K - 1; i++) {
    port++;
    std::string id = kad::random_kademlia_id(range4 + 2, range5 - 1);
    kad::Contact new_contact(id, ip, port, ip, port);
    ASSERT_EQ(0, routingtable.AddContact(new_contact));
  }
  ASSERT_EQ(2*kad::K-2, routingtable.Size());
  // make the second bucket full with a furthest peer
  port++;
  std::string id = kad::random_kademlia_id(range5 - 1, range5);
  kad::Contact furthest_contact(id, ip, port, ip, port);
  furthest_contact.set_last_seen(now);  // make sure this peer has the highest
                                        // score
  ASSERT_EQ(0, routingtable.AddContact(furthest_contact));
  ASSERT_EQ(2*kad::K-1, routingtable.Size());
  // Force K will take effect when the new peer is among the K cloeset peers
  id = kad::random_kademlia_id(range4+1, range4+2);
  port++;
  kad::Contact new_contact(id, ip, port, ip, port);
  ASSERT_EQ(0, routingtable.AddContact(new_contact));
  ASSERT_EQ(2*kad::K-1, routingtable.Size());
  kad::Contact new_contact1;
  ASSERT_TRUE(routingtable.GetContact(new_contact.node_id(),
                                      &new_contact1));
  ASSERT_TRUE(new_contact == new_contact1);
  kad::Contact furthest_contact1;
  ASSERT_FALSE(routingtable.GetContact(furthest_contact.node_id(),
                                       &furthest_contact1));
  // new peer which is not among K closest peers won't be accepted
  ASSERT_EQ(2, routingtable.AddContact(furthest_contact));
  ASSERT_EQ(2*kad::K-1, routingtable.Size());
  // make the routingtable split further, there will be 4 buckets
  for (int i = 0; i < kad::K - 1; i++) {
    port++;
    std::string id = kad::random_kademlia_id(range3+2, range4-1);
    kad::Contact new_contact(id, ip, port, ip, port);
    ASSERT_EQ(0, routingtable.AddContact(new_contact));
  }
  ASSERT_EQ(3*kad::K - 2, routingtable.Size());
  // make the brother bucket of the peer full with a furthest peer
  port++;
  id = kad::random_kademlia_id(range4-1, range4);
  kad::Contact furthest_contact2(id, ip, port, ip, port);
  furthest_contact2.set_last_seen(now);  // make sure this peer has the highest
                                        // score
  ASSERT_EQ(0, routingtable.AddContact(furthest_contact2));
  ASSERT_EQ(3*kad::K - 1, routingtable.Size());
  // Force K will take effect when the new peer is among the K cloeset peers
  id = kad::random_kademlia_id(range3 + 1, range3 + 2);
  port++;
  kad::Contact new_contact2(id, ip, port, ip, port);
  ASSERT_EQ(0, routingtable.AddContact(new_contact2));
  ASSERT_EQ(3*kad::K-1, routingtable.Size());
  kad::Contact new_contact3;
  ASSERT_TRUE(routingtable.GetContact(new_contact2.node_id(),
                                      &new_contact3));
  ASSERT_TRUE(new_contact2 == new_contact3);
  kad::Contact furthest_contact3;
  ASSERT_FALSE(routingtable.GetContact(furthest_contact2.node_id(),
                                       &furthest_contact3));
  // new peer which is not among K closest peers won't be accepted
  ASSERT_EQ(2, routingtable.AddContact(furthest_contact2));
  ASSERT_EQ(3*kad::K-1, routingtable.Size());
}

TEST_F(TestRoutingTable, BEH_KAD_GetLastSeenContact) {
  std::string enc_holder_id = "7";
  for (int i = 1; i < kad::kKeySizeBytes*2; i++)
    enc_holder_id += "1";
  std::string holder_id;
  base::decode_from_hex(enc_holder_id, holder_id);
  kad::RoutingTable routingtable(holder_id);
  std::string contacts_id_first[(kad::K/2)+1];
  std::string contacts_id_second[kad::K/2];
  kad::Contact contacts[kad::K+1];
  for (int i = 0; i < (kad::K/2)+1; i++) {
    for (int j = 0; j < kad::kKeySizeBytes*2; j++)
      contacts_id_first[i] += "d";
    if (i < (kad::K/2)) {
      for (int j = 0; j < kad::kKeySizeBytes*2; j++)
        contacts_id_second[i] += "d";
    }
  }
  for (int i = 0; i < (kad::K/2)+1; i++) {
    std::string rep;
    for (int j = 0; j < i+1; j++)
      rep+="f";
    contacts_id_first[i].replace(0, i, rep);
    contacts_id_first[i].replace(0, 1, "6");
  }
  for (int i = 0; i < kad::K/2; i++) {
    std::string rep;
    for (int j = 0; j < i+1; j++)
      rep+="f";
    contacts_id_second[i].replace(0, i+1, rep);
    contacts_id_second[i].replace(0, 1, "8");
  }
  kad::Contact empty;
  kad::Contact result;
  result = routingtable.GetLastSeenContact(0);
  ASSERT_TRUE(empty == result);
  std::string contact_id;
  std::string ip = "127.0.0.1";
  unsigned short port = 8880;
  for (int i = 0; i < (kad::K/2)+1; i++) {
    contact_id = "";
    base::decode_from_hex(contacts_id_first[i], contact_id);
    port++;
    kad::Contact contact(contact_id, ip, port, ip, port);
    contacts[i] = contact;
    ASSERT_EQ(0, routingtable.AddContact(contact));
  }
  contact_id = "";
  base::decode_from_hex(contacts_id_first[0], contact_id);
  kad::Contact last_first(contact_id, ip, 8880+1, ip, 8880+1);
  result = routingtable.GetLastSeenContact(0);
  ASSERT_TRUE(last_first == result);
  for (int i = 0; i < kad::K/2; i++) {
    contact_id = "";
    base::decode_from_hex(contacts_id_second[i], contact_id);
    port++;
    kad::Contact contact(contact_id, ip, port, ip, port);
    contacts[i] = contact;
    ASSERT_EQ(0, routingtable.AddContact(contact));
  }
  ASSERT_EQ(2, routingtable.KbucketSize());
  ASSERT_EQ(kad::K+1, routingtable.Size());
  contact_id = "";
  base::decode_from_hex(contacts_id_first[0], contact_id);
  kad::Contact last_second(contact_id, ip, 8880+(kad::K/2)+2, ip,
    8880+(kad::K/2)+2);
  result = routingtable.GetLastSeenContact(1);
  ASSERT_TRUE(last_second == result);
  result = routingtable.GetLastSeenContact(0);
  ASSERT_TRUE(last_first == result);
  result = routingtable.GetLastSeenContact(2);
  ASSERT_TRUE(empty == result);
}

TEST_F(TestRoutingTable, BEH_KAD_GetKClosestContacts) {
  std::string holder_id_enc("7"), holder_id;
  for (int i = 1; i < kad::kKeySizeBytes*2; i++)
    holder_id_enc += "1";
  std::vector<kad::Contact> ids1(kad::K/2);
  std::vector<kad::Contact> ids2(kad::K-2);
  base::decode_from_hex(holder_id_enc, holder_id);
  kad::RoutingTable routingtable(holder_id);
  std::string ip = "127.0.0.1";
  uint16_t port = 8000;
  for (int i = 0; i < kad::K/2; i++) {
    std::string id(kad::kKeySizeBytes*2, '6'), rep(i, 'a'), dec_id;
    id.replace(1, i, rep);
    base::decode_from_hex(id, dec_id);
    kad::Contact contact(dec_id, ip, port, ip, port);
    ids1[i] = contact;
    ++port;
    ASSERT_EQ(0, routingtable.AddContact(ids1[i]));
  }
  for (int i = 0; i < kad::K-2; i++) {
    std::string id(kad::kKeySizeBytes*2, 'f'), rep(kad::K-1-i, '0'), dec_id;
    id.replace(1, kad::K-1-i, rep);
    base::decode_from_hex(id, dec_id);
    kad::Contact contact(dec_id, ip, port, ip, port);
    ids2[i] = contact;
    ++port;
    ASSERT_EQ(0, routingtable.AddContact(ids2[i]));
    ASSERT_EQ(static_cast<boost::uint64_t>(kad::kKeySizeBytes)*2, id.size());
  }
  ASSERT_EQ(2, routingtable.KbucketSize());
  std::string id1(kad::kKeySizeBytes, 0x5);
  std::vector<kad::Contact> cts, ex;
  routingtable.FindCloseNodes(id1, kad::K, &cts, ex);
  ASSERT_EQ(kad::K, cts.size());
  // Getting nodes that are not in cts
  for (int i = 0; i < kad::K/2; i++) {
    bool in_cts = false;
    for (boost::uint32_t j = 0; j < cts.size() && !in_cts; j++) {
      if (cts[j] == ids1[i])
        in_cts = true;
    }
    if (!in_cts)
      ex.push_back(ids1[i]);
  }
  ASSERT_EQ(static_cast<boost::uint16_t>(0), ex.size());
  for (int i = 0; i < kad::K-2; i++) {
    bool in_cts = false;
    for (boost::uint32_t j = 0; j < cts.size() && !in_cts; j++) {
      if (cts[j] == ids2[i])
        in_cts = true;
    }
    if (!in_cts)
      ex.push_back(ids2[i]);
  }
  ASSERT_NE(static_cast<boost::uint16_t>(0), ex.size());
  // Checking distances
  for (boost::uint32_t i = 0; i < cts.size(); i++) {
    kad::BigInt cts_to_id = kad::kademlia_distance(id1, cts[i].node_id());
    for (boost::uint32_t j = 0; j < ex.size(); j++) {
      kad::BigInt ex_to_id = kad::kademlia_distance(id1, ex[j].node_id());
      ASSERT_TRUE(cts_to_id < ex_to_id);
    }
  }
}
