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

#include "kademlia/kbucket.h"
#include "kademlia/contact.h"
#include "base/crypto.h"
#include "maidsafe/maidsafe-dht.h"

#include <gtest/gtest.h>

using namespace kad;

class TestKbucket : public testing::Test {
public:
TestKbucket() : cry_obj() {}
  protected:
    void SetUp(){
      cry_obj.set_symm_algorithm("AES_256");
      cry_obj.set_hash_algorithm("SHA512");
    }

    crypto::Crypto cry_obj;
};

TEST_F(TestKbucket, BEH_KAD_IsInRange) {
  BigInt min_value(0);
  std::string hex_max_val;
  for (int i=0;i<kKeySizeBytes*2;i++)
    hex_max_val += "f";
  hex_max_val = "0x" + hex_max_val;
  BigInt max_value(hex_max_val);
  KBucket kbucket1(min_value,max_value);
  std::string id = cry_obj.Hash("15641654616","",crypto::STRING_STRING,false);
  ASSERT_TRUE(kbucket1.KeyInRange(id));
  hex_max_val = "";
  for (int i=0;i<kKeySizeBytes;i++)
    hex_max_val += "a";
  hex_max_val = "0x" + hex_max_val;
  BigInt max_value1(hex_max_val);
  KBucket kbucket2(min_value, max_value1);
  std::string enc_id;
  for (int i=0;i<kKeySizeBytes*2;i++)
    enc_id += "b";
  id = "";
  base::decode_from_hex(enc_id, id);
  ASSERT_FALSE(kbucket2.KeyInRange(id));
}

TEST_F(TestKbucket, BEH_KAD_AddContactGetContact) {
  BigInt min_value(0);
  std::string hex_max_val;
  for (int i=0;i<kKeySizeBytes*2;i++)
    hex_max_val += "f";
  hex_max_val = "0x" + hex_max_val;
  BigInt max_value(hex_max_val);
  KBucket kbucket(min_value,max_value);
  std::string id[K];
  std::string ip = "127.0.0.1";
  unsigned short port = 8880;
  for (int i=0; i < K; i++) {
    ASSERT_EQ(i, kbucket.Size());
    id[i] = cry_obj.Hash(base::itos(i), "", crypto::STRING_STRING,false);
    port ++;
    Contact contact(id[i], ip, port, ip, port);
    ASSERT_EQ(SUCCEED,kbucket.AddContact(contact));
  }
  port ++;
  std::string id1;
  id1 = cry_obj.Hash("125486", "", crypto::STRING_STRING,false);
  ASSERT_EQ(K, kbucket.Size());
  Contact contact1(id1, ip, port, ip, port);
  ASSERT_EQ(FULL,kbucket.AddContact(contact1));
  ASSERT_EQ(K, kbucket.Size());
  port = 8880;
  for (int i=0; i < K; i++) {
    port ++;
    Contact contact(id[i], ip, port, ip, port);
    Contact contact_rec;
    ASSERT_TRUE(kbucket.GetContact(id[i], &contact_rec));
    ASSERT_EQ(contact.node_id(), contact_rec.node_id());
    ASSERT_EQ(contact.host_ip(), contact_rec.host_ip());
    ASSERT_EQ(contact.host_port(), contact_rec.host_port());
    ASSERT_EQ(contact.local_ip(), contact_rec.local_ip());
    ASSERT_EQ(contact.local_port(), contact_rec.local_port());
  }
  Contact contact_rec;
  ASSERT_FALSE( kbucket.GetContact("no id",&contact_rec));
}

TEST_F(TestKbucket, BEH_KAD_GetContacts) {
  BigInt min_value(0);
  std::string hex_max_val;
  for (int i=0;i<kKeySizeBytes*2;i++)
    hex_max_val += "f";
  hex_max_val = "0x" + hex_max_val;
  BigInt max_value(hex_max_val);
  KBucket kbucket(min_value,max_value);
  std::string id[kad::K -1];
  std::string ip = "127.0.0.1";
  unsigned short port[kad::K -1];
  for (int i=0; i < kad::K -1; i++) {
    id[i] = cry_obj.Hash(base::itos(i), "", crypto::STRING_STRING,false);
    port[i] = 8880 + i;
    Contact contact(id[i], ip, port[i], ip, port[i]);
    ASSERT_EQ(SUCCEED,kbucket.AddContact(contact));
  }
  ASSERT_EQ(kad::K -1, kbucket.Size());
  std::vector<Contact> contacts,ex_contacts;
  for (int i=0; i < kad::K -1 ; i++) {
    std::cout << "contacts retrieved = " << i+1 << std::endl;
    kbucket.GetContacts(i+1, ex_contacts, &contacts);
    ASSERT_EQ(i+1, (int)contacts.size());
    for (int j=0; j <= i ; j++) {
      Contact contact;
      ASSERT_TRUE(kbucket.GetContact(id[kad::K-2-j], &contact));
      ASSERT_TRUE(contact == contacts[j]);
    }
    contacts.clear();
  }
  Contact ex_contact1, ex_contact2;
  ASSERT_TRUE(kbucket.GetContact(id[1], &ex_contact1));
  ASSERT_TRUE(kbucket.GetContact(id[2], &ex_contact2));
  ex_contacts.push_back(ex_contact1);
  ex_contacts.push_back(ex_contact2);
  kbucket.GetContacts(kad::K -1, ex_contacts, &contacts);
  ASSERT_EQ(kad::K -3,(int)contacts.size());
  for (int i=0; i<kad::K -3 ;i++) {
    EXPECT_TRUE(contacts[i] != ex_contacts[0]);
    EXPECT_TRUE(contacts[i] !=  ex_contacts[1]);
  }
  contacts.clear();
  ex_contacts.clear();
  kbucket.GetContacts(K, ex_contacts, &contacts);
  ASSERT_EQ(kad::K -1, kbucket.Size());
  contacts.clear();
  Contact contact1(id[2], ip, 8882, ip, 8882);
  kbucket.AddContact(contact1);
  kbucket.GetContacts(1, ex_contacts, &contacts);
  Contact contact2;
  ASSERT_TRUE(kbucket.GetContact(id[2], &contact2));
  ASSERT_TRUE(contact2 == contacts[0]) << "the contact readded was not placed at the begging of the list";
}

TEST_F(TestKbucket, BEH_KAD_DeleteContact) {
  BigInt min_value(0);
  std::string hex_max_val;
  for (int i=0;i<kKeySizeBytes*2;i++)
    hex_max_val += "f";
  hex_max_val = "0x" + hex_max_val;
  BigInt max_value(hex_max_val);
  KBucket kbucket(min_value,max_value);
  std::string id[kad::K - 1];
  std::string ip = "127.0.0.1";
  unsigned short port = 8880;
  for (int i=0; i < kad::K - 1; i++) {
    id[i] = cry_obj.Hash(base::itos(i), "", crypto::STRING_STRING,false);
    port ++;
    Contact contact(id[i], ip, port, ip, port);
    ASSERT_EQ(SUCCEED,kbucket.AddContact(contact));
  }
  for (int i=0; i < kFailedRpc; i++) {
    ASSERT_EQ(kad::K - 1, kbucket.Size());
    kbucket.RemoveContact(id[2], false);
    Contact contact;
    ASSERT_TRUE(kbucket.GetContact(id[2], &contact));
    ASSERT_EQ(i+1, contact.failed_rpc());
  }
  ASSERT_EQ(kad::K - 1, kbucket.Size());
  kbucket.RemoveContact(id[2], false);
  ASSERT_EQ(kad::K - 2, kbucket.Size()) << "Size of kbucket same as before deleting the contact";
  Contact contact;
  ASSERT_FALSE(kbucket.GetContact(id[2], &contact));
  kbucket.RemoveContact(id[1],true);
  ASSERT_EQ(kad::K - 3, kbucket.Size()) << "Size of kbucket same as before deleting the contact";
  ASSERT_FALSE(kbucket.GetContact(id[1], &contact));
}

TEST_F(TestKbucket, BEH_KAD_SetLastAccessed) {
  BigInt min_value(0);
  std::string hex_max_val;
  for (int i=0;i<kKeySizeBytes*2;i++)
    hex_max_val += "f";
  hex_max_val = "0x" + hex_max_val;
  BigInt max_value(hex_max_val);
  KBucket kbucket(min_value,max_value);
  boost::int32_t time_accessed = base::get_epoch_time();
  kbucket.set_last_accessed(time_accessed);
  ASSERT_EQ(static_cast<boost::uint32_t>(time_accessed), kbucket.last_accessed());
}

TEST_F(TestKbucket, BEH_KAD_FillKbucketUpdateContet) {
  BigInt min_value(0);
  std::string hex_max_val;
  for (int i=0;i<kKeySizeBytes*2;i++)
    hex_max_val += "f";
  hex_max_val = "0x" + hex_max_val;
  BigInt max_value(hex_max_val);
  KBucket kbucket(min_value,max_value);
  std::string id[K];
  std::string ip = "127.0.0.1";
  unsigned short port[K];
  for (int i=0; i < K; i++) {
    id[i] = cry_obj.Hash(base::itos(i), "", crypto::STRING_STRING,false);
    port[i] = 8880 + i;
    Contact contact(id[i], ip, port[i], ip, port[i]);
    ASSERT_EQ(SUCCEED,kbucket.AddContact(contact));
  }
  ASSERT_EQ(K, kbucket.Size());
  std::vector<Contact> contacts,ex_contacts;
  Contact contact1(id[kad::K -1], ip, port[kad::K -1], ip, port[kad::K -1]);
  ASSERT_EQ(SUCCEED,kbucket.AddContact(contact1));
  for (int i=0; i < K ; i++) {
    std::cout << "contacts retrieved = " << i+1 << std::endl;
    kbucket.GetContacts(i+1, ex_contacts, &contacts);
    ASSERT_EQ(i+1, (int)contacts.size());
    Contact contact;
    ASSERT_TRUE(kbucket.GetContact(id[kad::K -1], &contact));
    ASSERT_TRUE(contact == contacts[0]);
    contacts.clear();
  }
}

TEST_F(TestKbucket, BEH_ADD_AddSameContact) {
  BigInt min_value(0);
  std::string hex_max_val;
  for (int i=0;i<kKeySizeBytes*2;i++)
    hex_max_val += "f";
  hex_max_val = "0x" + hex_max_val;
  BigInt max_value(hex_max_val);
  KBucket kbucket(min_value,max_value);
  std::string id[kad::K - 1];
  std::string ip = "127.0.0.1";
  unsigned short port[kad::K - 1];
  for (int i=0; i < kad::K - 1; i++) {
    id[i] = cry_obj.Hash(base::itos(i), "", crypto::STRING_STRING,false);
    port[i] = 8880 + i;
    Contact contact(id[i], ip, port[i], ip, port[i]);
    ASSERT_EQ(SUCCEED,kbucket.AddContact(contact));
  }
  ASSERT_EQ(kad::K - 1, kbucket.Size());
  std::vector<Contact> contacts,ex_contacts;
  for (int i=0; i < kad::K - 1 ; i++) {
    std::cout << "contacts retrieved = " << i+1 << std::endl;
    kbucket.GetContacts(i+1, ex_contacts, &contacts);
    ASSERT_EQ(i+1, (int)contacts.size());
    for (int j=0; j <= i ; j++) {
      Contact contact;
      ASSERT_TRUE(kbucket.GetContact(id[kad::K - 2-j], &contact));
      ASSERT_TRUE(contact == contacts[j]);
    }
    contacts.clear();
  }
  Contact ex_contact1, ex_contact2;
  ASSERT_TRUE(kbucket.GetContact(id[1], &ex_contact1));
  ASSERT_TRUE(kbucket.GetContact(id[2], &ex_contact2));
  ex_contacts.push_back(ex_contact1);
  ex_contacts.push_back(ex_contact2);
  kbucket.GetContacts(kad::K - 1, ex_contacts, &contacts);
  ASSERT_EQ(kad::K - 3,(int)contacts.size());
  for (int i=0; i<kad::K - 3 ;i++) {
    EXPECT_TRUE(contacts[i] != ex_contacts[0]);
    EXPECT_TRUE(contacts[i] !=  ex_contacts[1]);
  }
  contacts.clear();
  ex_contacts.clear();
  kbucket.GetContacts(K, ex_contacts, &contacts);
  ASSERT_EQ(kad::K - 1, kbucket.Size());
  contacts.clear();
  Contact contact1(id[2], "192.168.1.70", 8890, "192.168.1.70", 8890);
  ASSERT_EQ(SUCCEED, kbucket.AddContact(contact1));
  kbucket.GetContacts(1, ex_contacts, &contacts);
  Contact contact2;
  ASSERT_TRUE(kbucket.GetContact(id[2], &contact2));
  ASSERT_TRUE(contact2 == contacts[0]) << "the contact readded was not placed at the begging of the list";
  ex_contacts.clear();
  contacts.clear();

  int currsize = kbucket.Size();
  Contact contact3(cry_obj.Hash("newid", "", crypto::STRING_STRING,false),
    ip, 8880, ip, 8880);
  ASSERT_EQ(SUCCEED, kbucket.AddContact(contact3));
  ASSERT_EQ(currsize, kbucket.Size());
  Contact contact4;
  kbucket.GetContacts(1, ex_contacts, &contacts);
  ASSERT_TRUE(kbucket.GetContact(cry_obj.Hash("newid",
      "", crypto::STRING_STRING,false), &contact4));
  ASSERT_TRUE(contact4 == contacts[0]) << "the contact readded was not placed at the begging of the list";


}

