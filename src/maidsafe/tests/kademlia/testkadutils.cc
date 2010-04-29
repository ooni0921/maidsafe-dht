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

#include <boost/thread/thread.hpp>
#include <gtest/gtest.h>
#include "maidsafe/kademlia/kadutils.h"
#include "maidsafe/kademlia/knodeimpl.h"
#include "maidsafe/kademlia/kadid.h"
#include "maidsafe/maidsafe-dht.h"

bool InRange(const std::string &key, const kad::KadId &min_range,
    const kad::KadId &max_range) {
  kad::KadId key_id(key, false);
  return static_cast<bool>((min_range <= key_id && key_id <= max_range));
}

TEST(KadRandomId, BEH_KAD_InRange) {
  kad::KadId min_range(510), max_range(kad::MAX_ID);
  std::string id = kad::random_kademlia_id(min_range, max_range);
  ASSERT_TRUE(InRange(id, min_range, max_range));
}

TEST(KadRandomId, BEH_KAD_KadEnvInRange) {
  kad::KadId min_range, max_range(kad::MAX_ID);
  for (int i = 1; i < 512; i++) {
    kad::KadId x(1);
    std::string id = kad::random_kademlia_id(min_range, x);
    kad::KadId id_val(id, false);
    ASSERT_TRUE(id_val >= min_range);
    ASSERT_TRUE(max_range >= id_val);
  }
}

TEST(ClientNodeId, BEH_KAD_ClientCreateId) {
  std::string id = kad::client_node_id();
  ASSERT_EQ(kad::kKeySizeBytes, static_cast<int>(id.size()));
  for (int i = 0; i < kad::kKeySizeBytes; i++)
    ASSERT_EQ(id[i], '\0');
  std::string enc_id = base::EncodeToHex(id);
  for (int i = 0; i < kad::kKeySizeBytes*2; i++)
    ASSERT_EQ(enc_id[i], '0');
}

TEST(VaultNodeId, FUNC_KAD_VaultCreateId) {
  std::string id;
  kad::KadId min_range;
  kad::KadId max_range(kad::MAX_ID);
  for (int i = 0; i < 50; i++) {
    id = kad::vault_random_id();
    ASSERT_TRUE(InRange(id, min_range, max_range));
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
}

TEST(KadUtilsTest, BEH_KAD_InsertKadContact) {
  std::vector<kad::Contact> contacts;
  for (char c = '9'; c >= '0'; --c)
    contacts.push_back(kad::Contact(std::string(64, c), "IP", 10000));
  ASSERT_EQ(size_t(10), contacts.size());
  // Copy the vector.
  std::vector<kad::Contact> contacts_before(contacts);
  std::string key(64, 'b');
  kad::KadId kad_key(key, false);
  kad::Contact new_contact(std::string(64, 'a'), "IP", 10000);
  kad::InsertKadContact(kad_key, new_contact, &contacts);
  ASSERT_EQ(size_t(11), contacts.size());
  // Check contacts have been re-ordered correctly.
  ASSERT_TRUE(contacts.at(0).node_id() == new_contact.node_id());
  ASSERT_TRUE(contacts.at(1).node_id() == contacts_before.at(7).node_id());
  ASSERT_TRUE(contacts.at(2).node_id() == contacts_before.at(6).node_id());
  ASSERT_TRUE(contacts.at(3).node_id() == contacts_before.at(9).node_id());
  ASSERT_TRUE(contacts.at(4).node_id() == contacts_before.at(8).node_id());
  ASSERT_TRUE(contacts.at(5).node_id() == contacts_before.at(3).node_id());
  ASSERT_TRUE(contacts.at(6).node_id() == contacts_before.at(2).node_id());
  ASSERT_TRUE(contacts.at(7).node_id() == contacts_before.at(5).node_id());
  ASSERT_TRUE(contacts.at(8).node_id() == contacts_before.at(4).node_id());
  ASSERT_TRUE(contacts.at(9).node_id() == contacts_before.at(1).node_id());
  ASSERT_TRUE(contacts.at(10).node_id() == contacts_before.at(0).node_id());
}

