/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in teh root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Dec 17, 2008
 *      Author: Jose
 */

#include <gtest/gtest.h>
#include "kademlia/contact.h"
#include "base/utils.h"
#include "base/crypto.h"

class TestContact : public testing::Test {
public:
TestContact() : cry_obj() {}
  protected:
    void SetUp() {
      cry_obj.set_symm_algorithm("AES_256");
      cry_obj.set_hash_algorithm("SHA512");
    }
    crypto::Crypto cry_obj;
};

TEST_F(TestContact, BEH_KAD_GetIp_Port_NodeId) {
  std::string ip("192.168.1.55");
  std::string local_ip = ip;
  unsigned short port = 8888;
  unsigned short local_port = port;
  std::string node_id = cry_obj.Hash("1238425", "", crypto::STRING_STRING,
      false);
  kad::Contact contact(node_id, ip, port, local_ip, local_port);
  ASSERT_EQ(base::inet_atob(ip), contact.host_ip());
  ASSERT_EQ(ip, base::inet_btoa(contact.host_ip()));
  ASSERT_EQ(node_id, contact.node_id());
  ASSERT_EQ(port, contact.host_port());
  ASSERT_EQ(base::inet_atob(local_ip), contact.local_ip());
  ASSERT_EQ(local_ip, base::inet_btoa(contact.local_ip()));
  ASSERT_EQ(local_port, contact.local_port());
}

TEST_F(TestContact, BEH_KAD_OverloadedOperators) {
  std::string ip = "192.168.1.55";
  std::string local_ip = ip;
  unsigned short port = 8888;
  unsigned short local_port = port;
  std::string node_id = cry_obj.Hash("1238425", "", crypto::STRING_STRING,
      false);
  kad::Contact contact1(node_id, ip, port, local_ip, local_port);
  kad::Contact contact2(node_id, ip, port, local_ip, local_port);
  ASSERT_TRUE(contact1 == contact2);
  kad::Contact contact3(node_id, ip, 8889);
  ASSERT_TRUE(contact1 == contact3);
  kad::Contact contact4(node_id, "192.168.2.54", port, "192.168.2.54", port);
  ASSERT_TRUE(contact1 == contact4);
  kad::Contact contact5(cry_obj.Hash("5612348", "", crypto::STRING_STRING,
      false), ip, port, ip, port);
  ASSERT_TRUE(contact1 == contact5);
  kad::Contact contact6(cry_obj.Hash("5612348", "", crypto::STRING_STRING,
      false), ip, 8889, ip, 8889);
  ASSERT_TRUE(contact1 != contact6);
  kad::Contact contact7(node_id, "192.168.2.54", 8889, "192.168.2.54", 8889);
  ASSERT_TRUE(contact1 == contact7);
  contact6 = contact1;
  ASSERT_TRUE(contact1 == contact6);
  kad::Contact contact8(contact1);
  ASSERT_TRUE(contact1 == contact8);
}

TEST_F(TestContact, BEH_KAD_IncreaseGetFailedRPC) {
  std::string ip = "192.168.1.55";
  std::string local_ip = ip;
  unsigned short port = 8888;
  unsigned short local_port = port;
  std::string node_id = cry_obj.Hash("1238425", "", crypto::STRING_STRING,
      false);
  kad::Contact contact(node_id, ip, port, local_ip, local_port);
  ASSERT_EQ(0, static_cast<int>(contact.failed_rpc()));
  contact.IncreaseFailed_RPC();
  ASSERT_EQ(1, static_cast<int>(contact.failed_rpc()));
  contact.IncreaseFailed_RPC();
  ASSERT_EQ(2, static_cast<int>(contact.failed_rpc()));
  contact.IncreaseFailed_RPC();
  ASSERT_EQ(3, static_cast<int>(contact.failed_rpc()));
}

TEST_F(TestContact, BEH_KAD_ContactPointer) {
  std::string ip = "192.168.1.55";
  std::string local_ip = ip;
  unsigned short port = 8888;
  unsigned short local_port = port;
  std::string node_id = cry_obj.Hash("1238425", "", crypto::STRING_STRING,
      false);
  kad::Contact *contact = new kad::Contact(node_id, ip, port, local_ip,
    local_port);
  ASSERT_EQ(base::inet_atob(ip), contact->host_ip());
  ASSERT_EQ(ip, base::inet_btoa(contact->host_ip()));
  ASSERT_EQ(node_id, contact->node_id());
  ASSERT_EQ(port, contact->host_port());
  ASSERT_EQ(base::inet_atob(local_ip), contact->local_ip());
  ASSERT_EQ(local_ip, base::inet_btoa(contact->local_ip()));
  ASSERT_EQ(local_port, contact->local_port());
  ASSERT_EQ(0, contact->failed_rpc());
  contact->IncreaseFailed_RPC();
  ASSERT_EQ(1, contact->failed_rpc());
}

TEST_F(TestContact, BEH_KAD_SerialiseToString) {
  std::string ip = "192.168.1.55";
  std::string local_ip = ip;
  unsigned short port = 8888;
  unsigned short local_port = port;
  std::string node_id = cry_obj.Hash("1238425", "", crypto::STRING_STRING,
      false);
  kad::Contact contact(node_id, ip, port, local_ip, local_port);
  std::string ser_contact;
  ASSERT_TRUE(contact.SerialiseToString(&ser_contact));
  kad::Contact contact1;
  std::string ser_contact1;
  ASSERT_FALSE(contact1.SerialiseToString(&ser_contact1));
  contact1.ParseFromString(ser_contact);
  ASSERT_EQ(ip, base::inet_btoa(contact1.host_ip()));
  ASSERT_EQ(port, contact1.host_port());
  ASSERT_EQ(node_id, contact1.node_id());
  ASSERT_EQ(local_ip, base::inet_btoa(contact1.local_ip()));
  ASSERT_EQ(local_port, contact1.host_port());
}
