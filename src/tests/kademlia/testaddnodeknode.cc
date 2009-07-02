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
#include <fstream>  // NOLINT (Fraser) - needed for kadconfig
#include "maidsafe/maidsafe-dht.h"
#include "kademlia/knodeimpl.h"
#include "tests/kademlia/fake_callbacks.h"
#include "transport/transportapi.h"

namespace kad {

class TestKnodes : public testing::Test {
 public:
  TestKnodes() : nodes(2), ch_managers(2), datastore_dir(2) {}
  virtual ~TestKnodes() {
    UDT::cleanup();
  }
 protected:
  void SetUp() {
    try {
      if (boost::filesystem::exists("KNodeTest"))
        boost::filesystem::remove_all("KNodeTest");
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    std::string datastore = "KNodeTest";
    boost::uint16_t port = 9100;
    for (int i = 0; i < 2; i++) {
      datastore_dir[i] = datastore + "/Datastore" + base::itos(port);
      boost::filesystem::create_directories(
        boost::filesystem::path(datastore_dir[i]));
      ch_managers[i].reset(new rpcprotocol::ChannelManager());
      nodes[i].reset(new KNodeImpl(datastore_dir[i], ch_managers[i], VAULT));
      ch_managers[i]->StartTransport(port,
        boost::bind(&KNodeImpl::HandleDeadRendezvousServer, nodes[i].get(),
        _1));
      port++;
    }
  }
  void TearDown() {
    for (int i = 0; i < 2; i++) {
      ch_managers[i]->StopTransport();
      nodes[i].reset();
      ch_managers[i].reset();
    }
    try {
      if (boost::filesystem::exists("KNodeTest"))
        boost::filesystem::remove_all("KNodeTest");
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    nodes.clear();
    ch_managers.clear();
    datastore_dir.clear();
  }
  std::vector< boost::shared_ptr<KNodeImpl> > nodes;
  std::vector< boost::shared_ptr<rpcprotocol::ChannelManager> > ch_managers;
  std::vector<std::string> datastore_dir;
};

TEST_F(TestKnodes, BEH_KAD_TestLastSeenNotReply) {
  std::string kconfig_file = datastore_dir[0] + "/.kadconfig";
  std::string id("7");
  for (int i = 1; i < kKeySizeBytes*2; i++)
    id += "1";
  GeneralKadCallback cb;
  nodes[0]->Join(id, kconfig_file,
    boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1), false);
  wait_result(&cb);
  ASSERT_EQ(kRpcResultSuccess, cb.result());
  cb.Reset();
  ASSERT_TRUE(nodes[0]->is_joined());
  // Adding Contacts until kbucket splits and filling kbuckets
  std::vector<std::string> bucket2ids(K+1), bucket1ids(3);
  for (int i = 0; i < K+1; i++) {
    for (int j = 0; j < kKeySizeBytes*2; j++)
      bucket2ids[i] += "f";
    std::string rep;
    int k;
    for (k = 0; k < i; k++)
      rep += "0";
    bucket2ids[i].replace(1, k, rep);
  }
  for (int i = 0; i < 3; i++) {
    for (int j = 0; j < kKeySizeBytes*2; j++)
      bucket1ids[i] += "7";
    std::string rep;
    int k;
    for (k = 0; k < i; k++)
      rep += "2";
    bucket1ids[i].replace(1, k, rep);
  }
  int port = 7000;
  Contact last_seen;
  std::string ip = "127.0.0.1";
  for (int i = 1 ; i < K-2; i++) {
    std::string id("");
    base::decode_from_hex(bucket2ids[i], &id);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes[0]->AddContact(contact, false));
    if (i == 1) last_seen = contact;
    port++;
  }
  for (int i = 0; i < 3; i++) {
    std::string id;
    base::decode_from_hex(bucket1ids[i], &id);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes[0]->AddContact(contact, false));
    port++;
  }
  for (int i = K-2; i < K+1; i++) {
    std::string id;
    base::decode_from_hex(bucket2ids[i], &id);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes[0]->AddContact(contact, false));
    port++;
  }
  id = "";
  port++;
  base::decode_from_hex(bucket2ids[0], &id);
  Contact contact(id, ip, port, ip, port);
  ASSERT_EQ(2, nodes[0]->AddContact(contact, false));

  Contact rec_contact;
  ASSERT_FALSE(nodes[0]->GetContact(contact.node_id(), &rec_contact));

  // nodes[0]->CheckToInsert(contact);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_TRUE(nodes[0]->GetContact(contact.node_id(), &rec_contact));
  ASSERT_TRUE(contact == rec_contact);
  ASSERT_FALSE(nodes[0]->GetContact(last_seen.node_id(), &rec_contact));

  nodes[0]->Leave();
  base::KadConfig kad_config;
  std::ifstream inputfile(kconfig_file.c_str(),
    std::ios::in | std::ios::binary);
  ASSERT_TRUE(kad_config.ParseFromIstream(&inputfile));
  inputfile.close();
  ASSERT_EQ(K+3, kad_config.contact_size());

  ASSERT_FALSE(nodes[0]->is_joined());
}

TEST_F(TestKnodes, FUNC_KAD_TestLastSeenReplies) {
  std::string kconfig_file = datastore_dir[0] + "/.kadconfig";
  std::string kconfig_file1 = datastore_dir[1] + "/.kadconfig";
  std::string id("7"), id2("9");
  for (int i = 1; i < kKeySizeBytes*2; i++) {
    id += "1";
    id2 += "2";
  }
  GeneralKadCallback cb;
  nodes[0]->Join(id, kconfig_file,
    boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1), false);
  wait_result(&cb);
  ASSERT_EQ(kRpcResultSuccess, cb.result());
  cb.Reset();
  ASSERT_TRUE(nodes[0]->is_joined());
  // Joining node 2 bootstrapped to node 1 so that node 1 adds him to its
  // routing table
  base::KadConfig kad_config1;
  base::KadConfig::Contact *kad_contact = kad_config1.add_contact();
  std::string hex_id;
  base::encode_to_hex(nodes[0]->node_id(), &hex_id);
  kad_contact->set_node_id(hex_id);
  kad_contact->set_ip(nodes[0]->host_ip());
  kad_contact->set_port(nodes[0]->host_port());
  kad_contact->set_local_ip(nodes[0]->local_host_ip());
  kad_contact->set_local_port(nodes[0]->local_host_port());
  std::fstream output1(kconfig_file1.c_str(),
    std::ios::out | std::ios::trunc | std::ios::binary);
  EXPECT_TRUE(kad_config1.SerializeToOstream(&output1));
  output1.close();

  nodes[1]->Join(id2, kconfig_file1,
    boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1), false);
  wait_result(&cb);
  ASSERT_EQ(kRpcResultSuccess, cb.result());
  cb.Reset();
  ASSERT_TRUE(nodes[1]->is_joined());
  Contact last_seen;
  ASSERT_TRUE(nodes[0]->GetContact(nodes[1]->node_id(), &last_seen));

  // Adding Contacts until kbucket splits and filling kbuckets
  std::vector<std::string> bucket2ids(K), bucket1ids(3);
  for (int i = 0; i < K; i++) {
    for (int j = 0; j < kKeySizeBytes*2; j++)
      bucket2ids[i] += "f";
    std::string rep;
    int k;
    for (k = 0; k < i; k++)
      rep += "0";
    bucket2ids[i].replace(1, k, rep);
  }
  for (int i = 0; i < 3; i++) {
    for (int j = 0; j < kKeySizeBytes*2; j++)
      bucket1ids[i] += "7";
    std::string rep;
    int k;
    for (k = 0; k < i; k++)
      rep += "2";
    bucket1ids[i].replace(1, k, rep);
  }
  int port = 7000;

  std::string ip = "127.0.0.1";
  for (int i = 1 ; i < K-3; i++) {
    std::string id;
    base::decode_from_hex(bucket2ids[i], &id);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes[0]->AddContact(contact, false));
    port++;
  }
  for (int i = 0; i < 3; i++) {
    std::string id;
    base::decode_from_hex(bucket1ids[i], &id);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes[0]->AddContact(contact, false));
    port++;
  }
  for (int i = K-3; i < K; i++) {
    std::string id;
    base::decode_from_hex(bucket2ids[i], &id);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes[0]->AddContact(contact, false));
    port++;
  }
  id = "";
  port++;
  base::decode_from_hex(bucket2ids[0], &id);
  Contact contact(id, ip, port, ip, port);
  ASSERT_EQ(2, nodes[0]->AddContact(contact, false));

  Contact rec_contact;
  ASSERT_FALSE(nodes[0]->GetContact(contact.node_id(), &rec_contact));

  // nodes[0]->CheckToInsert(contact);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_FALSE(nodes[0]->GetContact(contact.node_id(), &rec_contact));
  ASSERT_TRUE(nodes[0]->GetContact(last_seen.node_id(), &rec_contact));

  //nodes[0]->CheckToInsert(contact);
  ASSERT_EQ(2, nodes[0]->AddContact(contact, false));

  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_TRUE(nodes[0]->GetContact(contact.node_id(), &rec_contact));
  ASSERT_TRUE(nodes[0]->GetContact(last_seen.node_id(), &rec_contact));


  nodes[1]->Leave();
  nodes[0]->Leave();
  base::KadConfig kad_config;
  std::ifstream inputfile(kconfig_file.c_str(),
    std::ios::in | std::ios::binary);
  ASSERT_TRUE(kad_config.ParseFromIstream(&inputfile));
  inputfile.close();
  ASSERT_EQ(K+3, kad_config.contact_size());

  ASSERT_FALSE(nodes[0]->is_joined());
  ASSERT_FALSE(nodes[1]->is_joined());
}

}  // namespace kad
