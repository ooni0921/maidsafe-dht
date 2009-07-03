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
#include <boost/filesystem/fstream.hpp>
#include "maidsafe/maidsafe-dht.h"
#include "kademlia/knodeimpl.h"
#include "tests/kademlia/fake_callbacks.h"
#include "transport/transportapi.h"

namespace kad {

class MessageHandler {
 public:
  MessageHandler(): msgs(), ids(), dead_server_(true), server_ip_(),
    server_port_(0), node_(NULL), msgs_sent_(0) {}
  void OnMessage(const rpcprotocol::RpcMessage &msg,
      const boost::uint32_t conn_id) {
    std::string message;
    msg.SerializeToString(&message);
    msgs.push_back(message);
    ids.push_back(conn_id);
    printf("message %i arrived\n", msgs.size());
    if (node_ != NULL)
      node_->CloseConnection(conn_id);
  }
  void OnDeadRendezvousServer(const bool &dead_server, const std::string &ip,
    const boost::uint16_t &port) {
    dead_server_ = dead_server;
    server_ip_ = ip;
    server_port_ = port;
  }
  void set_node(transport::Transport *node) {
    node_ = node;
  }
  void OnSend(const boost::uint32_t &, const bool &success) {
    if (success)
      msgs_sent_++;
  }
  std::list<std::string> msgs;
  std::list<boost::uint32_t> ids;
  bool dead_server_;
  std::string server_ip_;
  boost::uint16_t server_port_;
  transport::Transport *node_;
  int msgs_sent_;
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
};

class TestKnodes : public testing::Test {
 public:
  TestKnodes() : nodes_(2), ch_managers_(2), msg_handlers_(2),
      datastore_dir_(2), test_dir_("") {}
  virtual ~TestKnodes() {
    UDT::cleanup();
  }
 protected:
  void SetUp() {
    test_dir_ = std::string("TestKnodes") + boost::lexical_cast<std::string>(
                 base::random_32bit_uinteger());
    try {
      if (boost::filesystem::exists(test_dir_))
        boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    for (int i = 0; i < 2; i++) {
      msg_handlers_[i].reset(new MessageHandler());
      ch_managers_[i].reset(new rpcprotocol::ChannelManager());
      ch_managers_[i]->StartTransport(0,
          boost::bind(&MessageHandler::OnDeadRendezvousServer,
          msg_handlers_[i].get(), _1, _2, _3));
      datastore_dir_[i] = test_dir_ + "/Datastore" +
                         base::itos(ch_managers_[i]->external_port());
      boost::filesystem::create_directories(
          boost::filesystem::path(datastore_dir_[i]));
      nodes_[i].reset(new KNodeImpl(datastore_dir_[i], ch_managers_[i], VAULT));
    }
  }
  void TearDown() {
    for (int i = 0; i < 2; i++) {
      ch_managers_[i]->StopTransport();
      nodes_[i].reset();
      ch_managers_[i].reset();
    }
    try {
      if (boost::filesystem::exists(test_dir_))
        boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    nodes_.clear();
    ch_managers_.clear();
    datastore_dir_.clear();
  }
  std::vector< boost::shared_ptr<KNodeImpl> > nodes_;
  std::vector< boost::shared_ptr<rpcprotocol::ChannelManager> > ch_managers_;
  std::vector< boost::shared_ptr<MessageHandler> > msg_handlers_;
  std::vector<std::string> datastore_dir_;
  std::string test_dir_;
};

TEST_F(TestKnodes, BEH_KAD_TestLastSeenNotReply) {
  std::string kconfig_file = datastore_dir_[0] + "/.kadconfig";
  std::string id("7");
  for (int i = 1; i < kKeySizeBytes*2; i++)
    id += "1";
  GeneralKadCallback cb;
  nodes_[0]->Join(id, kconfig_file,
    boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1), false);
  wait_result(&cb);
  ASSERT_EQ(kRpcResultSuccess, cb.result());
  cb.Reset();
  ASSERT_TRUE(nodes_[0]->is_joined());

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
    ASSERT_EQ(0, nodes_[0]->AddContact(contact, false));
    if (i == 1) last_seen = contact;
    port++;
  }
  for (int i = 0; i < 3; i++) {
    std::string id;
    base::decode_from_hex(bucket1ids[i], &id);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0]->AddContact(contact, false));
    port++;
  }
  for (int i = K-2; i < K+1; i++) {
    std::string id;
    base::decode_from_hex(bucket2ids[i], &id);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0]->AddContact(contact, false));
    port++;
  }
  id = "";
  port++;
  base::decode_from_hex(bucket2ids[0], &id);
  Contact contact(id, ip, port, ip, port);
  ASSERT_EQ(2, nodes_[0]->AddContact(contact, false));

  Contact rec_contact;
  ASSERT_FALSE(nodes_[0]->GetContact(contact.node_id(), &rec_contact));

  // waiting for the ping to the last seen contact to timeout
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(nodes_[0]->GetContact(contact.node_id(), &rec_contact));
  ASSERT_TRUE(contact == rec_contact);
  ASSERT_FALSE(nodes_[0]->GetContact(last_seen.node_id(), &rec_contact));

  nodes_[0]->Leave();
  base::KadConfig kad_config;
  std::ifstream inputfile(kconfig_file.c_str(),
    std::ios::in | std::ios::binary);
  ASSERT_TRUE(kad_config.ParseFromIstream(&inputfile));
  inputfile.close();
  ASSERT_EQ(K+3, kad_config.contact_size());

  ASSERT_FALSE(nodes_[0]->is_joined());
}

TEST_F(TestKnodes, FUNC_KAD_TestLastSeenReplies) {
  std::string kconfig_file = datastore_dir_[0] + "/.kadconfig";
  std::string kconfig_file1 = datastore_dir_[1] + "/.kadconfig";
  std::string id("7"), id2("9");
  for (int i = 1; i < kKeySizeBytes*2; i++) {
    id += "1";
    id2 += "2";
  }
  GeneralKadCallback cb;
  nodes_[0]->Join(id, kconfig_file,
    boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1), false);
  wait_result(&cb);
  ASSERT_EQ(kRpcResultSuccess, cb.result());
  cb.Reset();
  ASSERT_TRUE(nodes_[0]->is_joined());
  // Joining node 2 bootstrapped to node 1 so that node 1 adds him to its
  // routing table
  base::KadConfig kad_config1;
  base::KadConfig::Contact *kad_contact = kad_config1.add_contact();
  std::string hex_id;
  base::encode_to_hex(nodes_[0]->node_id(), &hex_id);
  kad_contact->set_node_id(hex_id);
  kad_contact->set_ip(nodes_[0]->host_ip());
  kad_contact->set_port(nodes_[0]->host_port());
  kad_contact->set_local_ip(nodes_[0]->local_host_ip());
  kad_contact->set_local_port(nodes_[0]->local_host_port());
  std::fstream output1(kconfig_file1.c_str(),
    std::ios::out | std::ios::trunc | std::ios::binary);
  EXPECT_TRUE(kad_config1.SerializeToOstream(&output1));
  output1.close();

  nodes_[1]->Join(id2, kconfig_file1,
    boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1), false);
  wait_result(&cb);
  ASSERT_EQ(kRpcResultSuccess, cb.result());
  cb.Reset();
  ASSERT_TRUE(nodes_[1]->is_joined());
  Contact last_seen;
  ASSERT_TRUE(nodes_[0]->GetContact(nodes_[1]->node_id(), &last_seen));

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
    ASSERT_EQ(0, nodes_[0]->AddContact(contact, false));
    port++;
  }
  for (int i = 0; i < 3; i++) {
    std::string id;
    base::decode_from_hex(bucket1ids[i], &id);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0]->AddContact(contact, false));
    port++;
  }
  for (int i = K-3; i < K; i++) {
    std::string id;
    base::decode_from_hex(bucket2ids[i], &id);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0]->AddContact(contact, false));
    port++;
  }
  id = "";
  port++;
  base::decode_from_hex(bucket2ids[0], &id);
  Contact contact(id, ip, port, ip, port);
  ASSERT_EQ(2, nodes_[0]->AddContact(contact, false));

  Contact rec_contact;
  ASSERT_FALSE(nodes_[0]->GetContact(contact.node_id(), &rec_contact));

  // wait for last seen contact to reply to ping
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_FALSE(nodes_[0]->GetContact(contact.node_id(), &rec_contact));
  ASSERT_TRUE(nodes_[0]->GetContact(last_seen.node_id(), &rec_contact));

  ASSERT_EQ(2, nodes_[0]->AddContact(contact, false));

  // wait for ping to last seen contact to timeout
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(nodes_[0]->GetContact(contact.node_id(), &rec_contact));
  ASSERT_TRUE(nodes_[0]->GetContact(last_seen.node_id(), &rec_contact));

  nodes_[1]->Leave();
  nodes_[0]->Leave();
  base::KadConfig kad_config;
  std::ifstream inputfile(kconfig_file.c_str(),
    std::ios::in | std::ios::binary);
  ASSERT_TRUE(kad_config.ParseFromIstream(&inputfile));
  inputfile.close();
  ASSERT_EQ(K+3, kad_config.contact_size());

  ASSERT_FALSE(nodes_[0]->is_joined());
  ASSERT_FALSE(nodes_[1]->is_joined());
}

}  // namespace kad
