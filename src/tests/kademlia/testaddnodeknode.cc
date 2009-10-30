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
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include "maidsafe/maidsafe-dht.h"
#include "tests/kademlia/fake_callbacks.h"
#include "maidsafe/transport-api.h"
#include "maidsafe/channelmanager-api.h"
#include "maidsafe/config.h"
#include "protobuf/rpcmessage.pb.h"

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
  TestKnodes() : nodes_(), ch_managers_(), transports_(), msg_handlers_(),
      datastore_dir_(2), test_dir_("") {}
  virtual ~TestKnodes() {
    transport::CleanUp();
  }
 protected:
  void SetUp() {
    test_dir_ = std::string("TestKnodes") + boost::lexical_cast<std::string>(
        base::random_32bit_uinteger());
    try {
      if (boost::filesystem::exists(test_dir_))
        boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      LOG(ERROR) << "filesystem exception: " << e.what() << std::endl;
    }
    for (int i = 0; i < 2; i++) {
      msg_handlers_.push_back(new MessageHandler);
      transports_.push_back(new transport::Transport);
      ch_managers_.push_back(new rpcprotocol::ChannelManager(transports_[i]));
      ASSERT_TRUE(ch_managers_[i]->RegisterNotifiersToTransport());
      ASSERT_TRUE(transports_[i]->RegisterOnServerDown(
        boost::bind(&MessageHandler::OnDeadRendezvousServer, msg_handlers_[i],
        _1, _2, _3)));
      ASSERT_EQ(0, transports_[i]->Start(0));
      ASSERT_EQ(0, ch_managers_[i]->Start());
      datastore_dir_[i] = test_dir_ + "/Datastore" +
          boost::lexical_cast<std::string>(transports_[i]->listening_port());
      boost::filesystem::create_directories(
          boost::filesystem::path(datastore_dir_[i]));
      nodes_.push_back(KNode(ch_managers_[i], transports_[i], VAULT, "",
        "", false, false));
    }
  }
  void TearDown() {
    for (int i = 0; i < 2; i++) {
      transports_[i]->Stop();
      ch_managers_[i]->Stop();
      delete transports_[i];
      delete ch_managers_[i];
      delete msg_handlers_[i];
    }
    try {
      if (boost::filesystem::exists(test_dir_))
        boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      LOG(ERROR) << "filesystem exception: " << e.what() << std::endl;
    }
    nodes_.clear();
    ch_managers_.clear();
    datastore_dir_.clear();
  }
  std::vector<KNode> nodes_;
  std::vector<rpcprotocol::ChannelManager*> ch_managers_;
  std::vector<transport::Transport*> transports_;
  std::vector<MessageHandler*> msg_handlers_;
  std::vector<std::string> datastore_dir_;
  std::string test_dir_;
};

TEST_F(TestKnodes, BEH_KAD_TestLastSeenNotReply) {
  std::string kconfig_file = datastore_dir_[0] + "/.kadconfig";
  std::string id("7");
  for (int i = 1; i < kKeySizeBytes*2; i++)
    id += "1";
  GeneralKadCallback cb;
  boost::asio::ip::address local_ip;
  ASSERT_TRUE(base::get_local_address(&local_ip));
  nodes_[0].Join(id, kconfig_file,
    local_ip.to_string(), transports_[0]->listening_port(),
    boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
  wait_result(&cb);
  ASSERT_EQ(kRpcResultSuccess, cb.result());
  cb.Reset();
  ASSERT_TRUE(nodes_[0].is_joined());

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
    std::string id = base::DecodeFromHex(bucket2ids[i]);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0].AddContact(contact, 0.0, false));
    if (i == 1) last_seen = contact;
    port++;
  }
  for (int i = 0; i < 3; i++) {
    std::string id = base::DecodeFromHex(bucket1ids[i]);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0].AddContact(contact, 0.0, false));
    port++;
  }
  for (int i = K-2; i < K+1; i++) {
    std::string id = base::DecodeFromHex(bucket2ids[i]);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0].AddContact(contact, 0.0, false));
    port++;
  }
  port++;
  id = base::DecodeFromHex(bucket2ids[0]);
  Contact contact(id, ip, port, ip, port);
  ASSERT_EQ(2, nodes_[0].AddContact(contact, 0.0, false));

  Contact rec_contact;
  ASSERT_FALSE(nodes_[0].GetContact(contact.node_id(), &rec_contact));

  // waiting for the ping to the last seen contact to timeout
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(nodes_[0].GetContact(contact.node_id(), &rec_contact));
  ASSERT_TRUE(contact == rec_contact);
  ASSERT_FALSE(nodes_[0].GetContact(last_seen.node_id(), &rec_contact));

  nodes_[0].Leave();
  base::KadConfig kad_config;
  std::ifstream inputfile(kconfig_file.c_str(),
    std::ios::in | std::ios::binary);
  ASSERT_TRUE(kad_config.ParseFromIstream(&inputfile));
  inputfile.close();
  ASSERT_EQ(K+3, kad_config.contact_size());

  ASSERT_FALSE(nodes_[0].is_joined());
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
  boost::asio::ip::address local_ip;
  ASSERT_TRUE(base::get_local_address(&local_ip));
  nodes_[0].Join(id, kconfig_file,
    local_ip.to_string(), transports_[0]->listening_port(),
    boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
  wait_result(&cb);
  ASSERT_EQ(kRpcResultSuccess, cb.result());
  cb.Reset();
  ASSERT_TRUE(nodes_[0].is_joined());
  // Joining node 2 bootstrapped to node 1 so that node 1 adds him to its
  // routing table
  base::KadConfig kad_config1;
  base::KadConfig::Contact *kad_contact = kad_config1.add_contact();
  std::string hex_id = base::EncodeToHex(nodes_[0].node_id());
  kad_contact->set_node_id(hex_id);
  kad_contact->set_ip(nodes_[0].host_ip());
  kad_contact->set_port(nodes_[0].host_port());
  kad_contact->set_local_ip(nodes_[0].local_host_ip());
  kad_contact->set_local_port(nodes_[0].local_host_port());
  std::fstream output1(kconfig_file1.c_str(),
    std::ios::out | std::ios::trunc | std::ios::binary);
  EXPECT_TRUE(kad_config1.SerializeToOstream(&output1));
  output1.close();

  nodes_[1].Join(id2, kconfig_file1,
    boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
  wait_result(&cb);
  ASSERT_EQ(kRpcResultSuccess, cb.result());
  cb.Reset();
  ASSERT_TRUE(nodes_[1].is_joined());
  Contact last_seen;
  ASSERT_TRUE(nodes_[0].GetContact(nodes_[1].node_id(), &last_seen));

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
    std::string id = base::DecodeFromHex(bucket2ids[i]);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0].AddContact(contact, 0.0, false));
    port++;
  }
  for (int i = 0; i < 3; i++) {
    std::string id = base::DecodeFromHex(bucket1ids[i]);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0].AddContact(contact, 0.0, false));
    port++;
  }
  for (int i = K-3; i < K; i++) {
    std::string id = base::DecodeFromHex(bucket2ids[i]);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0].AddContact(contact, 0.0, false));
    port++;
  }
  port++;
  id = base::DecodeFromHex(bucket2ids[0]);
  Contact contact(id, ip, port, ip, port);
  ASSERT_EQ(2, nodes_[0].AddContact(contact, 0.0, false));

  Contact rec_contact;
  ASSERT_FALSE(nodes_[0].GetContact(contact.node_id(), &rec_contact));

  // wait for last seen contact to reply to ping
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_FALSE(nodes_[0].GetContact(contact.node_id(), &rec_contact));
  ASSERT_TRUE(nodes_[0].GetContact(last_seen.node_id(), &rec_contact));

  ASSERT_EQ(2, nodes_[0].AddContact(contact, 0.0, false));

  // wait for ping to last seen contact to timeout
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(nodes_[0].GetContact(contact.node_id(), &rec_contact));
  ASSERT_TRUE(nodes_[0].GetContact(last_seen.node_id(), &rec_contact));

  // Getting info from base routing table to check rtt
  base::PDRoutingTableTuple tuple;
  ASSERT_EQ(0, (*base::PDRoutingTable::getInstance())[base::itos(
      nodes_[0].host_port())]->GetTupleInfo(nodes_[1].node_id(), &tuple));
  ASSERT_EQ(nodes_[1].node_id(), tuple.kademlia_id_);
  ASSERT_EQ(nodes_[1].host_ip(), tuple.host_ip_);
  ASSERT_EQ(nodes_[1].host_port(), tuple.host_port_);
  ASSERT_EQ(nodes_[1].rv_ip(), tuple.rendezvous_ip_);
  ASSERT_EQ(nodes_[1].rv_port(), tuple.rendezvous_port_);
  EXPECT_LT(0.0, tuple.rtt_);

  nodes_[1].Leave();
  nodes_[0].Leave();
  base::KadConfig kad_config;
  std::ifstream inputfile(kconfig_file.c_str(),
    std::ios::in | std::ios::binary);
  ASSERT_TRUE(kad_config.ParseFromIstream(&inputfile));
  inputfile.close();
  ASSERT_EQ(K+3, kad_config.contact_size());

  ASSERT_FALSE(nodes_[0].is_joined());
  ASSERT_FALSE(nodes_[1].is_joined());
}
}  // namespace kad
