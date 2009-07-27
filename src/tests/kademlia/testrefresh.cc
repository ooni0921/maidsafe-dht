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
#include "maidsafe/maidsafe-dht.h"
#include "tests/kademlia/fake_callbacks.h"
#include "transport/transportapi.h"

namespace kad {

class TestRefresh : public testing::Test {
 public:
  TestRefresh() : ch_managers(), nodes(), datadirs(), test_dir("TestKnodes"),
      testK(4), testRefresh(10), testNetworkSize(10) {
    test_dir += boost::lexical_cast<std::string>(base::random_32bit_uinteger());
  }
  ~TestRefresh() {
    UDT::cleanup();
  }
 protected:
  void SetUp() {
    try {
      if (boost::filesystem::exists(test_dir))
        boost::filesystem::remove_all(test_dir);
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    // Creating the nodes
    for (int i = 0; i < testNetworkSize; i++) {
      ch_managers.push_back(boost::shared_ptr<rpcprotocol::ChannelManager>(
          new rpcprotocol::ChannelManager()));
      std::string datadir = test_dir + std::string("/datastore") +
          base::itos(i);
      boost::filesystem::create_directories(datadir);
      nodes.push_back(boost::shared_ptr<KNode>(new KNode(ch_managers[i], VAULT,
          testK, kAlpha, kBeta, testRefresh)));
      EXPECT_EQ(0, ch_managers[i]->StartTransport(0, boost::bind(
          &kad::KNode::HandleDeadRendezvousServer, nodes[i].get(), _1)));
      datadirs.push_back(datadir);
    }
    GeneralKadCallback cb;
    for (int i = 0; i < testNetworkSize; i++) {
      printf("starting node %d\n", i);
      std::string kconfig_file1 = datadirs[i] + "/.kadconfig";
      if (i != 0) {
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
      }

      nodes[i]->Join("", kconfig_file1,
        boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1), false);
      wait_result(&cb);
      ASSERT_EQ(kRpcResultSuccess, cb.result());
      cb.Reset();
      ASSERT_TRUE(nodes[i]->is_joined());
    }
  }

  void TearDown() {
    // Stopping nodes
    for (int i = 0; i < testNetworkSize; i++) {
      nodes[i]->StopRvPing();
    }
    for (int i = testNetworkSize-1; i >= 0; i--) {
      printf("stopping node %d\n", i);
      nodes[i]->Leave();
      EXPECT_FALSE(nodes[i]->is_joined());
      ch_managers[i]->StopTransport();
    }
    try {
      boost::filesystem::remove_all(test_dir);
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
  }

  std::vector< boost::shared_ptr<rpcprotocol::ChannelManager> > ch_managers;
  std::vector< boost::shared_ptr<KNode> > nodes;
  std::vector<std::string> datadirs;
  std::string test_dir;
  boost::uint16_t testK;
  boost::uint32_t testRefresh;
  int testNetworkSize;
};

TEST_F(TestRefresh, FUNC_KAD_RefreshValue) {
  // Storing a Value
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string key = co.Hash("key", "", crypto::STRING_STRING, false);
  std::string value = base::RandomString(1024*5);
  StoreValueCallback store_cb;
  nodes[4]->StoreValue(key, value, 24*3600, boost::bind(
      &StoreValueCallback::CallbackFunc, &store_cb, _1));
  wait_result(&store_cb);
  ASSERT_EQ(kad::kRpcResultSuccess, store_cb.result());
  std::vector<int> indxs;
  std::vector<boost::uint32_t> last_refresh_times;
  std::vector<boost::uint32_t> expire_times;
  for (int i = 0; i < testNetworkSize; i++) {
    std::vector<std::string> values;
    if (nodes[i]->FindValueLocal(key, values)) {
      ASSERT_EQ(value, values[0]);
      indxs.push_back(i);
      boost::uint32_t last_refresh = nodes[i]->KeyLastRefreshTime(key, value);
      ASSERT_NE(0, last_refresh);
      last_refresh_times.push_back(last_refresh);
      boost::uint32_t expire_time = nodes[i]->KeyExpireTime(key, value);
      ASSERT_NE(0, expire_time);
      expire_times.push_back(expire_time);
    }
  }
  ASSERT_EQ(testK, indxs.size());
  boost::this_thread::sleep(boost::posix_time::seconds(testRefresh+8));
  for (unsigned int i = 0; i < indxs.size(); i++) {
    std::vector<std::string> values;
    EXPECT_TRUE(nodes[indxs[i]]->FindValueLocal(key, values));
    EXPECT_EQ(value, values[0]);
    EXPECT_EQ(expire_times[i], nodes[indxs[i]]->KeyExpireTime(key, value));
    EXPECT_LT(last_refresh_times[i],
        nodes[indxs[i]]->KeyLastRefreshTime(key, value)) << "FAILED  WITH NODE"
        << indxs[i];
  }
}

TEST_F(TestRefresh, FUNC_KAD_NewNodeinKClosest) {
  // Storing a Value
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string key = co.Hash("key", "", crypto::STRING_STRING, false);
  std::string value = base::RandomString(1024*5);
  StoreValueCallback store_cb;
  nodes[4]->StoreValue(key, value, 24*3600, boost::bind(
      &StoreValueCallback::CallbackFunc, &store_cb, _1));
  wait_result(&store_cb);
  ASSERT_EQ(kad::kRpcResultSuccess, store_cb.result());
  std::vector<int> indxs;
  std::vector<boost::uint32_t> last_refresh_times;
  std::vector<boost::uint32_t> expire_times;
  for (int i = 0; i < testNetworkSize; i++) {
    std::vector<std::string> values;
    if (nodes[i]->FindValueLocal(key, values)) {
      ASSERT_EQ(value, values[0]);
      indxs.push_back(i);
      boost::uint32_t last_refresh = nodes[i]->KeyLastRefreshTime(key, value);
      ASSERT_NE(0, last_refresh);
      last_refresh_times.push_back(last_refresh);
      boost::uint32_t expire_time = nodes[i]->KeyExpireTime(key, value);
      ASSERT_NE(0, expire_time);
      expire_times.push_back(expire_time);
    }
  }
  ASSERT_EQ(testK, indxs.size());
  boost::shared_ptr<rpcprotocol::ChannelManager> ch_manager(
      new rpcprotocol::ChannelManager());
  std::string local_dir = test_dir + std::string("/datastorenewnode");
  boost::filesystem::create_directories(local_dir);
  boost::shared_ptr<KNode> node(new KNode(ch_manager, VAULT, testK, kAlpha,
      kBeta, testRefresh));
  EXPECT_EQ(0, ch_manager->StartTransport(0, boost::bind(
      &kad::KNode::HandleDeadRendezvousServer, node.get(), _1)));
  std::string kconfig_file1 = local_dir + "/.kadconfig";
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
  GeneralKadCallback cb;
  // joining node with id == key of value stored
  node->Join(key, kconfig_file1,
    boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1), false);
  wait_result(&cb);
  ASSERT_EQ(kRpcResultSuccess, cb.result());
  cb.Reset();
  ASSERT_TRUE(node->is_joined());

  boost::this_thread::sleep(boost::posix_time::seconds(testRefresh+8));
  std::vector<std::string> values;
  EXPECT_TRUE(node->FindValueLocal(key, values));
  EXPECT_EQ(value, values[0]);
  EXPECT_NE(0, node->KeyExpireTime(key, value));
  EXPECT_NE(0, node->KeyLastRefreshTime(key, value));

  node->Leave();
  EXPECT_FALSE(node->is_joined());
  ch_manager->StopTransport();
}
}
