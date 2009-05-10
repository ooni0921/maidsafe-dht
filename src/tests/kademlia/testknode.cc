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
 *  Created on: Oct 14, 2008
 *      Author: haiyang
 */

#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/cstdint.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include <exception>
#include <vector>
#include <list>
#include "boost/date_time/posix_time/posix_time.hpp"
#include "base/utils.h"
#include "kademlia/contact.h"
#include "kademlia/knode.h"
#include "base/crypto.h"
#include "base/rsakeypair.h"
#include "rpcprotocol/channelmanager.h"
#include "tests/kademlia/fake_callbacks.h"

namespace fs = boost::filesystem;

const int kNetworkSize = 20;
const int kTestK = 4;

inline void create_rsakeys(std::string *pub_key, std::string *priv_key) {
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(512);
  *pub_key =  kp.public_key();
  *priv_key = kp.private_key();
}

inline void create_req(const std::string &pub_key, const std::string &priv_key,
  const std::string &key, std::string *sig_pub_key, std::string *sig_req) {
  crypto::Crypto cobj;
  cobj.set_symm_algorithm("AES_256");
  cobj.set_hash_algorithm("SHA512");
  *sig_pub_key = cobj.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  *sig_req = cobj.AsymSign(cobj.Hash(pub_key + *sig_pub_key + key, "",
      crypto::STRING_STRING, true), "", priv_key, crypto::STRING_STRING);
}

class KNodeTest: public testing::Test {
 protected:
  KNodeTest() : kad_config_file("KnodeTest/.kadconfig"),
                bootstrapping_nodes(),
                recursive_mutices_(),
                timers_(),
                channel_managers_(),
                knodes_(),
                dbs_(),
                cry_obj(),
                cb() {
    cry_obj.set_symm_algorithm("AES_256");
    cry_obj.set_hash_algorithm("SHA512");
  }

  virtual ~KNodeTest() {
    bootstrapping_nodes.clear();
    UDT::cleanup();
  }

  virtual void SetUp() {
    try {
      if (fs::exists("KnodeTest"))
        fs::remove_all("KnodeTest");
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    fs::create_directories("KnodeTest");
    // setup the nodes without starting them
    for (int  i = 0; i < kNetworkSize; ++i) {
      boost::shared_ptr<boost::recursive_mutex>
          recursive_mutex_local_(new boost::recursive_mutex);
      recursive_mutices_.push_back(recursive_mutex_local_);

      boost::shared_ptr<base::CallLaterTimer>
          timer_local_(new base::CallLaterTimer(recursive_mutices_[i].get()));
      timers_.push_back(timer_local_);

      boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager_local_(
          new rpcprotocol::ChannelManager(timers_[i].get(),
                                          recursive_mutices_[i].get()));
      channel_managers_.push_back(channel_manager_local_);

      std::string db_local_ = "KnodeTest/datastore"+base::itos(62001+i);
      dbs_.push_back(db_local_);


      boost::shared_ptr<kad::KNode>
          knode_local_(new kad::KNode(dbs_[i],
                                      timers_[i].get(),
                                      recursive_mutices_[i].get(),
                                      channel_managers_[i],
                                      kad::VAULT,
                                      kTestK,
                                      kad::kAlpha,
                                      kad::kBeta));
      EXPECT_EQ(0, channel_managers_[i]->StartTransport(62001+i,
        boost::bind(&kad::KNode::HandleDeadRendezvousServer, knode_local_.get(),
                    _1, _2, _3)));
      knodes_.push_back(knode_local_);
      cb.Reset();
    }

    // start node 1 and add his details to kad config protobuf
    kad_config_file = dbs_[1] + "/.kadconfig";
    knodes_[1]->Join("",
                     kad_config_file,
                     boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
    wait_result(&cb, recursive_mutices_[1].get());
    EXPECT_EQ(kad::kRpcResultSuccess, cb.result());
    printf("Node 1 joined.\n");
    base::KadConfig kad_config;
    base::KadConfig::Contact *kad_contact_ = kad_config.add_contact();
    kad_contact_->set_node_id(knodes_[1]->node_id());
    kad_contact_->set_ip(knodes_[1]->host_ip());
    kad_contact_->set_port(knodes_[1]->host_port());
    kad_contact_->set_local_ip(knodes_[1]->local_host_ip());
    kad_contact_->set_local_port(knodes_[1]->local_host_port());
    std::string node1_id = knodes_[1]->node_id();
    kad_config_file = dbs_[0] + "/.kadconfig";
    std::fstream output1(kad_config_file.c_str(),
      std::ios::out | std::ios::trunc | std::ios::binary);
    EXPECT_TRUE(kad_config.SerializeToOstream(&output1));
    output1.close();

    // bootstrap node 0 (off node 1) and reset kad config with his details
    cb.Reset();
    knodes_[0]->Join("",
                     kad_config_file,
                     boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
    wait_result(&cb, recursive_mutices_[0].get());
    EXPECT_EQ(kad::kRpcResultSuccess, cb.result());
    printf("Node 0 joined.\n");
    kad_config.Clear();
    kad_contact_ = kad_config.add_contact();
    kad_contact_->set_node_id(knodes_[0]->node_id());
    kad_contact_->set_ip(knodes_[0]->host_ip());
    kad_contact_->set_port(knodes_[0]->host_port());
    kad_contact_->set_local_ip(knodes_[0]->local_host_ip());
    kad_contact_->set_local_port(knodes_[0]->local_host_port());

    for (int i = 1; i < kNetworkSize; i++) {
      kad_config_file = dbs_[i] + "/.kadconfig";
      std::fstream output2(kad_config_file.c_str(),
        std::ios::out | std::ios::trunc | std::ios::binary);
      EXPECT_TRUE(kad_config.SerializeToOstream(&output2));
      output2.close();
    }

    // stop node 1
    cb.Reset();
    knodes_[1]->Leave();
    EXPECT_FALSE(knodes_[1]->is_joined());
    printf("Node 1 left.\n");

    // start the rest of the nodes (including node 1 again)
    for (int  i = 1; i < kNetworkSize; ++i) {
      std::string id;
      if (i == 1) {
        id = node1_id;
      }
      cb.Reset();
      kad_config_file = dbs_[i] + "/.kadconfig";
      knodes_[i]->Join(id,
                     kad_config_file,
                     boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
      wait_result(&cb, recursive_mutices_[i].get());
      ASSERT_EQ(kad::kRpcResultSuccess, cb.result());
      printf("Node %i joined.\n", i);
    }
    cb.Reset();
    printf("*-----------------------------------*\n");
    printf("*  %i local Kademlia nodes running  *\n", kNetworkSize);
    printf("*-----------------------------------*\n\n");
  }

  virtual void TearDown() {
    std::cout << "In tear down"<<std::endl;
    for (int i = 0; i < kNetworkSize; i++) {
      timers_[i]->CancelAll();
      cb.Reset();
      knodes_[i]->Leave();
      EXPECT_FALSE(knodes_[i]->is_joined());
      channel_managers_[i]->StopTransport();
      knodes_[i].reset();
    }
    try {
      if (fs::exists("KnodeTest"))
        fs::remove_all("KnodeTest");
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    printf("finished teardown\n");
  }

  std::string kad_config_file;
  std::vector<kad::Contact> bootstrapping_nodes;
  std::vector< boost::shared_ptr<boost::recursive_mutex> > recursive_mutices_;
  std::vector< boost::shared_ptr<base::CallLaterTimer> > timers_;
  std::vector< boost::shared_ptr<rpcprotocol::ChannelManager> >
      channel_managers_;
  std::vector< boost::shared_ptr<kad::KNode> > knodes_;
  std::vector<std::string> dbs_;
  crypto::Crypto cry_obj;
  GeneralKadCallback cb;
 private:
  KNodeTest(const KNodeTest&);
  KNodeTest &operator=(const KNodeTest&);
};

TEST_F(KNodeTest, BEH_KAD_FindClosestNodes) {
  std::string key = cry_obj.Hash("2evvnf3xssas21", "", crypto::STRING_STRING,
      false);
  FindCallback cb1;
  knodes_[5]->FindCloseNodes(key,
      boost::bind(&FindCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, recursive_mutices_[5].get());
  // make sure the nodes returned are what we expect.
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  ASSERT_NE(static_cast<unsigned int>(0), cb1.closest_nodes().size());
  std::list<std::string> closest_nodes_str = cb1.closest_nodes();
  std::list<std::string>::iterator it;
  std::list<kad::Contact> closest_nodes;
  for (it = closest_nodes_str.begin(); it != closest_nodes_str.end();
      it++) {
    kad::Contact node;
    node.ParseFromString(*it);
    closest_nodes.push_back(node);
  }
  ASSERT_EQ(static_cast<unsigned int>(kTestK), closest_nodes.size());
  std::list<kad::Contact> all_nodes;
  for (int i = 0; i < kNetworkSize; i++) {
    kad::Contact node(knodes_[i]->node_id(), knodes_[i]->host_ip(),
        knodes_[i]->host_port(), knodes_[i]->local_host_ip(),
        knodes_[i]->local_host_port(), knodes_[i]->rv_ip(),
        knodes_[i]->rv_port());
    all_nodes.push_back(node);
  }
  kad::SortContactList(&all_nodes, key);
  std::list<kad::Contact>::iterator it1, it2;
  it2= closest_nodes.begin();
  for (it1 = closest_nodes.begin(); it1 != closest_nodes.end();
      it1++, it2++) {
    ASSERT_TRUE(*it1 == *it2);
  }
  printf("\n\nDone\n");
}

TEST_F(KNodeTest, BEH_KAD_StoreAndLoadSmallValue) {
  // prepare small size of values
  std::string key = cry_obj.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(1024);  // 1KB
  // save key/value pair from no.8 node
  StoreValueCallback cb;
  std::string pub_key(""), priv_key(""), sig_pub_key(""), sig_req("");
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key, &sig_pub_key, &sig_req);
  knodes_[7]->StoreValue(key, value, pub_key, sig_pub_key, sig_req,
      boost::bind(&StoreValueCallback::CallbackFunc, &cb, _1));
  wait_result(&cb, recursive_mutices_[7].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb.result());
//  printf("***********Value stored on nodes ");
  // calculate number of nodes which hold this key/value pair
  int number = 0;
  for (int i = 0; i < kNetworkSize; i++) {
    std::vector<std::string> values;
    knodes_[i]->FindValueLocal(key, values);
    if (values.size() >= 1) {
      ASSERT_EQ(static_cast<unsigned int>(1), values.size());
      ASSERT_EQ(value, values[0]);
//      printf("%i, ", i);
      number++;
    }
  }
//  printf(" ***********\n\n");
  ASSERT_EQ(kTestK, number);
  // load the value from no.18 node
  cb.Reset();
  FindCallback cb1;
  knodes_[17]->FindValue(key, boost::bind(&FindCallback::CallbackFunc,
    &cb1, _1));
  wait_result(&cb1, recursive_mutices_[17].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  ASSERT_EQ(static_cast<unsigned int>(1), cb1.values().size());
  ASSERT_EQ(value, cb1.values().front());
//  printf("***********Found value via node 17***********\n");
  // load the value from no.1 node
  cb1.Reset();
  knodes_[0]->FindValue(key, boost::bind(&FakeCallback::CallbackFunc,
                                         &cb1,
                                         _1));
  wait_result(&cb1, recursive_mutices_[0].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  ASSERT_EQ(static_cast<unsigned int>(1), cb1.values().size());
  ASSERT_EQ(value, cb1.values().front());
//  printf("***********Found value via node 0***********\n");
}

TEST_F(KNodeTest, FUNC_KAD_StoreAndLoadBigValue) {
  // prepare big size of values
  std::string key = cry_obj.Hash("vcdrer434dccdwwt", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(1024*1024);  // 1MB
  // save key/value pair from no.10 node
  StoreValueCallback cb;
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key, &sig_pub_key, &sig_req);
  knodes_[10]->StoreValue(key, value, pub_key, sig_pub_key, sig_req,
      boost::bind(&StoreValueCallback::CallbackFunc, &cb, _1));
  wait_result(&cb, recursive_mutices_[10].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb.result());
  // calculate number of nodes which hold this key/value pair
  int number = 0;
  for (int i = 0; i < kNetworkSize; i++) {
    std::vector<std::string> values;
    knodes_[i]->FindValueLocal(key, values);
    if (values.size() >= 1) {
      ASSERT_EQ(static_cast<unsigned int>(1), values.size());
      ASSERT_EQ(value, values[0]);
      number++;
    }
  }
  ASSERT_EQ(kTestK, number);
  // load the value from no.11 node
  FindCallback cb1;
  knodes_[10]->FindValue(key,
      boost::bind(&FindCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, recursive_mutices_[10].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  ASSERT_EQ(static_cast<unsigned int>(1), cb1.values().size());
  ASSERT_EQ(value, cb1.values().front());
  // load the value from no.12 node
  FindCallback cb2;
  knodes_[11]->FindValue(key,
      boost::bind(&FindCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, recursive_mutices_[11].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb2.result());
  ASSERT_EQ(static_cast<unsigned int>(1), cb2.values().size());
  ASSERT_EQ(value, cb2.values().front());
}

TEST_F(KNodeTest, BEH_KAD_LoadNonExistingValue) {
  std::string key = cry_obj.Hash("bbffddnnoooo8822", "", crypto::STRING_STRING,
      false);
  // load the value from no.17 node
  FindCallback cb1;
  knodes_[16]->FindValue(key,
      boost::bind(&FindCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, recursive_mutices_[16].get());
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
}

TEST_F(KNodeTest, BEH_KAD_FindNode) {
  // find an existing node
  std::string node_id1 = knodes_[5]->node_id();
  FindNodeCallback cb1;
  knodes_[19]->FindNode(node_id1,
      boost::bind(&FindNodeCallback::CallbackFunc, &cb1, _1), false);
  wait_result(&cb1, recursive_mutices_[19].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  kad::Contact expect_node1;
  kad::Contact target_node1(knodes_[5]->node_id(), knodes_[5]->host_ip(),
      knodes_[5]->host_port());
  expect_node1.ParseFromString(cb1.contact());
  ASSERT_TRUE(target_node1 == expect_node1);
  // find a non-existing node
  FindNodeCallback cb2;
  std::string node_id2 = cry_obj.Hash("bccddde34333", "",
      crypto::STRING_STRING, false);
  knodes_[19]->FindNode(node_id2,
      boost::bind(&FindNodeCallback::CallbackFunc, &cb2, _1), false);
  wait_result(&cb2, recursive_mutices_[19].get());
  ASSERT_EQ(kad::kRpcResultFailure, cb2.result());
}

TEST_F(KNodeTest, BEH_KAD_Ping) {
  // ping by contact
  kad::Contact remote(knodes_[8]->node_id(), knodes_[8]->host_ip(),
      knodes_[8]->host_port(), knodes_[8]->local_host_ip(),
      knodes_[8]->local_host_port());
  PingCallback cb1;
  knodes_[19]->Ping(remote,
      boost::bind(&PingCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, recursive_mutices_[19].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  // ping by node id
  std::string remote_id = knodes_[9]->node_id();
  PingCallback cb2;
  knodes_[18]->Ping(remote_id,
      boost::bind(&PingCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, recursive_mutices_[18].get());
  // ASSERT_EQ(kad::kRpcResultSuccess, cb2.result());
  if (kad::kRpcResultSuccess != cb2.result()) {
    for (int i=0; i < kNetworkSize; i++) {
      kad::Contact ctc;
      if (knodes_[i]->GetContact(remote_id, &ctc))
        printf("node %d port %d, has knodes_[9]\n", i, knodes_[i]->host_port());
    }
    if (remote_id == kad::client_node_id()) {
      printf("remote id is a client_node_id\n");
    }
    if (remote_id == knodes_[18]->node_id())
      printf("remote_id == node_id of sender\n");
    FAIL();
  }
  // ping a dead node
  std::string dead_id = cry_obj.Hash("bb446dx", "", crypto::STRING_STRING,
      false);
  kad::Contact dead_remote(dead_id, "127.0.0.1", 9999);
  PingCallback cb3;
  knodes_[19]->Ping(dead_remote,
      boost::bind(&PingCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, recursive_mutices_[19].get());
  ASSERT_EQ(kad::kRpcResultFailure, cb3.result());
  PingCallback cb4;
  knodes_[19]->Ping(dead_id,
      boost::bind(&PingCallback::CallbackFunc, &cb4, _1));
  wait_result(&cb4, recursive_mutices_[19].get());
  ASSERT_EQ(kad::kRpcResultFailure, cb4.result());
}

TEST_F(KNodeTest, BEH_KAD_FindValueWithDeadNodes) {
  // Store a small value
  // prepair small size of values
  std::string key = cry_obj.Hash("rrvvdcccdd", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(3*1024);  // 3KB
  // save key/value pair from no.8 node
  StoreValueCallback cb;
  std::string pub_key(""), priv_key(""), sig_pub_key(""), sig_req("");
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key, &sig_pub_key, &sig_req);
  knodes_[8]->StoreValue(key, value, pub_key, sig_pub_key, sig_req,
      boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_result(&cb, recursive_mutices_[8].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb.result());
  // kill k-1 nodes, there should be at least one node left which holds this
  // value
  GeneralKadCallback cb1;
  for (int i = 0; i < kTestK - 1; i++ ) {
    timers_[2 + i]->CancelAll();
    knodes_[2 + i]->Leave();
  }
  base::sleep(2);
  // try to find value
  // load the value from no.20 node
  FindCallback cb2;
  knodes_[19]->FindValue(key,
      boost::bind(&FakeCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, recursive_mutices_[19].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb2.result());
  ASSERT_EQ(static_cast<unsigned int>(1), cb2.values().size());
  ASSERT_EQ(value, cb2.values().front());
}

TEST_F(KNodeTest, FUNC_KAD_Downlist) {
  // select a random node from node 1 to node 19
  int r_node = 1 + rand() % 19;
  std::string r_node_id = knodes_[r_node]->node_id();
  // Compute the sum of the nodes whose routing table contain r_node
  int sum_0 = 0;
  bool contacted_holder = false;
  for (int i = 1; i < kNetworkSize; i++) {
    if (i != r_node) {
      kad::Contact test_contact;
      if (knodes_[i]->GetContact(r_node_id, &test_contact)) {
        if (test_contact.failed_rpc() == kad::kFailedRpc) {
          sum_0++;
          if (!contacted_holder) {
            kad::Contact dead_node(knodes_[i]->node_id(), knodes_[i]->host_ip(),
              knodes_[i]->host_port(), knodes_[i]->local_host_ip(),
              knodes_[i]->local_host_port());
            PingCallback cb2;
            knodes_[0]->Ping(dead_node,
              boost::bind(&PingCallback::CallbackFunc, &cb2, _1));
            wait_result(&cb2, recursive_mutices_[0].get());
            ASSERT_EQ(kad::kRpcResultSuccess, cb2.result());
            contacted_holder = true;
          }
        }
      }
    }
  }
  cb.Reset();
  FindNodeCallback cb1;
  kad::Contact dead_node(r_node_id, knodes_[r_node]->host_ip(),
    knodes_[r_node]->host_port(), knodes_[r_node]->local_host_ip(),
    knodes_[r_node]->local_host_port());
  PingCallback cb2;
  knodes_[0]->Ping(dead_node,
      boost::bind(&PingCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, recursive_mutices_[0].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb2.result());
  // Kill r_node
  GeneralKadCallback cb;
  timers_[r_node]->CancelAll();
  knodes_[r_node]->Leave();
  ASSERT_FALSE(knodes_[r_node]->is_joined());
  channel_managers_[r_node]->StopTransport();
  // Do a find node
  knodes_[0]->FindCloseNodes(r_node_id,
      boost::bind(&FindNodeCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, recursive_mutices_[0].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  // Wait for a RPC timeout interval until the downlist are handled in the
  // network
  base::sleep(4*(kad::kRpcTimeout/1000+1));
  // Compute the sum of the nodes whose routing table contain r_node again
  int sum_1 = 0;
  for (int i = 1; i < kNetworkSize; i++) {
    if (i != r_node) {
      kad::Contact test_contact;
      if (knodes_[i]->GetContact(r_node_id, &test_contact)) {
        std::string enc_id;
        base::encode_to_hex(knodes_[i]->node_id(), enc_id);
        sum_1++;
      } else {
        if (test_contact.failed_rpc() > kad::kFailedRpc)
          sum_1++;
      }
    }
  }
  // r_node should be removed from the routing tables of some nodes
  ASSERT_LT(sum_1, sum_0);
}

TEST_F(KNodeTest, BEH_KAD_StoreWithInvalidRequest) {
  std::string key = cry_obj.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(1024);  // 1KB
  // save key/value pair from no.8 node
  StoreValueCallback cb;
  std::string pub_key(""), priv_key(""), sig_pub_key(""), sig_req("");
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key, &sig_pub_key, &sig_req);
  knodes_[7]->StoreValue(key, value, pub_key, sig_pub_key, "bad request",
      boost::bind(&StoreValueCallback::CallbackFunc, &cb, _1));
  wait_result(&cb, recursive_mutices_[7].get());
  ASSERT_EQ(kad::kRpcResultFailure, cb.result());
  std::string new_pub_key(""), new_priv_key("");
  create_rsakeys(&new_pub_key, &new_priv_key);
  ASSERT_NE(pub_key, new_pub_key);
  cb.Reset();
  knodes_[7]->StoreValue(key, value, new_pub_key, sig_pub_key, sig_req,
      boost::bind(&StoreValueCallback::CallbackFunc, &cb, _1));
  wait_result(&cb, recursive_mutices_[7].get());
  ASSERT_EQ(kad::kRpcResultFailure, cb.result());
}

TEST_F(KNodeTest, BEH_KAD_AllDirectlyConnected) {
  for (int i = 0; i < kNetworkSize; i++) {
    std::vector<kad::Contact> exclude_contacts;
    std::vector<kad::Contact> contacts;
    knodes_[i]->GetRandomContacts(kNetworkSize, exclude_contacts, &contacts);
    ASSERT_LT(0, static_cast<int>(contacts.size()));
    for (int j = 0; j < static_cast<int>(contacts.size()); j++) {
      ASSERT_EQ("", contacts[j].rendezvous_ip());
      ASSERT_EQ(0, contacts[j].rendezvous_port());
    }
  }
}

TEST_F(KNodeTest, BEH_KAD_PingIncorrectNodeLocalAddr) {
  //knodes_[4]->set_local_port(knodes_[6]->local_port());
  kad::Contact remote(knodes_[8]->node_id(), knodes_[8]->host_ip(),
      knodes_[8]->host_port(), knodes_[8]->local_host_ip(),
      knodes_[8]->local_host_port());
  PingCallback cb1;
  knodes_[4]->Ping(remote,
      boost::bind(&PingCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, recursive_mutices_[4].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());

  // now ping the node that has changed its local address
  kad::Contact remote1(knodes_[4]->node_id(), knodes_[4]->host_ip(),
      knodes_[4]->host_port(), knodes_[6]->local_host_ip(),
      knodes_[6]->local_host_port());
  cb1.Reset();
  knodes_[8]->Ping(remote1,
      boost::bind(&PingCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, recursive_mutices_[8].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
}

TEST_F(KNodeTest, BEH_KAD_ClientKnodeConnect) {
  boost::scoped_ptr<boost::recursive_mutex>
      recursive_mutex_local_(new boost::recursive_mutex);
  boost::scoped_ptr<base::CallLaterTimer>
      timer_local_(new base::CallLaterTimer(recursive_mutex_local_.get()));
  boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager_local_(
      new rpcprotocol::ChannelManager(timer_local_.get(),
                                      recursive_mutex_local_.get()));
  std::string db_local_ = "KnodeTest/datastore"+base::itos(63001);
  boost::scoped_ptr<kad::KNode> knode_local_(new kad::KNode(db_local_,
                                             timer_local_.get(),
                                             recursive_mutex_local_.get(),
                                             channel_manager_local_,
                                             kad::CLIENT,
                                             kTestK,
                                             kad::kAlpha,
                                             kad::kBeta));
  EXPECT_EQ(0, channel_manager_local_->StartTransport(63001,
    boost::bind(&kad::KNode::HandleDeadRendezvousServer, knode_local_.get(),
                _1, _2, _3)));
  knode_local_->Join("",
                     kad_config_file,
                     boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
  wait_result(&cb, recursive_mutex_local_.get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb.result());
  // Doing a storevalue
  std::string key = cry_obj.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(1024*10);  // 10KB
  StoreValueCallback cb1;
  std::string pub_key(""), priv_key(""), sig_pub_key(""), sig_req("");
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key, &sig_pub_key, &sig_req);
  knode_local_->StoreValue(key, value, pub_key, sig_pub_key, sig_req,
      boost::bind(&StoreValueCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, recursive_mutex_local_.get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());

  // loading the value with another existing node
  FindCallback cb2;
  knodes_[11]->FindValue(key, boost::bind(&FindCallback::CallbackFunc,
    &cb2, _1));
  wait_result(&cb2, recursive_mutices_[11].get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb2.result());
  ASSERT_EQ(static_cast<unsigned int>(1), cb2.values().size());
  ASSERT_EQ(value, cb2.values().front());
  cb2.Reset();

  // loading the value with the client
  knode_local_->FindValue(key, boost::bind(&FindCallback::CallbackFunc,
    &cb2, _1));
  wait_result(&cb2, recursive_mutex_local_.get());
  ASSERT_EQ(kad::kRpcResultSuccess, cb2.result());
  ASSERT_EQ(static_cast<unsigned int>(1), cb2.values().size());
  ASSERT_EQ(value, cb2.values().front());
  cb2.Reset();

  // Doing a find closest nodes with the client
  std::string key1 = cry_obj.Hash("2evvnf3xssas21", "", crypto::STRING_STRING,
      false);
  FindCallback cb3;
  knode_local_->FindCloseNodes(key1,
      boost::bind(&FindCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, recursive_mutex_local_.get());
  // make sure the nodes returned are what we expect.
  ASSERT_EQ(kad::kRpcResultSuccess, cb3.result());
  ASSERT_NE(static_cast<unsigned int>(0), cb3.closest_nodes().size());
  std::list<std::string> closest_nodes_str = cb3.closest_nodes();
  std::list<std::string>::iterator it;
  std::list<kad::Contact> closest_nodes;
  for (it = closest_nodes_str.begin(); it != closest_nodes_str.end();
      it++) {
    kad::Contact node;
    node.ParseFromString(*it);
    closest_nodes.push_back(node);
  }
  ASSERT_EQ(static_cast<unsigned int>(kTestK), closest_nodes.size());
  std::list<kad::Contact> all_nodes;
  for (int i = 0; i < kNetworkSize; i++) {
    kad::Contact node(knodes_[i]->node_id(), knodes_[i]->host_ip(),
        knodes_[i]->host_port());
    all_nodes.push_back(node);
  }
  kad::SortContactList(&all_nodes, key1);
  std::list<kad::Contact>::iterator it1, it2;
  it2= closest_nodes.begin();
  for (it1 = closest_nodes.begin(); it1 != closest_nodes.end();
      it1++, it2++) {
    ASSERT_TRUE(*it1 == *it2);
  }

  // Checking no node has stored the clients node in its routing table
  for (int i = 0; i < kNetworkSize; i++) {
    kad::Contact client_node;
    ASSERT_FALSE(knodes_[i]->GetContact(knode_local_->node_id(), &client_node));
  }
  timer_local_->CancelAll();
  cb.Reset();
  knode_local_->Leave();
  ASSERT_FALSE(knode_local_->is_joined());
  channel_manager_local_->StopTransport();
}

TEST_F(KNodeTest, BEH_KAD_FindDeadNode) {
  // find an existing node that has gone down
  // select a random node from node 1 to node 19
  int r_node = 1 + rand() % 19;
  std::string r_node_id = knodes_[r_node]->node_id();
  timers_[r_node]->CancelAll();
  knodes_[r_node]->Leave();
  ASSERT_FALSE(knodes_[r_node]->is_joined());
  channel_managers_[r_node]->StopTransport();
  // Do a find node
  FindNodeCallback cb1;
  knodes_[19]->FindNode(r_node_id,
      boost::bind(&FindNodeCallback::CallbackFunc, &cb1, _1), false);
  wait_result(&cb1, recursive_mutices_[19].get());
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
}

TEST_F(KNodeTest, BEH_KAD_RebootstrapNode) {
  cb.Reset();
  std::string ip = knodes_[1]->host_ip();
  boost::uint16_t port = knodes_[1]->host_port();
  knodes_[1]->Leave();
  ASSERT_FALSE(knodes_[1]->is_joined());
  channel_managers_[1]->StopTransport();
  knodes_[2]->HandleDeadRendezvousServer(true, ip, port);
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  bool finished_bootstrap = false;
  while (!finished_bootstrap) {
    {
      base::pd_scoped_lock gaurd(*recursive_mutices_[2].get());
      if (knodes_[2]->is_joined())
        finished_bootstrap = true;
    }
  }
  ASSERT_TRUE(knodes_[2]->is_joined());
}
